"""Daily snapshot job (Sprint Dashboards 3).

Runs at 00:05 UTC. Captures headline KPIs into ``exec_snapshots`` so
the Executive dashboard can render trend lines without an OLAP layer.

Idempotency
-----------
The destination table has a ``UNIQUE(captured_on)`` constraint, so
running the job twice the same day produces a single row — the
``ON CONFLICT (captured_on) DO UPDATE`` clause overwrites the row
with the freshest values. This also makes the bootstrap path safe
("populate today's row at startup if missing").

Risk Score
----------
A weighted composite 0-100 (higher = worse posture):

  0.40 × % open findings with priority ≥ 80
  0.30 × % open findings with KEV match
  0.20 × % open findings with SLA breached
  0.10 × min(1, MTTR_90d_critical / 30)            # 30 days = soft target

When the dataset is too sparse (no findings at all) we still write a
row with risk_score = 0 so the trend line has continuous data.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class SnapshotResult:
    job: str
    captured_on: str
    risk_score: int
    duration_ms: int


_INSERT_SQL = """
    INSERT INTO exec_snapshots (
        captured_on,

        total_cves, kev_total,
        critical_open, high_open, medium_open, low_open,

        findings_open, findings_in_review,
        findings_remediated_24h, findings_breached, findings_at_risk,

        risk_pending, risk_approved, risk_expiring_soon,

        mttr_critical_days, mttr_high_days, mttr_medium_days, mttr_low_days,

        kev_with_open_finding, poc_with_open_finding, nuclei_with_open_finding,

        risk_score
    )
    VALUES (
        $1,
        $2, $3,
        $4, $5, $6, $7,
        $8, $9,
        $10, $11, $12,
        $13, $14, $15,
        $16, $17, $18, $19,
        $20, $21, $22,
        $23
    )
    ON CONFLICT (captured_on) DO UPDATE SET
        captured_at              = NOW(),
        total_cves               = EXCLUDED.total_cves,
        kev_total                = EXCLUDED.kev_total,
        critical_open            = EXCLUDED.critical_open,
        high_open                = EXCLUDED.high_open,
        medium_open              = EXCLUDED.medium_open,
        low_open                 = EXCLUDED.low_open,
        findings_open            = EXCLUDED.findings_open,
        findings_in_review       = EXCLUDED.findings_in_review,
        findings_remediated_24h  = EXCLUDED.findings_remediated_24h,
        findings_breached        = EXCLUDED.findings_breached,
        findings_at_risk         = EXCLUDED.findings_at_risk,
        risk_pending             = EXCLUDED.risk_pending,
        risk_approved            = EXCLUDED.risk_approved,
        risk_expiring_soon       = EXCLUDED.risk_expiring_soon,
        mttr_critical_days       = EXCLUDED.mttr_critical_days,
        mttr_high_days           = EXCLUDED.mttr_high_days,
        mttr_medium_days         = EXCLUDED.mttr_medium_days,
        mttr_low_days            = EXCLUDED.mttr_low_days,
        kev_with_open_finding    = EXCLUDED.kev_with_open_finding,
        poc_with_open_finding    = EXCLUDED.poc_with_open_finding,
        nuclei_with_open_finding = EXCLUDED.nuclei_with_open_finding,
        risk_score               = EXCLUDED.risk_score
"""


async def capture_daily_snapshot(pool: asyncpg.Pool) -> SnapshotResult:
    t0 = time.monotonic()
    today = datetime.now(tz=UTC).date()

    async with pool.acquire() as conn:
        cve_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                    AS total_cves,
                COUNT(*) FILTER (WHERE is_kev = TRUE)       AS kev_total,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
                COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high_count,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium_count,
                COUNT(*) FILTER (WHERE severity = 'LOW')      AS low_count
            FROM cves
            """
        )
        finding_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'open')                                AS open_count,
                COUNT(*) FILTER (WHERE status = 'in_review')                           AS in_review_count,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                      AND due_date IS NOT NULL
                      AND due_date < CURRENT_DATE
                )                                                                       AS breached_count,
                COUNT(*) FILTER (
                    WHERE status IN ('open', 'in_review', 'planned')
                      AND due_date IS NOT NULL
                      AND due_date >= CURRENT_DATE
                      AND due_date <= CURRENT_DATE + INTERVAL '7 days'
                )                                                                       AS at_risk_count,
                COUNT(*) FILTER (
                    WHERE status = 'remediated'
                      AND updated_at >= NOW() - INTERVAL '24 hours'
                )                                                                       AS remediated_24h
            FROM findings
            """
        )
        # Severity bands by JOINing cves — used both for risk-score
        # and for the priority/KEV ratios.
        finding_signal_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                      AND COALESCE(f.priority_score, 0) >= 80
                )                                                                       AS prio80_count,
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                      AND c.is_kev = TRUE
                )                                                                       AS kev_open_count,
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                      AND c.has_public_poc = TRUE
                )                                                                       AS poc_open_count,
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                      AND c.has_nuclei_template = TRUE
                )                                                                       AS nuclei_open_count,
                COUNT(*) FILTER (
                    WHERE f.status IN ('open', 'in_review', 'planned')
                )                                                                       AS open_total
            FROM findings f
            JOIN cves c ON c.cve_id = f.cve_id
            """
        )
        risk_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending')       AS pending,
                COUNT(*) FILTER (WHERE status = 'approved')      AS approved,
                COUNT(*) FILTER (
                    WHERE status = 'approved'
                      AND expires_at <= CURRENT_DATE + INTERVAL '7 days'
                )                                                AS expiring_soon
            FROM risk_acceptances
            """
        )
        # MTTR per severity over the last 90 days. NULL if no remediated
        # findings exist for that severity.
        mttr_rows = await conn.fetch(
            """
            WITH last_remediated AS (
                SELECT DISTINCT ON (finding_id)
                       finding_id, changed_at
                FROM findings_history
                WHERE new_status = 'remediated'
                ORDER BY finding_id, changed_at DESC
            )
            SELECT
                c.severity,
                ROUND(
                  AVG(EXTRACT(EPOCH FROM (COALESCE(lr.changed_at, f.updated_at) - f.created_at)) / 86400.0)::numeric,
                  2
                ) AS mttr_days
            FROM findings f
            JOIN cves c ON c.cve_id = f.cve_id
            LEFT JOIN last_remediated lr ON lr.finding_id = f.id
            WHERE f.status = 'remediated'
              AND COALESCE(lr.changed_at, f.updated_at) >= NOW() - INTERVAL '90 days'
            GROUP BY c.severity
            """
        )
        mttr = {r["severity"]: float(r["mttr_days"]) if r["mttr_days"] is not None else None
                for r in mttr_rows}

    open_total = int(finding_signal_row["open_total"] or 0)
    if open_total > 0:
        prio80_pct  = float(finding_signal_row["prio80_count"]  or 0) / open_total
        kev_pct     = float(finding_signal_row["kev_open_count"] or 0) / open_total
        breach_pct  = float(finding_row["breached_count"]      or 0) / open_total
    else:
        prio80_pct = kev_pct = breach_pct = 0.0
    mttr_crit = mttr.get("CRITICAL") or 0.0
    mttr_norm = min(1.0, mttr_crit / 30.0) if mttr_crit else 0.0

    # Cap each component to 100, then weighted average.
    risk_score = int(round(
        100 * (
            0.40 * min(1.0, prio80_pct)
            + 0.30 * min(1.0, kev_pct)
            + 0.20 * min(1.0, breach_pct)
            + 0.10 * min(1.0, mttr_norm)
        )
    ))

    async with pool.acquire() as conn:
        await conn.execute(
            _INSERT_SQL,
            today,

            int(cve_row["total_cves"]),
            int(cve_row["kev_total"]),
            int(cve_row["critical_count"]),
            int(cve_row["high_count"]),
            int(cve_row["medium_count"]),
            int(cve_row["low_count"]),

            int(finding_row["open_count"]),
            int(finding_row["in_review_count"]),
            int(finding_row["remediated_24h"]),
            int(finding_row["breached_count"]),
            int(finding_row["at_risk_count"]),

            int(risk_row["pending"]),
            int(risk_row["approved"]),
            int(risk_row["expiring_soon"]),

            mttr.get("CRITICAL"),
            mttr.get("HIGH"),
            mttr.get("MEDIUM"),
            mttr.get("LOW"),

            int(finding_signal_row["kev_open_count"]),
            int(finding_signal_row["poc_open_count"]),
            int(finding_signal_row["nuclei_open_count"]),

            risk_score,
        )

    duration_ms = int((time.monotonic() - t0) * 1000)
    logger.info(
        "daily_snapshot.captured",
        captured_on=str(today),
        risk_score=risk_score,
        duration_ms=duration_ms,
    )
    return SnapshotResult(
        job="daily_snapshot",
        captured_on=str(today),
        risk_score=risk_score,
        duration_ms=duration_ms,
    )
