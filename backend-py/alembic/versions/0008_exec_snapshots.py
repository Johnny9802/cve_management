"""exec_snapshots — daily aggregate KPIs for the Executive dashboard

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-04

The Executive dashboard (Dashboard A) needs trend lines (open
critical findings over time, remediation velocity, MTTR, KEV
exposure …) which are not derivable from "as of now" tables. We
therefore capture a small daily snapshot of headline counters so
trends can be drawn without an OLAP layer.

The job ``daily_snapshot`` (see app/workers/daily_snapshot.py) writes
one row per day at 00:05 UTC. Rows are immutable; running the job
twice the same day is idempotent thanks to a UNIQUE(captured_on)
constraint.

Schema is intentionally narrow — adding new metrics is cheap because
each is a separate column.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS exec_snapshots (
            id                       BIGSERIAL   PRIMARY KEY,
            captured_on              DATE        NOT NULL UNIQUE,
            captured_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            total_cves               BIGINT      NOT NULL DEFAULT 0,
            kev_total                BIGINT      NOT NULL DEFAULT 0,
            critical_open            BIGINT      NOT NULL DEFAULT 0,
            high_open                BIGINT      NOT NULL DEFAULT 0,
            medium_open              BIGINT      NOT NULL DEFAULT 0,
            low_open                 BIGINT      NOT NULL DEFAULT 0,

            findings_open            BIGINT      NOT NULL DEFAULT 0,
            findings_in_review       BIGINT      NOT NULL DEFAULT 0,
            findings_remediated_24h  BIGINT      NOT NULL DEFAULT 0,
            findings_breached        BIGINT      NOT NULL DEFAULT 0,
            findings_at_risk         BIGINT      NOT NULL DEFAULT 0,

            risk_pending             BIGINT      NOT NULL DEFAULT 0,
            risk_approved            BIGINT      NOT NULL DEFAULT 0,
            risk_expiring_soon       BIGINT      NOT NULL DEFAULT 0,

            mttr_critical_days       NUMERIC(8,2),
            mttr_high_days           NUMERIC(8,2),
            mttr_medium_days         NUMERIC(8,2),
            mttr_low_days            NUMERIC(8,2),

            kev_with_open_finding    BIGINT      NOT NULL DEFAULT 0,
            poc_with_open_finding    BIGINT      NOT NULL DEFAULT 0,
            nuclei_with_open_finding BIGINT      NOT NULL DEFAULT 0,

            -- Composite Executive risk score 0-100 (higher = worse).
            -- See app/workers/daily_snapshot.py for the formula.
            risk_score               INT         NOT NULL DEFAULT 0
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_exec_snapshots_captured
            ON exec_snapshots(captured_on DESC)
        """
    )

    # GRANTs aligned with hardened roles (migration 0003).
    op.execute("GRANT INSERT, UPDATE, SELECT ON exec_snapshots TO cve_sync_worker")
    op.execute("GRANT SELECT ON exec_snapshots TO cve_query_engine")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE exec_snapshots_id_seq TO cve_sync_worker")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_exec_snapshots_captured")
    op.execute("DROP TABLE IF EXISTS exec_snapshots")
