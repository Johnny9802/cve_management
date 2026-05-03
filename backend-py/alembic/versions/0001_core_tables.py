"""core tables: cves, products, cpe_resolutions, findings, findings_history

Revision ID: 0001
Revises:
Create Date: 2026-04-30
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id               BIGSERIAL PRIMARY KEY,
            cve_id           TEXT        NOT NULL UNIQUE,
            source           TEXT        NOT NULL DEFAULT 'vulncheck_nvd'
                                 CHECK (source IN ('vulncheck_nvd', 'nvd_api', 'circl')),
            raw_payload      JSONB       NOT NULL,
            cvss_v3_score    NUMERIC(4,1),
            cvss_v3_vector   TEXT,
            cvss_v2_score    NUMERIC(4,1),
            severity         TEXT        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
            epss_score       NUMERIC(6,5),
            epss_percentile  NUMERIC(6,5),
            epss_updated_at  TIMESTAMPTZ,
            is_kev           BOOLEAN     NOT NULL DEFAULT FALSE,
            kev_added_date   DATE,
            published_at     TIMESTAMPTZ NOT NULL,
            last_modified_at TIMESTAMPTZ NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # GIN indexes on JSONB — critical for CPE config queries
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_raw_gin ON cves USING GIN(raw_payload)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_configurations ON cves USING GIN((raw_payload -> 'configurations'))")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_metrics ON cves USING GIN((raw_payload -> 'metrics'))")

    # B-tree indexes for dashboard filters
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_is_kev ON cves(is_kev) WHERE is_kev = TRUE")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves(last_modified_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC NULLS LAST)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id              BIGSERIAL PRIMARY KEY,
            name            TEXT        NOT NULL,
            vendor          TEXT,
            version         TEXT,
            normalized_cpe  TEXT,
            cpe_confidence  TEXT        CHECK (cpe_confidence IN ('certain', 'uncertain', 'manual')),
            sync_status     TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (sync_status IN ('pending', 'syncing', 'synced', 'error')),
            last_synced_at  TIMESTAMPTZ,
            cve_count       INT         NOT NULL DEFAULT 0,
            critical_count  INT         NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (name, vendor, version)
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS cpe_resolutions (
            id            BIGSERIAL PRIMARY KEY,
            input_string  TEXT        NOT NULL UNIQUE,
            resolved_cpe  TEXT        NOT NULL,
            confidence    TEXT        NOT NULL
                              CHECK (confidence IN ('certain', 'uncertain', 'manual')),
            match_score   NUMERIC(5,2),
            resolved_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_by   TEXT        NOT NULL DEFAULT 'auto'
                              CHECK (resolved_by IN ('auto', 'manual'))
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id               BIGSERIAL PRIMARY KEY,
            product_id       BIGINT      NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            cve_id           TEXT        NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
            status           TEXT        NOT NULL DEFAULT 'open'
                                 CHECK (status IN (
                                     'open', 'in_review', 'false_positive',
                                     'accepted_risk', 'planned', 'remediated', 'closed'
                                 )),
            match_confidence TEXT        CHECK (match_confidence IN ('certain', 'uncertain')),
            match_reason     TEXT,
            priority_score   NUMERIC(5,2),
            assigned_to      TEXT,
            due_date         DATE,
            notes            TEXT,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (product_id, cve_id)
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_product ON findings(product_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id)")
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_findings_open
            ON findings(product_id, priority_score DESC)
            WHERE status = 'open'
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority_score DESC NULLS LAST)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS findings_history (
            id         BIGSERIAL PRIMARY KEY,
            finding_id BIGINT      NOT NULL REFERENCES findings(id),
            old_status TEXT,
            new_status TEXT        NOT NULL,
            changed_by TEXT        NOT NULL DEFAULT 'system',
            changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reason     TEXT
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_findings_history_fid ON findings_history(finding_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS findings_history")
    op.execute("DROP TABLE IF EXISTS findings")
    op.execute("DROP TABLE IF EXISTS cpe_resolutions")
    op.execute("DROP TABLE IF EXISTS products")
    op.execute("DROP TABLE IF EXISTS cves")
