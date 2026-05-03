"""sync infrastructure: sync_jobs, sync_state, subscriptions_opencve, epss_history, audit_log

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-30
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS sync_jobs (
            id            BIGSERIAL   PRIMARY KEY,
            job_type      TEXT        NOT NULL
                              CHECK (job_type IN (
                                  'product_sync', 'bulk_ingest',
                                  'epss_refresh', 'kev_refresh', 'delta_sync'
                              )),
            target_id     TEXT,
            status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'running', 'completed', 'failed', 'dead')),
            priority      INT         NOT NULL DEFAULT 10,
            attempts      INT         NOT NULL DEFAULT 0,
            max_attempts  INT         NOT NULL DEFAULT 3,
            scheduled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at    TIMESTAMPTZ,
            completed_at  TIMESTAMPTZ,
            locked_until  TIMESTAMPTZ,
            error_message TEXT,
            metadata      JSONB       NOT NULL DEFAULT '{}'
        )
    """)

    # Partial index for job pickup — only pending rows, ordered by priority DESC
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_sync_jobs_pickup
            ON sync_jobs(status, priority DESC, scheduled_at ASC)
            WHERE status = 'pending'
    """)

    # Prevent double-queuing the same job type+target
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_sync_jobs_active
            ON sync_jobs(job_type, target_id)
            WHERE status IN ('pending', 'running') AND target_id IS NOT NULL
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (
            id              SERIAL      PRIMARY KEY,
            source          TEXT        NOT NULL UNIQUE
                                CHECK (source IN ('vulncheck', 'nvd_api')),
            last_success_at TIMESTAMPTZ,
            last_mod_date   TIMESTAMPTZ,
            total_ingested  BIGINT      NOT NULL DEFAULT 0,
            last_error      TEXT,
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # Seed rows — idempotent via ON CONFLICT DO NOTHING
    op.execute("""
        INSERT INTO sync_state(source)
        VALUES ('vulncheck'), ('nvd_api')
        ON CONFLICT DO NOTHING
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions_opencve (
            id             BIGSERIAL   PRIMARY KEY,
            vendor         TEXT        NOT NULL,
            product        TEXT        NOT NULL,
            project_id     TEXT,
            webhook_secret TEXT,
            active         BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (vendor, product)
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS epss_history (
            id          BIGSERIAL   PRIMARY KEY,
            cve_id      TEXT        NOT NULL REFERENCES cves(cve_id),
            score       NUMERIC(6,5) NOT NULL,
            percentile  NUMERIC(6,5),
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_epss_history_cve
            ON epss_history(cve_id, recorded_at DESC)
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          BIGSERIAL   PRIMARY KEY,
            action      TEXT        NOT NULL,
            actor       TEXT        NOT NULL DEFAULT 'system',
            target_type TEXT,
            target_id   TEXT,
            metadata    JSONB       NOT NULL DEFAULT '{}',
            ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS epss_history")
    op.execute("DROP TABLE IF EXISTS subscriptions_opencve")
    op.execute("DROP TABLE IF EXISTS sync_state")
    op.execute("DROP TABLE IF EXISTS sync_jobs")
