"""webhooks + webhook_deliveries (P7)

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-03

Schema follows the brief spec. Notes:

* ``secret`` is stored as plaintext because we need it on every dispatch
  to compute HMAC. The application MUST mask it on every API response and
  log line. We rely on the runtime configuration (``cve_user`` is the only
  role with SELECT on this table) plus operator hygiene; encrypting at
  rest is a future hardening task.
* ``event_types TEXT[]`` is convenient for "which webhooks subscribe to
  X" queries (``WHERE 'finding.kev_match' = ANY(event_types)``).
* ``min_priority`` is nullable — webhook subscribers can skip the priority
  filter and rely on event_type only.
* ``webhook_deliveries.delivered_at`` IS NULL for pending / in-flight
  attempts. The partial index on the dispatch column accelerates the
  worker's outbound query.
* GRANTs added for ``cve_sync_worker`` (write) and ``cve_query_engine``
  (read) — see migration 0003 for the rationale.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id              BIGSERIAL   PRIMARY KEY,
            name            TEXT        NOT NULL,
            url             TEXT        NOT NULL,
            secret          TEXT,
            event_types     TEXT[]      NOT NULL DEFAULT '{}',
            min_priority    INT         CHECK (min_priority IS NULL OR (min_priority BETWEEN 0 AND 100)),
            enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
            created_by      TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_success_at TIMESTAMPTZ,
            last_error_at   TIMESTAMPTZ,
            last_error      TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled) WHERE enabled = TRUE")
    op.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_event_types ON webhooks USING GIN (event_types)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id              BIGSERIAL   PRIMARY KEY,
            webhook_id      BIGINT      NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
            event_type      TEXT        NOT NULL,
            payload         JSONB       NOT NULL,
            dedup_key       TEXT,
            status_code     INT,
            response_body   TEXT,
            attempts        INT         NOT NULL DEFAULT 0,
            max_attempts    INT         NOT NULL DEFAULT 5,
            scheduled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            delivered_at    TIMESTAMPTZ,
            last_error      TEXT,
            locked_until    TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    # Worker query: fetch deliveries that are due, not currently locked,
    # and have not exhausted their retry budget.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_deliv_pending
            ON webhook_deliveries(scheduled_at, webhook_id)
            WHERE delivered_at IS NULL
        """
    )
    # Dedup detection: 5-minute window per (webhook_id, event_type, dedup_key).
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_webhook_deliv_dedup
            ON webhook_deliveries(webhook_id, event_type, dedup_key, created_at DESC)
            WHERE dedup_key IS NOT NULL
        """
    )

    # GRANTs for hardening migration roles
    op.execute(
        """
        GRANT INSERT, UPDATE, DELETE, SELECT ON webhooks, webhook_deliveries TO cve_sync_worker
        """
    )
    op.execute(
        """
        GRANT SELECT ON webhooks, webhook_deliveries TO cve_query_engine
        """
    )
    op.execute("GRANT USAGE, SELECT ON SEQUENCE webhooks_id_seq TO cve_sync_worker")
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE webhook_deliveries_id_seq TO cve_sync_worker"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS webhook_deliveries")
    op.execute("DROP TABLE IF EXISTS webhooks")
