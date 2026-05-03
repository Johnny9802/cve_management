"""risk_acceptances + audit_log extension (P8 + P9 partial — Sprint 3)

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-03

Sprint 3 brief excludes RBAC. This migration therefore introduces:

* ``risk_acceptances`` — new table for the formal risk-acceptance
  workflow (P8).
* ``audit_log`` extension — adds five columns to the table that already
  exists from migration 0002 (see REVIEW_FINDINGS PEF-1). This avoids a
  destructive rebuild while accommodating the brief's expected schema
  (actor_email, actor_role, diff, ip_address, user_agent).

Notes
-----
* ``findings.due_date`` already exists (migration 0001). No column added
  in this migration — the SLA matrix is enforced at INSERT/UPDATE time
  by the application service.
* ``audit_log.diff`` is a ``JSONB`` column distinct from the pre-existing
  ``metadata`` column. Both stay; ``metadata`` is reserved for non-diff
  context (request-id, correlation, etc.). The brief specifies "diff
  before/after" so we keep them separate to avoid overloading.
* No CASCADE on audit_log FK by design — audit rows must outlive the
  thing they describe.
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── risk_acceptances (P8) ─────────────────────────────────────────
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_acceptances (
            id              BIGSERIAL   PRIMARY KEY,
            finding_id      BIGINT      NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            requested_by    TEXT        NOT NULL,
            approved_by     TEXT,
            justification   TEXT        NOT NULL CHECK (length(justification) >= 10),
            expires_at      DATE        NOT NULL,
            status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            decided_at      TIMESTAMPTZ
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_risk_acc_finding ON risk_acceptances(finding_id)")
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_risk_acc_expires
            ON risk_acceptances(expires_at) WHERE status = 'approved'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_risk_acc_status
            ON risk_acceptances(status, finding_id)
        """
    )

    # GRANTs for hardened roles (migration 0003)
    op.execute(
        """
        GRANT INSERT, UPDATE, SELECT ON risk_acceptances TO cve_sync_worker
        """
    )
    op.execute("GRANT SELECT ON risk_acceptances TO cve_query_engine")
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE risk_acceptances_id_seq TO cve_sync_worker"
    )

    # ── audit_log extension (P9 partial) ──────────────────────────────
    # Adds the columns the brief specifies, preserving the existing
    # schema (action, actor, target_type, target_id, metadata, ts).
    op.execute(
        """
        ALTER TABLE audit_log
            ADD COLUMN IF NOT EXISTS actor_email TEXT,
            ADD COLUMN IF NOT EXISTS actor_role  TEXT,
            ADD COLUMN IF NOT EXISTS diff        JSONB,
            ADD COLUMN IF NOT EXISTS ip_address  INET,
            ADD COLUMN IF NOT EXISTS user_agent  TEXT
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_actor_email
            ON audit_log(actor_email, ts DESC)
            WHERE actor_email IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_log_action
            ON audit_log(action, ts DESC)
        """
    )


def downgrade() -> None:
    # Audit-log columns: drop, reverting to the migration-0002 schema.
    op.execute("DROP INDEX IF EXISTS idx_audit_log_action")
    op.execute("DROP INDEX IF EXISTS idx_audit_log_actor_email")
    op.execute(
        """
        ALTER TABLE audit_log
            DROP COLUMN IF EXISTS user_agent,
            DROP COLUMN IF EXISTS ip_address,
            DROP COLUMN IF EXISTS diff,
            DROP COLUMN IF EXISTS actor_role,
            DROP COLUMN IF EXISTS actor_email
        """
    )
    op.execute("DROP INDEX IF EXISTS idx_risk_acc_status")
    op.execute("DROP INDEX IF EXISTS idx_risk_acc_expires")
    op.execute("DROP INDEX IF EXISTS idx_risk_acc_finding")
    op.execute("DROP TABLE IF EXISTS risk_acceptances")
