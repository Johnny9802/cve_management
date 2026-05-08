"""missing indices for hot query paths (Sprint 2 — S2.11)

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-08

The production-readiness review (DB-01, DB-08) flagged that several
high-frequency queries had no supporting index:

* ``sync_jobs.target_id`` is queried by every ``LEFT JOIN sync_jobs j
  ON j.target_id = p.id::text`` in the products list endpoint and by
  the ``_enqueue_sync`` short-circuit. The existing partial UNIQUE
  constraint covers (job_type, target_id, status) but is selective
  only when filtered on those three columns.
* ``findings(product_id, status)`` is the natural composite for the
  Triage / Remediation pages that filter by a status set within a
  product. The pre-existing ``idx_findings_open`` is partial
  (``WHERE status = 'open'``) so it doesn't help with the other
  status values.
* ``findings(status, assigned_to)`` covers the SLA / owner-workload
  queries (e.g. "all open findings for owner X").

All indices are created with ``IF NOT EXISTS`` to keep the migration
idempotent. Downgrade drops them.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # sync_jobs target_id — supports product list join and enqueue dedup.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_sync_jobs_target
            ON sync_jobs(target_id)
        """
    )

    # findings (product_id, status) — Triage / Remediation filters.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_findings_product_status
            ON findings(product_id, status)
        """
    )

    # findings (status, assigned_to) — owner workload, SLA queries.
    # Partial: assigned_to IS NOT NULL keeps the index small (most
    # findings are unassigned).
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_findings_status_assigned
            ON findings(status, assigned_to)
            WHERE assigned_to IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_findings_status_assigned")
    op.execute("DROP INDEX IF EXISTS idx_findings_product_status")
    op.execute("DROP INDEX IF EXISTS idx_sync_jobs_target")
