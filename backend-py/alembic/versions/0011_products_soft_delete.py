"""products soft-delete (Sprint 4 — S4.6)

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-08

The hard DELETE on /api/products/{id} cascades to findings,
findings_history and risk_acceptances — all of which are governance-
relevant data the audit_log must outlive. Sprint 1 mitigated by
writing an audit row before the cascade, but the diff still loses
the connecting findings.

This migration introduces soft-delete columns. The router (next
commit) flips DELETE to set is_deleted=true and stamp the actor; the
cascade never fires.

Reads ignore deleted rows by default (a partial UNIQUE index keeps
the (name, vendor, version) constraint working only over live rows
so a re-add of a previously-deleted product is allowed).
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE products
            ADD COLUMN IF NOT EXISTS is_deleted   BOOLEAN     NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS deleted_at   TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS deleted_by   TEXT
        """
    )

    # Live-only partial index for the lookup hot path.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_products_live
            ON products(name, vendor, version)
            WHERE is_deleted = FALSE
        """
    )

    # The original UNIQUE(name, vendor, version) — defined inline in
    # 0001 — would block a re-add of a name/version pair that's been
    # soft-deleted. We replace it with a partial UNIQUE on live rows.
    op.execute(
        """
        DO $$ BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'products_name_vendor_version_key'
            ) THEN
                ALTER TABLE products
                    DROP CONSTRAINT products_name_vendor_version_key;
            END IF;
        END $$;
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_products_live_name_vendor_version
            ON products(name, vendor, version)
            WHERE is_deleted = FALSE
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_products_live_name_vendor_version")
    # Restore the original UNIQUE; if any soft-deleted duplicates exist
    # this will fail loudly — that's the desired behaviour, hard-delete
    # them first.
    op.execute(
        """
        ALTER TABLE products
            ADD CONSTRAINT products_name_vendor_version_key
            UNIQUE (name, vendor, version)
        """
    )
    op.execute("DROP INDEX IF EXISTS idx_products_live")
    op.execute(
        """
        ALTER TABLE products
            DROP COLUMN IF EXISTS deleted_by,
            DROP COLUMN IF EXISTS deleted_at,
            DROP COLUMN IF EXISTS is_deleted
        """
    )
