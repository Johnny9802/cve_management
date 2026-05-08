"""users table for in-app JWT authentication (Sprint 1 — S1.2a)

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-08

See ``docs/adr/0001-auth-strategy.md`` for the full decision record.

Roles
-----
* ``admin`` — all mutations including system config + user management.
* ``analyst`` — finding / product / webhook mutations; cannot approve
  own risk-acceptance (segregation of duty enforced in the router).
* ``viewer`` — read-only.

Password storage
----------------
``password_hash`` stores the full bcrypt output (algorithm + cost +
salt + hash). bcrypt's verify function reads the cost factor from the
hash itself, so increasing the work factor in the future requires no
schema change — only re-hashing on next login.

Email is the natural identifier (no separate username) and is stored
case-insensitively via ``CITEXT``-equivalent (LOWER on insert/lookup at
the application layer; we don't enable the citext extension to keep
the migration minimal).
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id              BIGSERIAL   PRIMARY KEY,
            email           TEXT        NOT NULL UNIQUE
                                        CHECK (email = LOWER(email)),
            password_hash   TEXT        NOT NULL,
            role            TEXT        NOT NULL DEFAULT 'viewer'
                                        CHECK (role IN ('admin', 'analyst', 'viewer')),
            is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login_at   TIMESTAMPTZ
        )
        """
    )

    # Lookup by email is the hot path during login.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_email_active
            ON users(email)
            WHERE is_active = TRUE
        """
    )

    # GRANTs aligned with the hardened roles (migration 0003). The auth
    # router runs as cve_query_engine for SELECTs and cve_sync_worker
    # for the seed INSERT during startup. Both need read; only the
    # latter writes.
    op.execute("GRANT SELECT, UPDATE ON users TO cve_query_engine")
    op.execute("GRANT INSERT, SELECT, UPDATE ON users TO cve_sync_worker")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO cve_sync_worker")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_users_email_active")
    op.execute("DROP TABLE IF EXISTS users")
