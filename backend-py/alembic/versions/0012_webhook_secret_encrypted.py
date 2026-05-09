"""webhook secret encryption-at-rest (Sprint 4 — S4.7)

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-08

Closes DB-06 / SEC-07. The plaintext ``webhooks.secret`` column is
replaced by ``secret_encrypted BYTEA`` storing a Fernet token (AES-128
in CBC + HMAC-SHA256). Encryption/decryption happens in the
application via ``app.services.crypto`` so the queries stay simple
and the encryption key never lands in pg_stat_statements.

Migration policy
----------------
* Add ``secret_encrypted`` (nullable).
* On every row that has a plaintext ``secret``, encrypt it
  application-side at startup if ``WEBHOOK_ENC_KEY`` is set; otherwise
  leave it untouched and log a one-time warning.
* The ``secret`` column is **kept** so dev environments without an
  encryption key still work. The application reads from
  ``secret_encrypted`` first, falling back to ``secret`` for legacy
  rows. This dual-read mode is removed in a future migration once
  ops confirms ``secret`` is empty.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE webhooks
            ADD COLUMN IF NOT EXISTS secret_encrypted BYTEA
        """
    )
    # Index nothing — secrets are read by id, not searched.
    # GRANTs follow the existing pattern in 0006.
    op.execute("GRANT SELECT, UPDATE ON webhooks TO cve_query_engine")
    op.execute("GRANT SELECT, INSERT, UPDATE ON webhooks TO cve_sync_worker")


def downgrade() -> None:
    op.execute("ALTER TABLE webhooks DROP COLUMN IF EXISTS secret_encrypted")
