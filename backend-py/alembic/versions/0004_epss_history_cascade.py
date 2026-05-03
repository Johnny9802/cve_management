"""fix epss_history FK to add ON DELETE CASCADE

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-02
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE epss_history
            DROP CONSTRAINT IF EXISTS epss_history_cve_id_fkey;
    """)
    op.execute("""
        ALTER TABLE epss_history
            ADD CONSTRAINT epss_history_cve_id_fkey
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE;
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE epss_history
            DROP CONSTRAINT IF EXISTS epss_history_cve_id_fkey;
    """)
    op.execute("""
        ALTER TABLE epss_history
            ADD CONSTRAINT epss_history_cve_id_fkey
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id);
    """)
