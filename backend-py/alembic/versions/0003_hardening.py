"""db hardening: revoke public schema, create RBAC roles, grant minimum privilege

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-30

Requires: the connection user must have CREATEROLE and schema ownership.
In the Docker self-hosted setup (POSTGRES_USER=cve_user), this runs fine because
the docker postgres image creates POSTGRES_USER with superuser privileges.
In managed environments (RDS, Supabase) run this migration as the master user.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # CVE-2018-1058: prevent unprivileged users from creating objects in public schema
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")

    # Idempotent role creation via DO blocks
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cve_sync_worker'
            ) THEN
                CREATE ROLE cve_sync_worker
                    LOGIN
                    PASSWORD 'change_sync_worker_password_before_production'
                    CONNECTION LIMIT 5;
            END IF;
        END
        $$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cve_query_engine'
            ) THEN
                CREATE ROLE cve_query_engine
                    LOGIN
                    PASSWORD 'change_query_engine_password_before_production'
                    CONNECTION LIMIT 10;
            END IF;
        END
        $$
    """)

    # Grant schema usage to both roles
    op.execute("GRANT USAGE ON SCHEMA public TO cve_sync_worker, cve_query_engine")

    # sync_worker: INSERT/UPDATE on tables it writes to
    op.execute("""
        GRANT INSERT, UPDATE ON
            cves,
            products,
            findings,
            findings_history,
            sync_jobs,
            sync_state,
            cpe_resolutions,
            subscriptions_opencve,
            audit_log,
            epss_history
        TO cve_sync_worker
    """)

    # sync_worker also needs SELECT (for upsert ON CONFLICT + queries)
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO cve_sync_worker")

    # sync_worker needs sequence access for BIGSERIAL inserts
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cve_sync_worker")

    # query_engine: SELECT only — zero write access
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO cve_query_engine")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cve_query_engine")

    # Ensure future tables inherit these grants (ALTER DEFAULT PRIVILEGES)
    op.execute("""
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT SELECT ON TABLES TO cve_query_engine
    """)
    op.execute("""
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE ON TABLES TO cve_sync_worker
    """)
    op.execute("""
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO cve_sync_worker, cve_query_engine
    """)


def downgrade() -> None:
    # Reverting hardening is intentionally incomplete — dropping roles
    # that may own objects can cause data loss. Downgrade only restores PUBLIC access.
    op.execute("GRANT ALL ON SCHEMA public TO PUBLIC")
    # To fully remove roles: DROP ROLE cve_sync_worker; DROP ROLE cve_query_engine;
    # Run manually if needed.
