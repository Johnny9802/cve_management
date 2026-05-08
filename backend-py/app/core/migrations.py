import os

import structlog
from alembic.config import Config

from alembic import command

logger = structlog.get_logger(__name__)


def run_migrations(database_url: str) -> None:
    """Run pending Alembic migrations synchronously.

    Called once at application startup (inside lifespan, before accepting traffic).
    Safe to call repeatedly — Alembic tracks applied revisions in alembic_version table.
    """
    alembic_ini = os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini")
    alembic_ini = os.path.normpath(alembic_ini)

    cfg = Config(alembic_ini)

    # Override the URL from env (ignores the placeholder in alembic.ini)
    url = database_url
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    cfg.set_main_option("sqlalchemy.url", url)

    logger.info("migrations.start")
    command.upgrade(cfg, "head")
    logger.info("migrations.complete")
