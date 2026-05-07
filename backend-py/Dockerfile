# =============================================================================
# CVE Management Platform — Backend Dockerfile (Python 3.12 / FastAPI)
# -----------------------------------------------------------------------------
# Multi-stage build:
#   1. builder — uses `uv` to install runtime deps from pyproject.toml into
#      /opt/venv. Single source of truth: dependency list lives in
#      pyproject.toml, NOT duplicated here.
#   2. runtime — slim image with the prepared venv, app code, alembic, and a
#      non-root user.
#
# Note on reproducibility: a `uv.lock` was not generated at refactor time
# because `uv` is not installed on the build host. As a result we use
# `uv sync --no-dev --no-install-project` WITHOUT `--frozen`, which resolves
# deps at build time against pyproject.toml constraints. To get fully
# reproducible builds, run `uv lock` locally, commit `uv.lock`, then change
# the COPY + uv sync lines below (see inline TODO).
# =============================================================================

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1

# Pull the uv binary from the official Astral image (pinned to :latest;
# pin to a version tag like :0.4.0 in stricter environments).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create the target venv at the canonical /opt/venv path used by runtime.
RUN uv venv /opt/venv

# Copy ONLY pyproject.toml so dep layer is cached when project code changes.
# TODO: when uv.lock is committed, change to:
#       COPY pyproject.toml uv.lock ./
#       RUN VIRTUAL_ENV=/opt/venv uv sync --frozen --no-dev --no-install-project
COPY pyproject.toml ./

# Install runtime deps into /opt/venv. --no-install-project skips building the
# project itself (source not present in this stage). --no-dev excludes the
# dev-dependencies group. uv reads dependencies from pyproject.toml.
ENV VIRTUAL_ENV=/opt/venv
RUN uv sync --no-dev --no-install-project

# ── Stage 2: runtime image ─────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    VIRTUAL_ENV=/opt/venv

COPY --from=builder /opt/venv /opt/venv

COPY app/      ./app/
COPY alembic/  ./alembic/
COPY alembic.ini .

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup --no-create-home appuser && \
    chown -R appuser:appgroup /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=30s \
    CMD python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health/ready')" \
        || exit 1

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "warning", \
     "--workers", "1"]
