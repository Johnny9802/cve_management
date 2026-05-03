# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml .

# Create venv then install deps using uv (avoids pip-in-venv bootstrapping)
RUN uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python3 --no-cache \
        "fastapi>=0.111.0" \
        "uvicorn[standard]>=0.30.0" \
        "asyncpg>=0.29.0" \
        "httpx>=0.27.0" \
        "pydantic>=2.7.0" \
        "pydantic-settings>=2.3.0" \
        "structlog>=24.1.0" \
        "arq>=0.26.0" \
        "apscheduler>=3.10.0,<4.0.0" \
        "rapidfuzz>=3.9.0" \
        "alembic>=1.13.0" \
        "sqlalchemy[asyncio]>=2.0.0" \
        "redis[hiredis]>=5.0.0"

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
