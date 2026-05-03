# CVE Management Platform — Developer Guide

## Overview

Vulnerability management platform: ingests CVEs from VulnCheck NVD++ / NIST NVD, matches them against a software inventory, and surfaces prioritised findings for remediation tracking.

**Stack:** Python 3.12 / FastAPI / asyncpg / Valkey / PostgreSQL 16  
**Architecture:** 4-layer (Data → Ingestion → Resolution → Query) — see plan at `~/.claude/plans/lovely-splashing-zephyr.md`

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | ≥ 3.12 | `brew install python@3.12` |
| uv | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Docker | ≥ 24 | Docker Desktop |
| docker compose | v2 | bundled with Docker Desktop |

---

## Quick Start — Local Dev (no Docker)

```bash
cd backend-py

# Create venv + install all deps including dev
uv venv --python 3.12
uv sync --extra dev

# Copy and edit environment
cp ../.env.example ../.env
# Edit ../.env — set POSTGRES_PASSWORD, REDIS_PASSWORD, VULNCHECK_API_KEY

# Start only the infrastructure (no app container)
cd .. && docker compose up postgres valkey -d

# Run migrations
cd backend-py
DATABASE_URL="postgresql://cve_user:your_password@localhost:5433/cve_management" \
  uv run alembic upgrade head

# Start the backend with hot-reload
DATABASE_URL="postgresql://cve_user:your_password@localhost:5433/cve_management" \
REDIS_URL="redis://:your_redis_password@localhost:6380" \
VULNCHECK_API_KEY="your_key" \
  uv run uvicorn app.main:app --reload --port 8000

# API docs: http://localhost:8000/api/docs
# Health:   http://localhost:8000/api/health
```

---

## Quick Start — Full Stack (Docker Compose)

```bash
cp .env.example .env
# Edit .env — minimum: POSTGRES_PASSWORD, REDIS_PASSWORD, VULNCHECK_API_KEY

# Build and start everything
docker compose up --build

# Logs
docker compose logs -f backend

# Stop
docker compose down
```

The frontend is at `http://localhost:3000`.  
The Python API is at `http://localhost:3001`.

---

## Running Tests

```bash
cd backend-py

# Unit + contract tests (no Docker required)
uv run pytest tests/unit/ tests/contract/ -v

# Integration tests (requires Docker daemon)
uv run pytest tests/integration/ -v -s

# Full suite with coverage
uv run pytest --cov=app --cov-report=term-missing

# Single test file
uv run pytest tests/unit/test_version_matcher.py -v
```

---

## Database Migrations

```bash
cd backend-py

# Apply all pending migrations
uv run alembic upgrade head

# Create a new migration
uv run alembic revision --autogenerate -m "add_my_table"

# Rollback one step
uv run alembic downgrade -1

# Check current revision
uv run alembic current
```

---

## Project Structure

```
backend-py/
├── app/
│   ├── api/routers/     # FastAPI routers (products, cves, findings, dashboard, health)
│   ├── core/            # config, db pool, cache, logging, metrics
│   ├── ingestion/       # VulnCheck/NVD clients, rate governor, circuit breaker, enrichment
│   ├── models/          # Pydantic models (nvd, product, finding, priority)
│   ├── query/           # Multi-tier query engine (local → CIRCL → OpenCVE)
│   ├── resolution/      # CPE normalizer, version matcher, resolution cache
│   └── workers/         # Product sync, sync job queue, APScheduler
├── alembic/versions/    # Database migrations (0001 → 0003)
└── tests/
    ├── unit/            # Pure-function tests (no I/O)
    ├── integration/     # testcontainers (PostgreSQL + Redis)
    └── contract/        # respx HTTP mocks per provider
```

---

## Common Operations

### Add a product manually
```bash
curl -X POST http://localhost:3001/api/products \
  -H "Content-Type: application/json" \
  -d '{"name":"nginx","vendor":"nginx","version":"1.18.0"}'
```

### Trigger a manual CVE sync for a product
```bash
curl -X POST http://localhost:3001/api/products/1/sync
```

### Update a finding status
```bash
curl -X PATCH http://localhost:3001/api/findings/1/CVE-2024-1234 \
  -H "Content-Type: application/json" \
  -d '{"status":"in_review","actor":"analyst@example.com","reason":"Investigating"}'
```

### Check sync state + circuit breakers
```bash
curl http://localhost:3001/api/health | jq '{sync_state, circuit_breakers}'
```

### View provider metrics
```bash
curl http://localhost:3001/api/health/metrics | jq '.providers'
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | — | asyncpg-compatible PostgreSQL DSN |
| `REDIS_URL` | yes | — | Valkey/Redis connection URL |
| `VULNCHECK_API_KEY` | yes* | — | VulnCheck NVD++ API key (*free tier available) |
| `NVD_API_KEY` | no | — | NIST NVD API key (raises rate limit to 50 req/30s) |
| `OPENCVE_API_KEY` | no | — | OpenCVE polling key (Tier 3, optional) |
| `ALLOWED_ORIGIN` | no | `http://localhost:3000` | CORS allowed frontend origin |
| `AUTO_MIGRATE` | no | `true` | Run Alembic migrations at startup |
| `DELTA_SYNC_INTERVAL_HOURS` | no | `1` | CVE delta sync frequency |
| `LOG_LEVEL` | no | `INFO` | `DEBUG` / `INFO` / `WARNING` |
| `ENVIRONMENT` | no | `development` | `development` / `production` |

---

## Architecture Notes

- **OpSec constraint:** asset inventory never leaves the perimeter for routine queries. CIRCL / OpenCVE are fallback-only (Tier 2/3). Raw product names/hostnames never sent externally.
- **Rate limiting:** per-provider `TokenBucket` (asyncio.Semaphore, single-instance). See `app/ingestion/rate_governor.py`.
- **Circuit breakers:** per-provider FSM (CLOSED→OPEN→HALF_OPEN). State visible at `/api/health`.
- **Sync queue:** DB-backed (`sync_jobs` table, `FOR UPDATE SKIP LOCKED`), polled every 5s by APScheduler.
- **Version matching:** `app/resolution/version_matcher.py` — port of Node.js logic, handles semver, OpenSSL patch letters, pre-releases.
- **CVE priority score:** EPSS×40 + CVSS severity band (0-25) + KEV (+25) + recency (0-10) = 0-100. See `app/models/priority.py`.
