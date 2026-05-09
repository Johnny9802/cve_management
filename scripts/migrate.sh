#!/usr/bin/env bash
# Standalone migration runner (Sprint 4 — S4.2).
#
# In a multi-replica deployment we set ``AUTO_MIGRATE=false`` and
# run this script as a Kubernetes init container or a deploy-time job.
# The pattern fixes blocker R2: ``AUTO_MIGRATE=true`` on every replica
# races on ``alembic_version`` LOCKs and produces sporadic startup
# failures.
#
# Usage:
#   DATABASE_URL=postgres://... ./scripts/migrate.sh
#
# The script intentionally fails fast: if migrations fail, the deploy
# pipeline must surface the error before the new app pods start.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[migrate] DATABASE_URL is required" >&2
  exit 2
fi

# Run inside the backend image so we don't need a host Python install.
# Pinned to the same image tag the deployment uses; in CI/CD this is
# the freshly-built image — guaranteed to ship the alembic versions
# the app expects.
IMAGE="${BACKEND_IMAGE:-cve-management-backend:latest}"

echo "[migrate] image=$IMAGE"
echo "[migrate] DATABASE_URL=${DATABASE_URL%%@*}@<redacted>"

docker run --rm \
  --network "${DOCKER_NETWORK:-cve-management-network}" \
  -e "DATABASE_URL=$DATABASE_URL" \
  -e "PYTHONPATH=/app" \
  "$IMAGE" \
  /opt/venv/bin/alembic -c /app/alembic.ini upgrade head

echo "[migrate] done"
