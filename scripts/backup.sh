#!/usr/bin/env bash
# Postgres backup (Sprint 4 — S4.5).
#
# Daily ``pg_dump`` of the cve_management database into a compressed
# custom-format archive. Output filename includes UTC timestamp so a
# nightly cron can fan out into a directory without colliding.
#
# Default destination is ``./backups/`` on the host. Set
# ``BACKUP_DIR`` to override (e.g. an NFS mount). Set ``BACKUP_S3_BUCKET``
# to additionally upload via aws-cli — left to the operator to wire if
# they want offsite copies.
#
# Retention: anything in ``BACKUP_DIR`` older than ``BACKUP_KEEP_DAYS``
# (default 30) is removed at the end of the run.
#
# Restore is a one-liner:
#   pg_restore -U cve_user -d cve_management --clean --if-exists <backup.dump>
# (see RUNBOOK.md for the full disaster-recovery procedure.)
set -euo pipefail

POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-cve-postgres}"
POSTGRES_USER="${POSTGRES_USER:-cve_user}"
POSTGRES_DB="${POSTGRES_DB:-cve_management}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BACKUP_DIR}/cve-${POSTGRES_DB}-${TS}.dump"

mkdir -p "$BACKUP_DIR"

echo "[backup] container=$POSTGRES_CONTAINER db=$POSTGRES_DB → $OUT"

# -F c : custom format (compressed, parallel-restore-friendly)
# --no-owner / --no-privileges : keeps the dump portable across
#   environments where role names differ (dev cve_user vs prod
#   cve_app).
docker exec "$POSTGRES_CONTAINER" \
  pg_dump \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -F c \
    --no-owner \
    --no-privileges \
  > "$OUT"

# Sanity check — pg_dump returns 0 even on partial dumps in some edge
# cases, so we also assert the file isn't empty.
if [[ ! -s "$OUT" ]]; then
  echo "[backup] FATAL: dump file is empty" >&2
  rm -f "$OUT"
  exit 1
fi

SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "[backup] ok size=$SIZE"

# Optional S3 upload — requires aws-cli configured on the host.
if [[ -n "${BACKUP_S3_BUCKET:-}" ]]; then
  echo "[backup] uploading to s3://$BACKUP_S3_BUCKET/"
  aws s3 cp "$OUT" "s3://${BACKUP_S3_BUCKET}/$(basename "$OUT")"
fi

# Retention.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'cve-*.dump' \
  -mtime "+${BACKUP_KEEP_DAYS}" -print -delete
echo "[backup] retention done (>${BACKUP_KEEP_DAYS}d removed)"
