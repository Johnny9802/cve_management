# RUNBOOK

Incident response playbook. Each entry: detection → mitigation →
investigation → escalation. Cross-reference Sentry alerts and the
Prometheus rules (when shipped).

## Index

1. [Circuit breaker stuck OPEN](#1-circuit-breaker-stuck-open)
2. [Sync job stuck in `running`](#2-sync-job-stuck-in-running)
3. [Postgres long-running query](#3-postgres-long-running-query)
4. [Redis OOM / eviction storm](#4-redis-oom--eviction-storm)
5. [`/api/health/ready` failing](#5-apihealthready-failing)
6. [Restore Postgres from backup](#6-restore-postgres-from-backup)
7. [Rotate the webhook encryption key](#7-rotate-the-webhook-encryption-key)
8. [Scheduler not firing](#8-scheduler-not-firing)
9. [Rate limiter 429 storm](#9-rate-limiter-429-storm)

---

## 1. Circuit breaker stuck OPEN

**Detection.** `GET /api/health` shows
`circuit_breakers.<provider>.state == "open"` for more than the
recovery timeout (60s NVD/VulnCheck, 5min CIRCL, 1h KEV).
`circuit_breaker_state{provider="..."} == 2` on the Prometheus gauge.

**Mitigation.** Don't try to "kick" the breaker — its job is to
protect us from a bad upstream. The breaker reopens itself on the
next probe call after `recovery_timeout`. If the upstream is genuinely
down for hours, the circuit will keep flipping CLOSED → OPEN; that's
fine — let it.

**Investigation.**
* Check upstream status pages (status.vulncheck.com, status.first.org,
  CISA KEV → simply curl the JSON).
* Look at `provider_errors_total{provider="<name>"}` rate. Steady
  401? Key expired — see secret rotation in OPERATIONS.md.
* Steady 429? Our rate governor is misconfigured for the new tier.

**Escalation.** Customer impact is low — sync is delayed, not lost.
Escalate only if a circuit has been OPEN > 24h.

---

## 2. Sync job stuck in `running`

**Detection.**
```sql
SELECT id, job_type, target_id, locked_until, attempts
FROM sync_jobs
WHERE status = 'running' AND locked_until < NOW();
```

**Mitigation.** The lock has a 5-minute TTL; rows where
`locked_until < NOW()` are claim-able by another worker. The
`sync_job_poll` job will pick them up on the next tick (every 5 s).
If a row stays stuck, force it back to pending:

```sql
UPDATE sync_jobs
SET status = 'pending', locked_until = NULL, attempts = attempts + 1
WHERE id = <id>;
```

**Investigation.** Find the worker that crashed:

```bash
docker compose logs --since 10m backend | grep -E "sync_job|product_sync.*error"
```

**Escalation.** Repeated stuck rows on the same `target_id` mean the
downstream call is killing the worker. Open the relevant CVE/product
manually to confirm it's not a malformed payload.

---

## 3. Postgres long-running query

**Detection.** The PG `log_min_duration_statement = 500` line in
`docker-compose.yml` already logs anything over 500 ms. Look for
``duration: NNNms statement: ...``.

**Mitigation.**

```sql
-- Identify
SELECT pid, now() - query_start AS dur, query
FROM pg_stat_activity
WHERE state != 'idle' ORDER BY dur DESC LIMIT 5;

-- Cancel a single query (sends SIGINT, query has a chance to
-- clean up):
SELECT pg_cancel_backend(<pid>);

-- Last resort, terminate (sends SIGTERM):
SELECT pg_terminate_backend(<pid>);
```

**Investigation.** `EXPLAIN (ANALYZE, BUFFERS) <query>`. The Sprint 2
indices (`idx_sync_jobs_target`, `idx_findings_product_status`,
`idx_findings_status_assigned`) cover every hot read path; a plan
that hits Seq Scan is a regression — file an issue.

---

## 4. Redis OOM / eviction storm

**Detection.** `INFO memory` shows `maxmemory_policy:allkeys-lru` and
`evicted_keys` climbing. Dashboard cache misses spike.

**Mitigation.** Already configured: Valkey has
`--maxmemory 256mb --maxmemory-policy allkeys-lru` (compose), so it
self-protects. If eviction is constant, raise `maxmemory` to 512 MB
and rebuild.

**Investigation.** What's filling the cache?

```bash
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" \
  --bigkeys
```

Common culprits: stale `intel:*` keys (10-min TTL — should expire),
runaway `LIMITS:LIMITER/...` keys when the same IP hammers the API
(legit, slowapi prunes them on its own).

---

## 5. `/api/health/ready` failing

**Detection.** Docker health check flips to `unhealthy`; Kubernetes
removes the pod from the service.

**Mitigation.** Ready checks are simple — DB SELECT 1 + Redis PING.

```bash
curl -v http://localhost:3011/api/health/ready
docker compose exec postgres pg_isready -U cve_user -d cve_management
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" PING
```

If both deps respond, the issue is in the FastAPI lifespan — restart
the backend.

**Investigation.** Lifespan errors are logged at startup:

```bash
docker compose logs --tail=200 backend | grep -E "startup\.|sentry\.|leader\."
```

A common cause is an unset `JWT_SECRET` in production (the lifespan
refuses to start). Another is the migration step taking >60s on a
huge new index — chunk the migration or run it offline.

---

## 6. Restore Postgres from backup

**Pre-condition.** A `*.dump` file from `scripts/backup.sh` (custom
format, compressed).

```bash
# 1. stop app pods so writes don't race the restore
docker compose stop backend frontend

# 2. drop + recreate the database (DESTRUCTIVE)
docker compose exec postgres psql -U cve_user -d postgres -c \
  "DROP DATABASE IF EXISTS cve_management;"
docker compose exec postgres psql -U cve_user -d postgres -c \
  "CREATE DATABASE cve_management;"

# 3. restore
docker compose exec -T postgres pg_restore \
  -U cve_user -d cve_management --clean --if-exists \
  < /path/to/cve-cve_management-YYYYMMDD.dump

# 4. start app — alembic_version table is part of the dump, so the
#    auto-migrate on boot is a no-op (head is already current).
docker compose start backend frontend
```

**RTO target:** 30 min for a 100 MB dump on a developer laptop;
production should be 10× faster on real hardware.

**RPO target:** 24 h (nightly cron). Tighten with hourly cron + WAL
shipping when the org needs it.

---

## 7. Rotate the webhook encryption key

The plaintext signing secret is encrypted with Fernet
(`WEBHOOK_ENC_KEY`); rotating means re-encrypting every row.

```bash
# 1. generate new key (do NOT replace the old one yet)
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. one-shot Python script — exits 0 if every row was rewritten
python <<EOF
import asyncio, os
import asyncpg
from cryptography.fernet import Fernet

OLD = Fernet(os.environ["WEBHOOK_ENC_KEY"].encode())
NEW = Fernet(b"$NEW_KEY")

async def main():
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    rows = await pool.fetch("SELECT id, secret_encrypted FROM webhooks")
    async with pool.acquire() as conn, conn.transaction():
        for r in rows:
            plain = OLD.decrypt(bytes(r["secret_encrypted"])).decode()
            new_token = NEW.encrypt(plain.encode())
            await conn.execute(
                "UPDATE webhooks SET secret_encrypted = \$1 WHERE id = \$2",
                new_token, r["id"]
            )
    await pool.close()

asyncio.run(main())
EOF

# 3. set the new key in the env, restart the backend
echo "WEBHOOK_ENC_KEY=$NEW_KEY" >> .env
docker compose up -d --no-deps backend
```

---

## 8. Scheduler not firing

**Detection.** `GET /api/health` shows `scheduler_jobs: []` or
`next_run_time` is `null` for every job.

**Mitigation.** Likely the leader election lock is stuck. The TTL is
30s — wait 60s and check again. If the lock is held by a node id that
no longer exists:

```bash
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" GET scheduler:leader
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" DEL scheduler:leader
```

The next backend will acquire it on its next refresh tick (10 s).

**Investigation.** Multi-replica: only one replica should be leader.
`grep "leader\.acquired" backend.log` across all replicas — exactly
one match per ~30 s.

---

## 9. Rate limiter 429 storm

**Detection.** Frontend calls fail with 429 + `Retry-After` headers.
`http_requests_total{status="429"}` spikes.

**Mitigation.** First check: is it a real attacker or our own load
test?

```bash
# What IP is being throttled?
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" \
  --scan --pattern 'LIMITS:LIMITER/*' | head
```

If it's the legit frontend IP (e.g. all users behind one corporate
NAT), bump the default in `app/core/rate_limit.py` and ship. If it's
an attacker, the limiter is doing its job — capture the IP and add
it to the upstream WAF/proxy denylist. Don't touch the application
config.

To clear the buckets manually (use sparingly, the limit will reset
naturally on the next minute):

```bash
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" \
  --scan --pattern 'LIMITS:*' | \
  xargs -r docker compose exec -T valkey valkey-cli -a "$REDIS_PASSWORD" DEL
```
