# OPERATIONS

Production posture, secrets management, and scaling notes for the CVE
Management Platform.

> **Status:** the platform is portfolio-grade after Sprint 4. The
> blockers from `docs/PRODUCTION_READINESS_REVIEW.md` that don't need
> a real cluster (auth, rate limit, security headers, webhook secret
> encryption, soft-delete, leader election, distributed limits, image
> scan, backups, perf baseline) are closed. The blockers that *do*
> need a cluster (k8s manifests, Prometheus + AlertManager wiring) are
> documented in `DEPLOY.md` and left to the operator.

## Pre-deploy checklist

Before the first production rollout:

- [ ] **JWT_SECRET** — set to a 48-byte random URL-safe value:
      `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
      The lifespan refuses to start in `ENVIRONMENT=production` if the
      dev sentinel leaks through.
- [ ] **POSTGRES_PASSWORD** + **REDIS_PASSWORD** — replace the
      `change_me_*` defaults from `.env.example`.
- [ ] **WEBHOOK_ENC_KEY** — Fernet key, generated with
      `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
      The webhooks API returns 503 when this is empty; the app refuses
      to write a plaintext secret.
- [ ] **ADMIN_EMAIL** + **ADMIN_PASSWORD** — first-run seed; remove
      after the first successful login. Subsequent users via DB or
      a future `POST /api/admin/users` endpoint.
- [ ] **SENTRY_DSN** + **NEXT_PUBLIC_SENTRY_DSN** — empty = SDK
      no-ops; set on both sides to capture errors.
- [ ] **VULNCHECK_API_KEY** — required for the primary CVE source.
      `NVD_API_KEY` raises the NIST rate limit; `OPENCVE_API_KEY` and
      `VULNX_API_KEY` are optional enrichers.
- [ ] **AUTO_MIGRATE=false** in production — run migrations via the
      `scripts/migrate.sh` job before the new pods start (R2).
- [ ] **ALLOWED_ORIGIN** — set to the exact frontend origin; never
      `*` in production (the security headers middleware doesn't fix
      a permissive CORS for you).
- [ ] **HSTS** — emitted only when `ENVIRONMENT=production`. Verify
      with `curl -I https://api.example.com/api/health/ready` and
      look for `strict-transport-security: max-age=31536000;
      includeSubDomains`.

## Secret rotation

| Secret | Rotation cadence | How |
|---|---|---|
| `JWT_SECRET` | Annual or after a compromise | Set new value, restart all replicas. **Existing tokens are invalidated**; users re-login. |
| `WEBHOOK_ENC_KEY` | After a DB compromise only | Re-encrypt every row: see `RUNBOOK.md` "rotate webhook encryption key". The lifespan does not re-encrypt automatically. |
| `POSTGRES_PASSWORD` | 90 days | Update the secret manager + restart Postgres + restart the backend. The connection string is read from env on every pool create. |
| `REDIS_PASSWORD` | 90 days | Same pattern as Postgres. |
| `VULNCHECK_API_KEY` / `NVD_API_KEY` / `OPENCVE_API_KEY` / `VULNX_API_KEY` | When provider rotates | `PATCH /api/system/config` with admin token; the new key is stored in Redis (TTL-less) and consulted on every outbound request. |
| `ADMIN_PASSWORD` | After first login | Bcrypt hash in `users.password_hash`; bypass via `UPDATE users SET password_hash=$crypt$...`. |

## Scaling

The Sprint 4 work makes the backend horizontally scalable:

* **Cron jobs** — gated by Redis-based leader election
  (`app/core/leader.py`). Exactly one replica runs `delta_sync`,
  `epss_refresh`, `kev_refresh`, `daily_snapshot`, etc.; the others
  tick the schedule and skip with a debug log.
* **Queue workers** — `sync_jobs` and `webhook_deliveries` are pulled
  with `FOR UPDATE SKIP LOCKED`, so every replica drains work safely.
* **Rate limiter** — slowapi storage points at Redis when `REDIS_URL`
  is set, sharing counters across replicas (`LIMITS:LIMITER/<ip>/<path>`
  keys).
* **Sessions** — JWT bearer; no server-side session state, no sticky
  routing required.

Vertical sizing rule of thumb (single replica, 50 VUs sustained):

| Resource | Per-replica budget |
|---|---|
| CPU | 250 m request / 500 m limit |
| RAM | 256 MiB request / 512 MiB limit |
| Postgres connections | min 2 / max 10 per replica (`asyncpg.create_pool`) |
| Redis | shared, ~5 MB working set on a 50-product inventory |

## Health & observability

| Endpoint | Purpose | Use |
|---|---|---|
| `GET /api/health` | Full status (DB + Redis + circuit breakers + sync state + scheduler jobs) | Dashboard / on-call |
| `GET /api/health/ready` | Liveness/readiness — DB + Redis ping only | Kubernetes probes, docker healthcheck |
| `GET /api/health/metrics` | In-process metrics JSON | Frontend dashboard |
| `GET /metrics` | Prometheus exposition | Scraper config |

Sentry, when configured, captures unhandled exceptions on both sides;
PII is stripped at the SDK layer (`Authorization`, `Cookie`,
`X-API-Key` headers + request bodies + cookies). User context is
limited to id + role.

## What's *not* covered yet

Tracked separately, all behind a real cluster:

* Kubernetes manifests + HPA (S4.1) — see `DEPLOY.md` for the
  pattern; manifests not in repo because they can't be tested
  without a target.
* Prometheus AlertManager rules (S4.11) — would land in
  `monitoring/alerts.yml` once the team has a Prometheus instance.
* Multi-tenant scoping — explicit non-goal of v1; ADR 0002 will
  cover org-level RBAC.
