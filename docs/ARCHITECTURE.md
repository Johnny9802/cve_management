# ARCHITECTURE

Quick navigation: see the production-readiness review at
`docs/PRODUCTION_READINESS_REVIEW.md` for the as-built audit and
risk register, and `docs/adr/0001-auth-strategy.md` for the auth
trade-offs.

## High level

```
                        ┌─────────────────┐
                        │  Frontend       │   Next.js 14, dark theme,
                        │  (Next.js)      │   server components for SEO
                        │                 │   client components for state.
                        └─────────┬───────┘
                                  │ HTTPS · JWT bearer
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  FastAPI backend                                             │
   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
   │  │ API routers  │→│ Service layer │→│ Repos / asyncpg   │   │
   │  │ (47 routes)  │  │ (audit,       │  │                   │   │
   │  │              │  │  webhooks,    │  │                   │   │
   │  │              │  │  crypto …)    │  │                   │   │
   │  └──────┬───────┘  └──────────────┘  └────────┬─────────┘   │
   │         │                                     │             │
   │         │ ▶ Middleware: SecurityHeaders,      │             │
   │         │   CORS, slowapi, Prometheus,        │             │
   │         │   AuthGate (FE) / require_role (BE) │             │
   │         │                                     │             │
   │  ┌──────▼──────┐                              ▼             │
   │  │ Workers     │   ┌─────────────────┐  ┌────────────┐      │
   │  │ APScheduler │──▶│ sync_jobs queue │  │ PostgreSQL │      │
   │  │ leader-only │   │ (FOR UPDATE     │  │            │      │
   │  │             │   │  SKIP LOCKED)   │  └────────────┘      │
   │  └──────┬──────┘   └────────┬────────┘                      │
   │         │                   │                               │
   │         │           ┌───────▼────────┐                      │
   │         └──────────▶│ Valkey (Redis) │  cache, rate limit,  │
   │                     │                │  scheduler:leader,   │
   │                     │                │  intel:*, dashboard:*│
   │                     └────────────────┘                      │
   └──────────┬───────────────────────────────────┬──────────────┘
              │                                   │
              ▼                                   ▼
        Outbound (OpsecAware)              Outbound webhooks
        VulnCheck NVD++                    (HMAC SHA-256
        NIST NVD                            signed; SSRF-checked)
        FIRST EPSS
        CISA KEV
        OpenCVE (opt)
        ProjectDiscovery vulnx (opt)
```

## Layers

The backend follows the four-layer split documented at the start of
the rewrite:

| Layer | Modules | Responsibility |
|---|---|---|
| **Data** | `app/api/routers/*` | Authentication, authorization, validation, response shaping. Routers never do business logic; they orchestrate. |
| **Ingestion** | `app/ingestion/*`, `app/workers/*` | Pull CVE data from upstream APIs, respect rate limits, retry, fail closed via the circuit breaker. Owned by the leader replica. |
| **Resolution** | `app/resolution/*` | Match a software inventory entry against a CVE. Pure functions where possible (`version_matcher`), backed by Redis for the CPE alias cache. |
| **Query** | `app/query/*`, `app/services/*` | Read-side: dashboards, finding lifecycle, audit log, webhooks dispatch. The split keeps read paths off the ingestion hot loop. |

## Resilience patterns

* **Token-bucket rate limiter** per upstream provider
  (`app/ingestion/rate_governor.py`). One bucket per provider so a
  slow VulnCheck doesn't starve EPSS.
* **Circuit breaker** per provider
  (`app/ingestion/circuit_breaker.py`). FSM `CLOSED → OPEN →
  HALF_OPEN`; recovery timeouts tuned per provider's typical recovery
  window.
* **OpSec egress filter** (`app/core/http.py:OpsecAwareClient`).
  Outbound bodies are scanned for asset-shaped data (IPv4, MAC,
  hostname / asset_id field names) and blocked before leaving the
  perimeter.
* **SSRF guard** (`app/core/ssrf.py`). Webhook URLs are resolved and
  every returned IP checked against RFC1918 / loopback / link-local /
  cloud-metadata ranges.
* **Distributed leader** (`app/core/leader.py`). Cron jobs gate on
  `leader.is_leader` so multi-replica deployments don't N-times the
  upstream quota.

## Database surface

13 tables, ~10 hot indices. Full schema in
`docs/PRODUCTION_READINESS_REVIEW.md` §B.3 and the alembic
migrations under `backend-py/alembic/versions/`.

Highlights:

* `users` — bcrypt password hash, role check constraint, partial
  index on active emails (S1.2a).
* `findings` + `findings_history` — FSM transitions land in history;
  composite indices on `(product_id, status)` and partial on
  `(status, assigned_to)` cover Triage / Remediation queries (S2.11).
* `audit_log` — diff JSONB column, masking applied at write time
  (`app/services/audit.py`); never CASCADE'd (audit outlives the
  thing it describes).
* `webhooks.secret_encrypted` — Fernet-encrypted ciphertext (S4.7);
  the plaintext column is gone.
* `products.is_deleted` — soft-delete (S4.6) with a partial UNIQUE
  on live rows so re-adding a deleted product is allowed.

## Deploy stance

Single docker-compose stack today (see `DEPLOY.md`). All Sprint 4
hardening (JWT, leader election, distributed rate limiter, image
scan, encryption-at-rest, soft-delete, backup, perf baseline) is
ready for a multi-replica swing without a code change — only env
vars + `AUTO_MIGRATE=false` + a kubectl apply away.

## Authoritative sources

* `docs/PRODUCTION_READINESS_REVIEW.md` — full as-built audit, risk
  register, sprint plan.
* `docs/adr/0001-auth-strategy.md` — auth model.
* `CHANGELOG.md` — version history.
* `OPERATIONS.md` — secrets, scaling, hardening checklist.
* `RUNBOOK.md` — incident response.
* `DEPLOY.md` — deploy patterns (compose + the k8s sketch).
