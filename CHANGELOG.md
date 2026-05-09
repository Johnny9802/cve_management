# Changelog

All notable changes to this project. Conventional Commits-aligned.
The MVP itself was developed before this file was introduced; entries
start at the Sprint 1 hardening cycle which is the point at which the
platform crossed into "release-management worthy".

## [0.4.0] — 2026-05-09 — Sprint 4 (deploy & ops hardening)

### Security

* Soft-delete on `products` (alembic 0011) — DELETE no longer
  cascades the audit trail away (S4.6, R5).
* Webhook secrets encrypted at rest with Fernet; the plaintext
  `webhooks.secret` column is gone (S4.7, DB-06 / SEC-07 / R6).
* WEBHOOK_ENC_KEY is required to create a webhook in any environment;
  the API returns 503 without it instead of falling open.

### Scaling

* Redis-based single-leader election for cron jobs
  (`app/core/leader.py`); replicas without the lock skip
  delta_sync / epss_refresh / kev_refresh / daily_snapshot /
  expire_risk_acceptances / opencve_poll / vulnx_refresh /
  retention_cleanup / queue_cleanup. Per-replica jobs
  (sync_job_poll, webhook_dispatch) keep running everywhere
  (S4.8, R3).
* slowapi storage points at Redis when REDIS_URL is set; rate-limit
  counters shared across replicas (S4.9).

### Build

* `uv.lock` committed; Dockerfile now runs `uv sync --frozen`
  (S4.4). Build is byte-identical given the same lock + base image.
* uv binary pinned to `0.4.18` (was `:latest`).
* `[build-system]` + `[tool.hatch]` block added to `pyproject.toml`
  so `uv sync` recognises the workspace and installs the deps array.

### CI

* New `supply-chain` job: gitleaks history scan, pip-audit on backend
  deps, npm audit on frontend deps. All non-blocking; report-only
  baseline (S4.3).
* New `images` job: builds backend + frontend Docker images with
  Buildx, Trivy scans each (CRITICAL+HIGH SARIF uploaded to GitHub
  Security tab), and pushes to `ghcr.io/<repo>/{backend,frontend}`
  with `:latest` and `:<sha7>` tags **only on main**. PRs build +
  scan but never push.

### Ops & docs

* `scripts/migrate.sh` — standalone migration runner targeting the
  init-container pattern (S4.2).
* `scripts/backup.sh` — nightly `pg_dump -F c` with retention,
  optional S3 upload (S4.5). Restore documented in RUNBOOK.
* `tests/perf/baseline.js` — k6 production sign-off load profile
  with p95 + error-rate thresholds (S4.12).
* `docs/OPERATIONS.md`, `docs/RUNBOOK.md`, `docs/ARCHITECTURE.md`,
  `docs/DEPLOY.md` (S4.10).

### Deferred (require a real cluster)

* Kubernetes manifests + HPA (S4.1) — sketched in DEPLOY.md.
* Prometheus AlertManager rules (S4.11).

## [0.3.0] — 2026-05-08 — Sprint 3 (frontend tests + a11y + observability)

### Added

* Vitest + React Testing Library wiring; 17 unit tests on Badge
  family, ErrorBoundary, lib/auth, lib/csv (S3.1).
* Playwright E2E smoke (login → dashboards → findings) with
  axe-core a11y assertions (S3.2 / S3.3).
* `components/UI/Form.jsx` (TextField / Select / Textarea) with
  forced ids + aria-describedby; `LoadingSkeleton` family (S3.4).
* Page-level `ErrorBoundary` mounted inside `AppShell`; subtree
  render errors no longer blank the dashboard (S2.7 / S3.6 hook).
* Prometheus `/metrics` endpoint with HTTP histogram, per-provider
  counters, circuit breaker gauge, OpSec egress counter (S3.7).
* Sentry SDK on both sides (`sentry-sdk[fastapi]` + `@sentry/browser`)
  with PII scrubbed `before_send` and lazy require so the SSR bundle
  stays Sentry-free when no DSN is set (S3.6).

### Fixed

* Charts on the legacy dashboard accept `onClick` and act as filter
  chips (FE-05).
* `<fieldset>`/`<legend>` on `/reports/audit` action filter — was a
  free-floating label above a radiogroup (FE-14).

## [0.2.0] — 2026-05-08 — Sprint 2 (FE pages + DB hardening + tests)

### Added

* `/findings` — list with FSM tabs + drawer with history and status
  picker (S2.1, FE-01).
* `/webhooks` — CRUD + test + delivery log; secret surfaced once on
  create (S2.2, FE-02).
* `/inventory` — drop-zone CSV upload + tabs software/OS heuristic
  (S2.4, FE-09 / FE-11).
* `/reports/{sla,mttr,audit}` — three single-purpose governance
  views (S2.3).
* alembic 0010 — composite indices on `findings(product_id,status)`
  and `findings(status,assigned_to)`, plus
  `idx_sync_jobs_target` for the products list join (S2.11).
* Daily `queue_cleanup` scheduler job — drops `sync_jobs`
  completed > 90d / dead > 30d and `webhook_deliveries`
  delivered > 90d (DB-04, DB-05).
* 12 unit tests for `CircuitBreaker` FSM (TST-02 / S2.9).
* 8 integration tests covering authz invariants on every mutating
  router (S2.8).
* `pytest-cov` reporting in CI; advisory 70% target documented
  (S2.10).

### Fixed

* `audit.record_in_tx` now passes `'{}'` to `metadata` instead of
  NULL when the caller omits it; closes a regression where
  PATCH /api/findings returned 500 because of a NOT NULL constraint
  on `audit_log.metadata`.

## [0.1.0] — 2026-05-08 — Sprint 1 (auth + hardening)

### Added

* JWT bearer authentication + RBAC (admin / analyst / viewer) —
  ADR 0001. Login + refresh + me endpoints; require_role decorator
  on every mutating router (S1.1 / S1.2 / S1.3).
* slowapi rate limiter, default 200/min/IP, `3/min` on
  `/api/cves/export` (S1.5).
* Security headers middleware (CSP / X-Frame / X-Content-Type /
  Referrer / Permissions / HSTS in prod) (S1.6).
* Audit log on every mutating endpoint
  (products / webhooks / system / findings / risk_acceptance) (S1.7).
* Frontend login page + axios bearer interceptor + AuthGate
  client-side guard (S1-FE).

### Removed

* The legacy Node.js `backend/` directory (S1.4); the FastAPI
  rewrite was canonical for two months but the old code was still
  buildable.
