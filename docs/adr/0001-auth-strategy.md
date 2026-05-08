# ADR 0001 — Authentication & Authorization Strategy

**Status:** Accepted
**Date:** 2026-05-08
**Sprint:** 1 (production-readiness hardening)
**Supersedes:** none — first auth ADR for the platform

## Context

The platform exposes 47 HTTP endpoints today. Until Sprint 1, **none of
them required authentication**. That means anyone with network access
to the backend can:

* Overwrite the VulnCheck / NVD / OpenCVE API keys via
  `PATCH /api/system/config`, breaking sync silently or routing
  egress through an attacker-controlled key.
* Create or approve risk-acceptance records on any finding (the
  `requested_by` / `decided_by` fields are accepted as free-form
  strings from the request body).
* Modify finding status (open ↔ remediated ↔ accepted_risk), distorting
  governance reporting.
* Delete products / webhooks, cascading audit-log loss.

This is risk **R1** in the production-readiness review and is the
single largest blocker to a production rollout.

## Decision

Implement **JWT bearer authentication in-app** with **role-based
authorization** at three levels: `admin`, `analyst`, `viewer`.

### Why in-app and not behind a reverse-proxy?

| Option | Score |
|---|---|
| **JWT in-app** (chosen) | Self-contained, no extra infra, easy demo, FastAPI-idiomatic via `Depends`. |
| Reverse-proxy (oauth2-proxy + GitHub OAuth) | Cleaner separation but introduces an extra service in compose / k8s; portfolio-overkill. |
| Static API key | Cheapest, but no UI login, no roles, no per-user audit. Discarded. |

The platform is currently a single-org tool. The complexity of an
external IdP isn't justified before multi-tenancy (Sprint 5+). When
that ships we revisit and this ADR is superseded by ADR 0002.

### Token shape and lifecycle

* **Access token** — JWT signed with HS256, payload
  `{sub: user_id, email, role, exp, iat, type: "access"}`, TTL **60 minutes**.
* **Refresh token** — JWT signed with HS256, payload
  `{sub: user_id, exp, iat, type: "refresh"}`, TTL **7 days**.
* `JWT_SECRET` is a required environment variable in `production`.
  In `development` we fall back to a fixed dev secret with a **loud
  warning at startup** so nobody mistakes a dev container for a real
  deployment.

### Roles and authorization model

| Role | Can do | Cannot do |
|---|---|---|
| `admin` | All POST/PATCH/DELETE incl. `/api/system/config` and user management | — |
| `analyst` | Mutate findings, products, webhooks; create risk-acceptance | Approve own risk-acceptance (segregation of duty); update system config; manage users |
| `viewer` | Read-only on all GET endpoints | Any mutation |

GET endpoints stay **public for the MVP** to keep the demo low-friction.
This is documented and tracked as a follow-up: when multi-tenant
scoping lands we flip them to `Depends(require_authenticated)`.

### Password storage

* **bcrypt** with cost factor 12 (default). Hash + work-factor stored
  in `users.password_hash`.
* No password recovery flow in Sprint 1 — admin resets passwords
  directly (CLI / DB). Self-service reset is a Sprint 2+ concern.

### Initial admin seed

On first startup, if the `users` table is empty and the env vars
`ADMIN_EMAIL` and `ADMIN_PASSWORD` are set, the app creates a single
admin user. After that, the seed code is a no-op. This avoids shipping
a hard-coded `admin@example.com` / `changeme` and forces operators to
think about credentials before the app has any.

### Frontend token storage

`localStorage` (not `httpOnly` cookie). Trade-offs:

* **Pro** — zero CSRF surface; no server-side session state; works
  with the static Next.js standalone output without extra
  middleware.
* **Con** — XSS would expose the token. Mitigation: the strict CSP
  shipped in S1.6 forbids inline scripts and untrusted CDNs, and the
  Next.js app does not render user-controlled HTML.

If the platform ever serves user-generated content, switch to a
sliding-session `httpOnly Secure SameSite=Strict` cookie — that's a
two-day refactor scoped to ADR 0002.

## Consequences

### Positive
* Closes blocker R1 / SEC-01..03.
* Audit log finally has a trustworthy `actor_email` (today it's a
  client-supplied string).
* `Depends(require_role("admin"))` makes the policy checkable by
  reading the route signature — no scattered `if user.role != ...`.

### Negative
* +2 dependencies (`bcrypt`, `pyjwt`).
* `JWT_SECRET` becomes a critical secret to rotate / store. Documented
  in OPERATIONS.md (S4.10).
* Multi-instance deployments need the same `JWT_SECRET` everywhere;
  otherwise tokens become invalid across replicas. Addressed by
  Kubernetes `Secret` + env-var injection in Sprint 4.

### Open questions deferred to ADR 0002
* OAuth/OIDC provider integration (Google Workspace, Entra ID,
  GitHub) for enterprise SSO.
* Refresh-token rotation + revocation list (today refresh tokens are
  stateless and cannot be invalidated before expiry).
* Per-org role binding (`tenant_id` in the JWT claims).
* Service-account tokens (long-lived) for CI integrations.

## Related work
* SEC-01, SEC-02, SEC-03 in `docs/PRODUCTION_READINESS_REVIEW.md` §B.5
* Sprint 1 tasks S1.1..S1.3, S1.7
* Frontend login page (S1-FE)
