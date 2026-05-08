# Production-Readiness Review — CVE Management Platform

> **Data review:** 2026-05-08
> **Branch:** main
> **Reviewer:** orchestrazione multi-agent (Explore × 5 + sintesi opus)
> **Stato:** SOLO ANALISI — nessuna modifica al codice in questo round

---

## A. Executive Summary

### Valutazione complessiva: **PARTIALLY READY → "Almost ready *for an internal/portfolio deployment*"; NOT READY *for un deploy multi-tenant esposto a Internet senza un reverse-proxy autenticante davanti*.**

### Sintesi a una frase
La piattaforma ha una **dorsale tecnica solida** (FastAPI async + asyncpg + circuit breaker + OpsecAwareClient + SSRF guard + audit log + 237 test backend), ma manca **completamente un livello di autenticazione applicativa** e ha **gap di copertura sui router e sul frontend** che bloccano un rilascio production.

### Distanza dalla produzione
| Asse | Stato | Effort residuo |
|---|---|---|
| Backend domain logic | 80% pronto | 2-3 giorni di rifinitura |
| Backend security (auth) | 10% pronto | **5-7 giorni — blocking** |
| Database schema | 90% pronto | 1 giorno (indici + retention) |
| Frontend UI shell | 80% pronto | 2-3 giorni (4 pagine mancanti) |
| Frontend test/qualità | 30% pronto | 4-6 giorni (zero test, error boundary, a11y) |
| Test backend | 60% pronto | 4-5 giorni (circuit breaker FSM, router integration) |
| DevOps/CI | 50% pronto | 3-4 giorni (image build, scan, k8s) |
| Observability | 35% pronto | 2-3 giorni (Prometheus, Sentry, OTEL opzionale) |
| Documentazione operativa | 45% pronto | 1-2 giorni (RUNBOOK, OPERATIONS, backup) |

**Effort totale stimato verso production-ready: ~22-30 giorni-uomo** (con un solo dev) oppure **~10-12 giorni** parallelizzando attraverso gli agent.

---

### Top blocker critici (non rilasciabile finché non chiusi)

| # | Blocker | Severità | File | Fix owner |
|---|---|---|---|---|
| **B1** | Nessuna autenticazione su endpoint state-changing — chiunque può `PATCH /api/system/config` e sovrascrivere le API key dei provider, oppure modificare lo stato delle finding e creare risk-acceptance | **CRITICAL** | `app/api/routers/system.py:177-193`, `risk_acceptance.py:39-167` | security-architect + python-backend-engineer |
| **B2** | Codice morto del backend Node.js ancora nel repo (`backend/`) — confonde ops, mantiene Dockerfile non-multistage, espone superficie di attacco non monitorata | **HIGH** | `backend/Dockerfile`, `backend/src/`, `backend/package.json` | devops-platform-engineer |
| **B3** | Frontend: 4 pagine core mancanti (`/findings`, `/webhooks`, `/reports`, `/inventory`) e 3 dashboard (Remediation/Exposure/Executive) non caricano dati pur avendo i componenti | **HIGH** | `frontend/src/app/dashboards/{remediation,exposure,executive}/page.jsx` (no fetch), nessuna `app/findings/`, `app/webhooks/`, `app/reports/` | frontend-architect + fullstack-dev-agent |
| **B4** | Zero test sui router (47 endpoint, 0 integration test) e zero test sul `CircuitBreaker` FSM | **HIGH** | `backend-py/tests/integration/` (manca cartella `test_routers/`), `app/ingestion/circuit_breaker.py` (0 test) | qa-testing-agent |
| **B5** | Default deboli in compose (`cve_password`, `cve_redis`) + `AUTO_MIGRATE=true` su shared DB → race su rolling update multi-instance | **HIGH** | `docker-compose.yml:8-11,61-65`, `backend-py/Dockerfile:73-77` | devops-platform-engineer |
| **B6** | Nessun rate-limit applicativo sugli endpoint pubblici (DoS / brute-force triviale) | **HIGH** | tutti i router | security-architect |
| **B7** | Nessun error-tracking (Sentry/Glitchtip) né per backend né per frontend; gli errori 5xx restano nei log container | **HIGH** | `app/main.py`, `frontend/src/app/layout.jsx` | devops-platform-engineer |
| **B8** | Soft-delete assente: `DELETE /api/products/{id}` cascata distrugge findings + history + audit collegati senza traccia | **MEDIUM-HIGH** | `app/api/routers/products.py:178`, schema migrations | database-architect |

> **Nota su un finding del primo agent corretto in fase di verifica:** un agent ha segnalato `.env` committato con `VULNCHECK_API_KEY` reale. Verifica diretta: `.env` è in `.gitignore` riga 2 e `git ls-files | grep '^\.env$'` non lo mostra → **falso positivo, no leak su git**. Tuttavia il file esiste localmente; raccomandato comunque ruotare la key prima di un eventuale `git add -A` distratto.

### Maturity rating per area
| Area | Rating |
|---|---|
| Architecture | Almost ready |
| Backend domain | Almost ready |
| Backend security/auth | **Not ready** |
| Database | Almost ready |
| Frontend | Partially ready |
| Test | Partially ready |
| Deploy / CI | Partially ready |
| Observability | Partially ready |
| Documentation | Partially ready |
| **Globale** | **Partially ready** |

---

## B. Findings dettagliati

> Severity scale: **Critical** = blocca rilascio; **High** = va chiuso pre-prod; **Medium** = chiudere entro Sprint 4; **Low** = nice-to-have.

### B.1 — Architettura

| ID | Sev | Area | Problema | File | Evidenza | Fix | Effort | Owner |
|---|---|---|---|---|---|---|---|---|
| ARC-01 | High | architecture | Doppio backend nel repo (Node legacy `backend/` + Python attivo `backend-py/`). `backend/Dockerfile` ancora buildable. Confusione operativa, sup. di attacco morta. | `backend/`, `backend/Dockerfile`, `docker-compose.yml` (non lo referenzia ma è ancora presente) | `git ls-files backend/` mostra ~20 file Node ancora tracciati; CI non lo testa | Cancellare `backend/` (recuperabile da git history se serve), aggiornare README per rimuovere riferimenti | Low | devops-platform-engineer |
| ARC-02 | Medium | architecture | Logiche di "Resolution layer" e "Query layer" si sovrappongono parzialmente: `cpe_normalizer.py` (resolution) chiama VulnCheck (query). Boundary non netti. | `app/resolution/cpe_normalizer.py`, `app/query/` | Imports cross-layer | Definire ADR per chi può chiamare cosa; spostare la chiamata a un service in `app/services/` | Medium | system-architect |
| ARC-03 | Medium | architecture | `app/services/` esiste ma è quasi vuota; molta logica di servizio è dentro i router. | `app/api/routers/products.py` (160 righe con SQL inline), `findings.py` | Router fanno I/O DB diretto invece di delegare a un service | Estrarre repository/service pattern; router solo orchestratori | Medium | backend-architect |

### B.2 — Backend

#### Configurazione & secrets
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-CFG-01 | High | `app/core/config.py:14,17` | Default contengono password (`cve_password`, `cve_redis`). Se env var non settata, usa default debole senza errori. | Rimuovere default; `Field(...)` (required); `model_validator` startup-time |
| BE-CFG-02 | Medium | `app/core/config.py:45` | `environment: str = "development"` come default → silenzioso fallback a dev se non settato | Default a `"production"`, opt-in a dev |
| BE-CFG-03 | Medium | `app/core/config.py` | Nessuna validazione presenza chiave API critica (vulncheck/nvd) all'avvio | `@model_validator(mode="after")` con warning strutturato |

#### Async correctness
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-ASY-01 | High | `app/main.py:53` | `await asyncio.to_thread(run_migrations,…)` blocca lifespan senza timeout — startup hang se DB lento | `await asyncio.wait_for(asyncio.to_thread(...), timeout=60)` |
| BE-ASY-02 | High | `app/main.py:145` | `scheduler.shutdown(wait=False)` interrompe job in volo | `wait=True` + `wait_for(timeout=30)` |
| BE-ASY-03 | Medium | `app/main.py:150-153` | Background task cancellati ma non verificato che rispettino il `CancelledError` | `asyncio.wait_for(asyncio.gather(...), timeout=5)` |
| BE-ASY-04 | Medium | router lazy-enrichment | `asyncio.create_task()` senza registrazione in `app.state.background_tasks` → leak a shutdown | Helper `register_bg_task(coro)` da usare ovunque |

#### API design / validation
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-API-01 | High | `app/api/routers/cves.py:48-120` | Endpoint `/export` senza rate limit, `LIMIT 10000` hard-coded — DoS leggero | slowapi `@limiter.limit("3/minute")`, paginazione cursor |
| BE-API-02 | Medium | `app/api/routers/findings.py:75-82` | Param `status` accettato senza validazione (silently filtra) | `status: Literal["open","in_review","planned",…] \| None` |
| BE-API-03 | Medium | `app/api/routers/cves.py:206-207` | `min_priority` non clamp 0–100 | `min(100, max(0, v))` |
| BE-API-04 | Low | `app/api/routers/risk_acceptance.py:65` | Validation regex per "approve|reject" | Usare `Literal` |
| BE-API-05 | Medium | `app/api/routers/cves.py:119` | `Content-Disposition` filename non RFC 5987 encoded | `urllib.parse.quote()` |

#### Database access (vedi anche sezione B.3)
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-DB-01 | High | `app/api/routers/cves.py:95` | Export `LIMIT 10000` non paginato — memoria | Cursor-based + chunked stream |
| BE-DB-02 | Medium | `app/core/db.py:11-18` | Pool senza `acquire_timeout` — deadlock se 10 conn leakate | `acquire_timeout=5` |
| BE-DB-03 | Medium | `app/api/routers/cves.py:256` | `SELECT DISTINCT … ORDER BY` su espressione computata — sort prima di distinct | Riscrittura con CTE |
| BE-DB-04 | Low | `app/api/routers/cves.py:226` | f-string SQL con `field` (enum-safe) e `days` (int). Pattern fragile | Commento esplicito + helper SQL builder |

#### Ingestion / workers
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-ING-01 | High | `app/ingestion/ingest_worker.py:147-150` | Su `CircuitOpenError` ritorna 0 CVE invece di restare su dato stale | Fallback a NVD o checkpoint precedente |
| BE-ING-02 | High | `app/workers/scheduler.py` | APScheduler senza leader-election → multi-instance esegue delta_sync N volte | Distributed lock via Redis (SET NX EX) o riga in `sync_state` con FOR UPDATE |
| BE-ING-03 | Medium | `app/ingestion/ingest_worker.py:307` | Errori troncati a 500 char | Colonna TEXT senza limit, oppure JSON array |
| BE-ING-04 | Medium | `app/ingestion/rate_governor.py:43-47` | Refill float drift su giorni | `int(...)` per troncare frazioni |
| BE-ING-05 | Low | `app/main.py:121-134` | Scheduler.start() non verifica successo | `assert scheduler.get_jobs()` post-start |

#### Error handling
| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| BE-ERR-01 | Medium | `app/api/middleware/error_handler.py:52-60` | Risposta generica OK ma `logger.exception()` mette stack a structlog (visibile a chi accede ai log container) | Filtrare path interni nei traceback in prod, full trace solo a DEBUG |
| BE-ERR-02 | Medium | `app/core/http.py:169-189` | OpSec violation logga via structlog ma NON scrive in `audit_log` — non queryable | Background task `audit.record(action="opsec.egress_blocked", ...)` |
| BE-ERR-03 | Low | router intel | `Depends()` senza guard se `app.state.db_pool` mancante | Helper `get_pool(request)` con `raise HTTPException(500)` esplicito |

### B.3 — Database

| ID | Sev | File | Problema | Fix |
|---|---|---|---|---|
| DB-01 | **High** | `0002_sync_infra.py` (manca indice) | `sync_jobs.target_id` non indicizzato per filtri TEXT (presente solo nel partial unique) — query "products list" fa LEFT JOIN su `target_id = p.id::text` → seq scan a 100k+ righe | `CREATE INDEX idx_sync_jobs_target ON sync_jobs(target_id)` (nuova migration 0009) |
| DB-02 | High | `app/api/routers/findings.py:30-38` | Update status finding + insert in `findings_history` non in transaction — possibile mismatch | Wrap in `async with conn.transaction():` |
| DB-03 | Medium | `app/api/routers/products.py:178` | `DELETE FROM products` cascata su findings/history/risk_acceptances → **perdita audit trail** | Soft-delete (`is_deleted, deleted_at`) o `audit.record_in_tx()` prima di DELETE |
| DB-04 | Medium | scheduler retention | `sync_jobs` con `status IN ('completed','dead')` non vengono cancellati → bloat tabella | Daily cleanup job: `DELETE … WHERE completed_at < NOW() - INTERVAL '90 days'` |
| DB-05 | Medium | scheduler retention | `webhook_deliveries` storiche non cancellate | Daily cleanup |
| DB-06 | Medium | `0006_webhooks.py:41` | `webhook.secret` plaintext (mascherato in API ma non a riposo) | Encryption at rest (PGCrypto) o spostare in Vault |
| DB-07 | Medium | `app/resolution/cpe_normalizer.py:41-56` | JSONB extraction con ILIKE su `raw_payload->'configurations'` — full scan anche con GIN | Materializzare colonna `cpe_criteria_text` o functional GIN index (PG14+) |
| DB-08 | Low | `app/api/routers/findings.py` | Mancano composite index `(product_id, status)` per filtri | `CREATE INDEX idx_findings_product_status` |
| DB-09 | Low | scheduler retention | DELETE batch grandi senza chunking — long lock | `LIMIT 1000` + loop |

### B.4 — Frontend

| ID | Sev | File | Problema | Fix |
|---|---|---|---|---|
| FE-01 | **Critical** | (manca) `app/findings/` | Backend espone `/api/findings/*` (FSM, history, audit) ma nessuna pagina UI | Creare `app/findings/page.jsx` (lista con tab status) + `app/findings/[productId]/[cveId]/page.jsx` |
| FE-02 | **Critical** | (manca) `app/webhooks/` | API `/api/webhooks/*` esiste, nessuna UI di gestione | `app/webhooks/page.jsx` CRUD + delivery log |
| FE-03 | **Critical** | `app/dashboards/{remediation,exposure,executive}/page.jsx` | Pagine esistono ma NON chiamano gli endpoint dashboard relativi | Wire `getDashboardRemediation()`, `getDashboardExposure()`, `getDashboardExecutive()` dal `lib/api.js` |
| FE-04 | High | (manca) `app/reports/` | API SLA/MTTR/audit esistono ma nessuna pagina | `app/reports/sla/page.jsx`, `mttr`, `audit` |
| FE-05 | High | `components/Dashboard/SeverityChart.jsx`, `TimelineChart.jsx` | Charts non hanno `onClick` → analista non può filtrare cliccando | Aggiungere `onClick` su recharts segments + wire a `onFilter` |
| FE-06 | High | `components/CVE/CVETable.jsx` | Righe non keyboard-activable (no `tabIndex`, no `onKeyDown`) | Aggiungere `role="button" tabIndex={0} onKeyDown={Enter\|Space → onRowClick}` |
| FE-07 | High | `app/dashboards/*/page.jsx` | Nessun `<ErrorBoundary>` — un fetch failure crasha la pagina | Wrap dashboard sections in error boundary + toast |
| FE-08 | Medium | `lib/api.js` consumers | Error handling inconsistente: alcuni `try/catch` con setError, altri silent | `useApiError` hook + toast centralizzato |
| FE-09 | Medium | (manca) `components/UI/Form/` | Nessun componente form condiviso (TextField, Select) → markup duplicato | Estrarre primitive |
| FE-10 | Medium | (manca) `components/UI/LoadingSkeleton/` | Loading state non uniforme | Skeleton variants (table-row, card, chart) |
| FE-11 | Medium | (manca) `app/inventory/` | CSV import nascosto in `AddProductModal`; design doc chiede pagina dedicata con drop-zone visibile a empty | `app/inventory/page.jsx?type=software\|os` |
| FE-12 | Medium | `components/LiveSearch/LiveSearchPanel.jsx` | 5 mode tabs in un solo componente di 250+ righe; duplicazione con `CVETable` | Estrarre `<CVEDataTable>` condiviso, spostare Exploitability fuori |
| FE-13 | Low | `components/Products/ProductsGrid.jsx:5-10` | Emoji `⟳` per sync state | Lucide `Loader2`/`AlertCircle`/`Check` |
| FE-14 | Low | label/input | Alcuni `<input>` senza `id` matchato da `<label htmlFor>` | Audit + fix |
| FE-15 | Low | `lib/api.js` | Niente retry/backoff | Helper `withRetry()` |
| FE-16 | Low | `lib/api.js` | Niente request dedupe/cache | Valutare React Query / SWR (post-MVP) |
| FE-17 | Low | bundle | Bundle size sconosciuto | `next build && @next/bundle-analyzer` |

### B.5 — Security

| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| SEC-01 | **Critical** | `app/api/routers/system.py:177-193` | `PATCH /api/system/config` setta API key dei provider in Redis senza alcuna auth | `Depends(require_admin)` + audit |
| SEC-02 | **Critical** | `app/api/routers/risk_acceptance.py:39-167` | Risk acceptance create/decide accettano `requested_by`/`decided_by` come stringhe libere senza verifica identità | Reverse-proxy auth + `X-Actor-Email` validato vs claim |
| SEC-03 | **Critical** | tutti i router | Nessun middleware di auth applicativa: ogni `POST/PATCH/DELETE` è pubblico se l'app è esposta a Internet | OAuth2/OIDC reverse-proxy (Authelia/Keycloak/oauth2-proxy) o Depends JWT bearer |
| SEC-04 | High | nessun middleware | Nessun rate limit applicativo (slowapi assente) — DoS triviale | `slowapi` con limiti per-IP, più stretti su POST |
| SEC-05 | High | `app/main.py` | Header sicurezza mancanti: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | Middleware `SecurityHeaders` |
| SEC-06 | High | `app/api/routers/products.py`, `webhooks.py`, `system.py` | Operazioni mutanti **non** scrivono in `audit_log` | Aggiungere `audit.record_in_tx()` |
| SEC-07 | High | `0006_webhooks.py:41` + `services/webhooks.py` | Webhook secret plaintext a riposo (mascherato solo in API) | Encryption (PGCrypto with key management) |
| SEC-08 | Medium | `app/main.py:181-187` | CORS lista origini singola da env var; nessun guard contro `*` | Validator startup: rifiuta `*` se `environment=="production"` |
| SEC-09 | Medium | `docker-compose.yml:14` | `command: postgres -c ssl=off` — interno docker OK ma se DB esposto è plaintext | TLS in prod |
| SEC-10 | Medium | `docker-compose.yml:8-11,61-65` | Default `cve_password`, `cve_redis` deboli | Default vuoti + healthcheck startup che fallisce |
| SEC-11 | Low | `pyproject.toml` | `apscheduler>=3.10,<4.0` — 3.x EOL imminente | Pianificare upgrade a 4.x |
| SEC-12 | Low | tutto | No CSRF — ma è API stateless senza cookie quindi accettabile **se** auth via Bearer | Documentare scelta in OPERATIONS.md |
| SEC-13 | Medium | `app/main.py` | Nessun limite size body (default uvicorn) | `MaxBodySizeMiddleware` (1 MB su POST products, 100 KB altrove) |

### B.6 — Test

| ID | Sev | Area | Problema | Fix |
|---|---|---|---|---|
| TST-01 | **Critical** | router | 47 endpoint, **0 integration test** (solo `e2e_smoke.py`) | Almeno 1 happy + 1 error path per endpoint mutante |
| TST-02 | **Critical** | `app/ingestion/circuit_breaker.py` | FSM CLOSED→OPEN→HALF_OPEN: 0 test | Unit test con clock fittizio |
| TST-03 | High | `app/workers/{webhook_worker,daily_snapshot,risk_acceptance_expirer,scheduler}.py` | Worker async non testati | Test con `freezegun` + DB testcontainer |
| TST-04 | High | `frontend/` | **Zero test** (no jest/vitest/playwright) | Vitest per componenti chiave + Playwright smoke su 4 dashboard |
| TST-05 | Medium | CI | Integration & security test `continue-on-error: true` | Renderli blocking dopo aver passato 1 settimana stabili |
| TST-06 | Medium | CI | `pytest-cov` non configurato | Aggiungere `[tool.coverage]` e gate al 70% |
| TST-07 | Medium | tests contract | `test_iter_delta_chunks_large_range` dipende da `datetime.now()` reale | Patch con `freezegun` |
| TST-08 | Low | tests unit | `mock_redis()` troppo lasco (AsyncMock generico, no TTL) | Fixture redis tipizzata |
| TST-09 | Low | tests | Nessun `pytest.mark.timeout` → integration può pendere indefinitivamente | `pytest-timeout` plugin |

### B.7 — Deploy / DevOps

| ID | Sev | File:line | Problema | Fix |
|---|---|---|---|---|
| DEV-01 | High | repo root | Cartella `backend/` (Node) morta ancora presente | Rimuovere |
| DEV-02 | High | `.github/workflows/ci.yml` | No image build/push, no SBOM, no Trivy/grype, no `pip-audit`, no `npm audit`, no gitleaks | Pipeline completa: build → scan → push → smoke |
| DEV-03 | High | `docker-compose.yml` | Niente `mem_limit` / `cpus` su nessun servizio | Limits espliciti |
| DEV-04 | High | `backend-py/Dockerfile:73-77` + `app/main.py:52-53` | `AUTO_MIGRATE=true` su rolling update multi-istanza → race / lock | Init container / Job pre-deploy + `AUTO_MIGRATE=false` in prod |
| DEV-05 | Medium | `backend-py/Dockerfile:42` | Niente `uv.lock` committato — build non riproducibile | `uv lock` + `uv sync --frozen` |
| DEV-06 | Medium | `backend-py/Dockerfile:27` | `COPY --from=ghcr.io/astral-sh/uv:latest` non pinned | Pin a versione (es. `:0.4.18`) |
| DEV-07 | Medium | `backend-py/Dockerfile:73-77` | `--workers 1` hardcoded; nessuna gunicorn fallback | Documentare scaling orizzontale (replicas) e mantenere 1 worker per replica |
| DEV-08 | Medium | `frontend/next.config.js:8` | API URL build-time (`NEXT_PUBLIC_API_URL`) → image non portabile tra env | Runtime config endpoint o middleware rewrite |
| DEV-09 | Medium | (manca) | Nessuno script backup/restore Postgres | `pg_dump` cron + retention 30d + test restore mensile |
| DEV-10 | Medium | (manca) | Nessun manifest k8s | Deployment + Service + ConfigMap/Secret + HPA |
| DEV-11 | Low | CI | `enable-cache: false` per uv (workaround) | Riabilitare dopo `uv.lock` |
| DEV-12 | Low | CI | Ruff e mypy `continue-on-error: true` | Renderli blocking gradualmente |

### B.8 — Observability / logging

| ID | Sev | Area | Problema | Fix |
|---|---|---|---|---|
| OBS-01 | High | (manca) | Nessun error tracker (Sentry) né backend né frontend | `sentry-sdk[fastapi]` + `@sentry/nextjs` |
| OBS-02 | High | (manca) | Nessun alert (no AlertManager, no PagerDuty, no Slack webhook su circuit OPEN/sync stuck) | Alert rules + integrazione Slack |
| OBS-03 | Medium | `app/core/metrics.py` | Metrics in-process JSON, non Prometheus → no scrape multi-instance | `prometheus_client` su `/metrics` |
| OBS-04 | Medium | (manca) | Niente OpenTelemetry per tracing distribuito (interno→VulnCheck→NVD→FIRST) | `opentelemetry-instrumentation-fastapi`, `httpx`, `asyncpg` |
| OBS-05 | Medium | router products/webhooks/system | Mutazioni non audited (vedi SEC-06) | `audit.record_in_tx()` |
| OBS-06 | Low | `app/core/db.py:15` | `command_timeout=60` ma niente log query lente | Logger middleware con `query_text` redatto |

### B.9 — Documentation

| ID | Sev | Doc | Problema | Fix |
|---|---|---|---|---|
| DOC-01 | High | (manca) `docs/OPERATIONS.md` | Niente checklist hardening prod, gestione segreti, scaling, multi-tenant | Scriverlo |
| DOC-02 | High | (manca) `docs/RUNBOOK.md` | Niente recovery: circuit breaker bloccato, sync job stuck, DB deadlock, restore | Scriverlo |
| DOC-03 | Medium | (manca) `docs/ARCHITECTURE.md` | C4 + ADR esistono solo in `~/.claude/plans/...` (privato), non nel repo | ADR-001..N nel repo |
| DOC-04 | Medium | (manca) `docs/DEPLOY_K8S.md` | Solo compose documentato | Manifest + guida |
| DOC-05 | Low | (manca) `CHANGELOG.md` | Niente versioning | Iniziare a 0.1.0 |
| DOC-06 | Low | `README.md` | Quick-start non avvisa che `VULNCHECK_API_KEY` è praticamente obbligatoria | ⚠️ box in evidenza |
| DOC-07 | Low | `CLAUDE.md` | Riferimento a `~/.claude/plans/lovely-splashing-zephyr.md` (path utente) | Spostare contenuto rilevante in `docs/ARCHITECTURE.md` |

---

## C. Checklist production-ready

> Legenda: ✅ ok · ⚠️ parziale · ❌ mancante

### Backend
- ⚠️ API robuste (validation Pydantic v2 ok; alcuni `Literal` mancanti — BE-API-02/03)
- ⚠️ Validazione input (parametrizzata SQL ok; SSRF guard ok; nessun body-size limit — SEC-13)
- ✅ Status code coerenti (FastAPI default + `HTTPException` espliciti)
- ⚠️ Gestione errori (handler generico; manca audit egress — BE-ERR-02)
- ✅ Logging strutturato (structlog + masking)
- ⚠️ Configurazione per ambiente (no profili dev/staging/prod — BE-CFG-02)
- ⚠️ Gestione dati sensibili (audit mask ok; webhook secret plaintext a riposo — DB-06/SEC-07)

### Frontend
- ⚠️ UI coerente (badge unificati; form primitive ancora inline — FE-09)
- ✅ Responsive design (desktop/tablet/mobile testati)
- ⚠️ Loading state (alcune pagine mancano — FE-10)
- ⚠️ Empty state (presente in dashboard nuove; assente altrove)
- ⚠️ Error state (no error boundaries — FE-07)
- ⚠️ Validazione client (basic; mancano URL/email/CPE format — FE-08)
- ⚠️ Accessibilità (focus ring + modal trap ok; CVETable rows non keyboard — FE-06)
- ✅ Messaggi utente

### Security
- ✅ Secrets non committati (`.env` in `.gitignore` verificato)
- ⚠️ CORS configurato (singola origine ok; no guard `*` — SEC-08)
- ❌ Headers sicurezza (SEC-05)
- ✅ Validazione SQL parametrizzata
- ⚠️ Sanitizzazione output (mask ok in audit; no in error handler — BE-ERR-01)
- ⚠️ Dipendenze controllate (no `pip-audit`/`npm audit` in CI — DEV-02)
- ❌ Rate limiting (SEC-04)
- ❌ Autenticazione/autorizzazione (SEC-01/02/03)
- ✅ SSRF (eccellente — `app/core/ssrf.py`)

### Testing
- ✅ Unit test (146)
- ✅ Integration test (27, con testcontainers)
- ✅ Contract test (44, respx)
- ❌ API test (0 sui router — TST-01)
- ❌ Frontend component test (0 — TST-04)
- ❌ E2E (0)
- ⚠️ Regression test (snapshot data assenti)
- ❌ Accessibility test (0 — axe-core mancante)
- ❌ Performance test (0 — k6/locust)
- ⚠️ Security test (20, solo OpSec/SSRF; manca authz)

### Deploy
- ✅ Ambienti separati (override.yml dev)
- ⚠️ Variabili d'ambiente (default deboli — SEC-10)
- ⚠️ Container readiness (single-stage Node legacy ancora — DEV-01)
- ⚠️ CI/CD (test ok; build/push/scan mancanti — DEV-02)
- ⚠️ Migration strategy (`AUTO_MIGRATE=true` rischioso multi-instance — DEV-04)
- ❌ Rollback strategy
- ✅ Health check (`/api/health`, `/api/health/ready`)

### Observability
- ✅ Log strutturati (JSON stdout)
- ❌ Error tracking (OBS-01)
- ⚠️ Metriche (in-process — OBS-03)
- ❌ Alert (OBS-02)
- ⚠️ Audit log (router products/webhooks/system non scrivono — SEC-06)
- ❌ Dashboard operative (no Grafana)

### Documentation
- ✅ README ottimo
- ✅ Setup locale chiaro
- ⚠️ Configurazione ambienti (manca staging/prod — DOC-01)
- ✅ API doc (Swagger live)
- ⚠️ Architettura (in plan privato — DOC-03)
- ⚠️ Guida deploy (compose ok; k8s assente — DOC-04)
- ❌ Troubleshooting / runbook (DOC-02)

---

## D. Piano di remediation per sprint

> Sprint = 1 settimana di lavoro. Owner = agent primario; Reviewer = agent di controllo qualità incrociata.

### Sprint 1 — "Hardening critico" (blocking per qualunque prod, anche internal)
**Obiettivo:** chiudere tutti i Critical (auth, system config, risk acceptance, dead code Node).
**Definition of done:** nessun endpoint mutante è raggiungibile senza autenticazione; CI passa; smoke `pytest tests/integration/e2e_smoke.py` verde.

| # | Task | Area | Priority | Owner | Reviewer | Effort | Acceptance | Dipendenze |
|---|---|---|---|---|---|---|---|---|
| S1.1 | Disegnare strategia auth: reverse-proxy oauth2-proxy davanti + JWT bearer interno; documentare in `docs/OPERATIONS.md` | security | Critical | security-architect | system-architect | M | ADR scritto + diagramma | — |
| S1.2 | Implementare middleware FastAPI `verify_jwt` + `require_role(Admin/Analyst/Viewer)` | backend | Critical | python-backend-engineer | security-architect | M | Test integration: 401 senza token, 403 ruolo errato | S1.1 |
| S1.3 | Proteggere `/api/system/config` (Admin only) e tutti i router `POST/PATCH/DELETE` | backend | Critical | python-backend-engineer | code-reviewer | M | ogni endpoint mutante ha `Depends(require_role)` | S1.2 |
| S1.4 | Rimuovere `backend/` Node legacy + aggiornare README | devops | High | devops-platform-engineer | system-architect | L | repo non contiene più `backend/` | — |
| S1.5 | Aggiungere `slowapi` rate limit globale (100 r/m GET, 20 r/m POST per IP) + test | security | High | security-architect | python-backend-engineer | L | 429 dopo soglia, header `Retry-After` | — |
| S1.6 | Security headers middleware (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) | security | High | security-architect | code-reviewer | L | curl mostra header attesi | — |
| S1.7 | Audit log su `products.create/bulk_import/delete`, `webhooks.create/update/delete`, `system.update_config` | backend | High | python-backend-engineer | reporting-governance-agent | L | `audit_log` ha riga per ogni operazione | S1.3 |

**Rischi sprint 1:** la scelta auth (reverse-proxy vs in-app) impatta deploy → S1.1 va finalizzato il primo giorno.

---

### Sprint 2 — "Frontend completo + test backend"
**Obiettivo:** chiudere FE-01..04 (4 pagine mancanti), portare i dashboard a "data loaded", aggiungere test sui router e sul circuit breaker.
**DoD:** ogni route presente nella nav è funzionante + ha loading/empty/error state; coverage backend ≥ 70%; `pytest --cov` blocking in CI.

| # | Task | Area | Priority | Owner | Reviewer | Effort | Acceptance | Dipendenze |
|---|---|---|---|---|---|---|---|---|
| S2.1 | Creare `app/findings/page.jsx` (lista con tab status) + `app/findings/[productId]/[cveId]/page.jsx` (drawer dettaglio + history) | frontend | Critical | frontend-architect → fullstack-dev-agent | qa-testing-agent | H | navigazione Triage → Findings → dettaglio funziona |  S1 (auth) |
| S2.2 | Creare `app/webhooks/page.jsx` (CRUD + test endpoint + delivery log) | frontend | Critical | frontend-architect → fullstack-dev-agent | qa-testing-agent | M | webhook creato, test invio, delivery visibile | S1 |
| S2.3 | Creare `app/reports/sla` + `mttr` + `audit` | frontend | High | reporting-governance-agent → fullstack-dev-agent | frontend-architect | M | 3 pagine con grafici + export CSV/PDF | — |
| S2.4 | Creare `app/inventory/page.jsx?type=software\|os` con drop-zone CSV | frontend | High | frontend-architect → fullstack-dev-agent | data-engineer-inventory | M | upload CSV funziona, validazione client | — |
| S2.5 | Wire dashboards Remediation/Exposure/Executive: chiamate API + loading/empty/error | frontend | Critical | frontend-architect → fullstack-dev-agent | qa-testing-agent | M | dati visibili su tutti e 4 i dashboard | — |
| S2.6 | Charts cliccabili (`SeverityChart`, `TimelineChart`) → filter callback | frontend | High | frontend-architect | qa-testing-agent | L | click slice → filtro applicato | S2.5 |
| S2.7 | `<ErrorBoundary>` su ogni pagina dashboard | frontend | High | frontend-architect | code-reviewer | L | fetch failure non crasha la pagina | — |
| S2.8 | Test integration su tutti i router mutanti (47 endpoint) | test | Critical | qa-testing-agent | python-backend-engineer | H | 1 happy + 1 401/403 + 1 422 per ognuno | S1 |
| S2.9 | Test FSM `CircuitBreaker` (CLOSED↔OPEN↔HALF_OPEN) | test | Critical | qa-testing-agent | api-integration-engineer | M | 100% coverage del modulo | — |
| S2.10 | Configurare `pytest-cov` + soglia 70% blocking in CI | test | High | qa-testing-agent | devops-platform-engineer | L | CI fallisce se coverage < 70% | S2.8/S2.9 |
| S2.11 | Aggiungere indici DB mancanti (`idx_sync_jobs_target`, `idx_findings_product_status`) e cleanup jobs (`sync_jobs`, `webhook_deliveries`) | database | High | database-architect | python-backend-engineer | M | migration 0009 applicata; query plans `EXPLAIN` mostrano index scan | — |
| S2.12 | Wrap `findings.update_status` + `history insert` in transaction | database | High | database-architect | code-reviewer | L | crash mid-update non lascia mismatch | — |

---

### Sprint 3 — "Frontend test + UX/A11y + observability"
**Obiettivo:** test frontend, accessibilità completa, error tracker, metriche prometheus.
**DoD:** Vitest verde su componenti chiave; Playwright smoke su 4 dashboard; axe-core senza violation critiche; Sentry attivo backend+frontend; `/metrics` Prometheus esposto.

| # | Task | Area | Priority | Owner | Reviewer | Effort | Acceptance |
|---|---|---|---|---|---|---|---|
| S3.1 | Setup Vitest + RTL; test `CVETable`, `CVEDetailModal`, `AddProductModal`, `Badge`, `useUrlState` | test | High | qa-testing-agent | frontend-architect | M | 30+ test verdi |
| S3.2 | Setup Playwright; smoke E2E sui 4 dashboard + Findings + Webhooks | test | High | qa-testing-agent | frontend-architect | M | smoke nightly verde |
| S3.3 | A11y audit con axe-core in CI (`@axe-core/playwright`) | test | Medium | qa-testing-agent | frontend-architect | L | 0 violation severity=serious |
| S3.4 | Estrarre `<TextField>`, `<Select>`, `<Textarea>`, `<LoadingSkeleton>` in `components/UI/` | frontend | Medium | frontend-architect | code-reviewer | M | duplicazione markup -50% |
| S3.5 | Keyboard navigation su `CVETable` rows + label/htmlFor audit | frontend | High | frontend-architect | qa-testing-agent | L | tab + Enter naviga |
| S3.6 | Sentry SDK backend (sentry-sdk[fastapi]) + frontend (@sentry/nextjs) | observability | High | devops-platform-engineer | python-backend-engineer + frontend-architect | M | crash sintetico arriva su Sentry |
| S3.7 | Migrare `app/core/metrics.py` a `prometheus_client`; esporre `/metrics` | observability | Medium | devops-platform-engineer | python-backend-engineer | M | scrape Prometheus locale funziona |
| S3.8 | OpenTelemetry instrumentation FastAPI + httpx + asyncpg (opzionale) | observability | Medium | devops-platform-engineer | api-integration-engineer | M | trace visibile in Tempo/Jaeger |
| S3.9 | Loading/empty/error state uniformi su tutte le pagine | frontend | High | frontend-architect | qa-testing-agent | M | screenshot tre-state per ogni pagina |

---

### Sprint 4 — "Deploy readiness + docs operative + hardening finale"
**Obiettivo:** Kubernetes manifest, init container per migrazioni, backup, runbook, scan immagini, soft-delete.
**DoD:** rolling deploy in K8s funzionante; backup automatico; RUNBOOK e OPERATIONS scritti; CI image build + Trivy verde.

| # | Task | Area | Priority | Owner | Reviewer | Effort | Acceptance |
|---|---|---|---|---|---|---|---|
| S4.1 | Manifest k8s: Deployment backend (3 replicas), StatefulSet scheduler (1 replica via leader-election Redis), Service, ConfigMap, Secret, HPA | devops | High | devops-platform-engineer | system-architect | H | rolling update funziona, scheduler non duplica job |
| S4.2 | Init container che esegue `alembic upgrade head`; settare `AUTO_MIGRATE=false` in prod | devops | High | devops-platform-engineer | database-architect | M | migration eseguita una volta sola pre-deploy |
| S4.3 | Pipeline CI completa: build immagini + Trivy scan + push registry + smoke against image; gitleaks; pip-audit; npm audit | devops | High | devops-platform-engineer | security-architect | H | PR bloccata se CVE critical su immagine |
| S4.4 | `uv lock` + `uv sync --frozen` in Dockerfile; pin uv image | devops | Medium | devops-platform-engineer | python-backend-engineer | L | build riproducibile |
| S4.5 | Backup `pg_dump` cron + retention 30g + restore test mensile + documentare RTO/RPO | database | High | database-architect | devops-platform-engineer | M | dump verificato, restore eseguito su staging |
| S4.6 | Soft-delete su `products` (e cascade su findings → mark `deleted=true`) + audit log su delete | database | Medium | database-architect | reporting-governance-agent | M | DELETE non perde audit trail |
| S4.7 | Encryption-at-rest su `webhooks.secret` (PGCrypto + key in Vault o env) | security | Medium | security-architect | database-architect | M | secret in DB cifrato; API ritorna solo su create |
| S4.8 | Leader election scheduler (Redis SET NX EX 30s, refresh) | backend | High | python-backend-engineer | devops-platform-engineer | M | 3 replicas: solo 1 esegue delta_sync |
| S4.9 | Distributed limiter Redis (slowapi-redis o limits) | security | Medium | security-architect | python-backend-engineer | M | rate limit consistente tra replicas |
| S4.10 | Scrivere `docs/OPERATIONS.md`, `docs/RUNBOOK.md`, `docs/ARCHITECTURE.md`, `docs/DEPLOY_K8S.md`, `CHANGELOG.md` | docs | High | product-owner-secops | system-architect | M | 5 doc create, link da README |
| S4.11 | Alert rules (Prometheus AlertManager): circuit OPEN > 5m, sync stuck > 1h, 5xx rate > 1%, p95 latency > 1s | observability | High | devops-platform-engineer | reporting-governance-agent | M | alert testati con scenario sintetico |
| S4.12 | Test di carico (k6 o locust): baseline 100 RPS list cves, 10 RPS POST products | performance | Medium | qa-testing-agent | python-backend-engineer | M | report con p95/p99, no errori |

---

### Sprint 5 (post-MVP / nice-to-have)
- Multi-tenant (org_id su tutte le tabelle, RLS Postgres)
- React Query / SWR su frontend
- Dark/Light mode toggle
- Export PDF report executive
- TypeScript migration frontend
- APScheduler 4 upgrade

---

## E. Strategia di testing

### E.1 — Stack consigliato (compatibile con quello attuale)

| Layer | Tool | Stato attuale | Azione |
|---|---|---|---|
| Backend unit | `pytest` + `pytest-asyncio` | ✅ presente | mantenere |
| Backend HTTP mock | `respx` | ✅ presente | estendere a OpenCVE, webhook outbound |
| Backend integration | `testcontainers` (PG+Redis) | ✅ presente | aggiungere `pytest-timeout` |
| Backend coverage | `pytest-cov` | ❌ mancante | **aggiungere** + soglia 70% |
| Backend property-based | `hypothesis` | ❌ | nice-to-have su version_matcher |
| Frontend unit/component | `vitest` + `@testing-library/react` | ❌ | **aggiungere** |
| Frontend E2E | `Playwright` | ❌ | **aggiungere** smoke nightly |
| Frontend a11y | `@axe-core/playwright` | ❌ | aggiungere in CI |
| Performance | `k6` (script standalone) | ❌ | aggiungere baseline |
| Security | `bandit` (Python), `pip-audit`, `npm audit`, `gitleaks`, `Trivy` | ❌ | tutti in CI |

### E.2 — Test bloccanti pre-prod
1. Tutti gli endpoint mutanti hanno almeno: 200 happy + 401/403 senza/scarso ruolo + 422 input invalido
2. `CircuitBreaker` FSM con tutti i transition coperti
3. `version_matcher` (già OK — 33 test edge case)
4. Webhook outgoing HMAC sign + retry backoff + dead-letter
5. Sync queue concurrent claim (`FOR UPDATE SKIP LOCKED`)
6. Frontend smoke: login → upload CSV → vedere CVE → cambiare status finding → vedere audit
7. A11y: nessuna violation `serious` o `critical` su Triage/Findings/Webhooks
8. Carico: 100 RPS GET /api/cves senza errori, p95 < 500 ms

### E.3 — Test coverage target
- Backend overall: **≥ 70%** (gate CI)
- Critical paths (router auth, circuit breaker, version matcher, sync queue, webhook delivery): **≥ 85%**
- Frontend: **≥ 50%** componenti chiave + smoke E2E sui 4 dashboard

### E.4 — Owner per categoria
| Categoria | Owner | Reviewer |
|---|---|---|
| Backend unit | qa-testing-agent | python-backend-engineer |
| Backend integration | qa-testing-agent | backend-architect |
| Backend contract | qa-testing-agent | api-integration-engineer |
| Backend security | qa-testing-agent | security-architect |
| Frontend component | qa-testing-agent | frontend-architect |
| Frontend E2E | qa-testing-agent | frontend-architect |
| A11y | qa-testing-agent | frontend-architect |
| Performance | qa-testing-agent | python-backend-engineer + devops |
| Regression (snapshot) | qa-testing-agent | reporting-governance-agent |

### E.5 — Test manuali tollerabili (solo temporaneamente)
- Verifica visiva responsive su mobile reale (post-Playwright viewport)
- Restore disaster Postgres (manuale fino allo Sprint 4 task S4.5)

---

## F. Review grafica e frontend

### F.1 — Pagine critiche prima della produzione
| Route | Severità | Stato | Azione |
|---|---|---|---|
| `/dashboards/triage` | Critical | 70% | rifinire bulk action + due-date inline edit |
| `/dashboards/remediation` | Critical | componenti ok ma niente fetch | wire API, aggiungere ErrorBoundary |
| `/dashboards/exposure` | High | come sopra | wire API |
| `/dashboards/executive` | High | come sopra | wire API + snapshot |
| `/findings` | Critical | mancante | creare lista + drawer |
| `/webhooks` | Critical | mancante | creare CRUD + delivery |
| `/reports/{sla,mttr,audit}` | High | mancante | creare 3 pagine |
| `/inventory?type=…` | High | mancante (oggi è solo modale) | dedicata con drop-zone |
| `/cves/[id]/intel` | Medium | sepolto in LiveSearchPanel | estrarre |

### F.2 — Quick wins UX (≤ 1 giorno totale)
1. Click handler su `SeverityChart` e `TimelineChart` → filtro
2. Tasti Enter/Space su righe `CVETable`
3. Sostituire emoji `⟳` con Lucide `Loader2` su `ProductsGrid` sync badge
4. Aggiungere `<ErrorBoundary>` di pagina su 4 dashboard
5. `htmlFor`/`id` audit su tutti i form (script grep)
6. `Loading skeleton` per tabelle CVE / Findings / Webhooks

### F.3 — Componenti da rifattorizzare
- `app/page.jsx` (legacy, 301 righe) → spezzare e poi deprecare
- `LiveSearchPanel.jsx` → rimuovere tab Exploitability, estrarre `<CVEDataTable>` condivisa
- `AddProductModal.jsx` → estrarre `<Field>` in `UI/Form/TextField`
- `CVETable.jsx` → estrarre cells in sub-component, aggiungere keyboard

### F.4 — Coerenza grafica (audit dei 6 sistemi)
- ✅ **Badge family** — unificato in `UI/Badge.jsx` (severity, KEV, EPSS, PoC, priority, source, match, finding-status, SLA)
- ✅ **Focus ring** — `:focus-visible` globale indigo + offset
- ✅ **Modal** — `useEscape` + `useFocusTrap` standardizzati
- ⚠️ **Form** — manca primitive condivisa
- ⚠️ **Tabelle** — `CVETable` e `LiveSearchPanel` divergenti
- ⚠️ **Loading state** — non standardizzato

### F.5 — Mobile
- StatsBar `grid-cols-2` ok
- CVETable: 10 colonne → richiede scroll orizzontale; valutare hide priorità bassa (Source/Match) sotto toggle
- Sidebar: nascosta sotto lg → mostrare drawer su tap (non solo header link)

### F.6 — Modifiche post-MVP
- Migrazione TypeScript (rischio basso, valore alto sul medio termine)
- Theme system con tokens estratti
- Intl/i18n (l'app è oggi mista IT/EN)

---

## G. Roadmap finale verso produzione

### G.1 — Quick wins (≤ 2 giorni totali, nessun cambio architettura)
1. Cancellare `backend/` legacy (DEV-01)
2. Rimuovere default deboli `cve_password`/`cve_redis` (SEC-10)
3. `slowapi` rate limit globale (SEC-04)
4. Security headers middleware (SEC-05)
5. Audit log su mutazioni products/webhooks/system (SEC-06)
6. Click handler su charts + keyboard su `CVETable` (FE-05/06)
7. Indici DB mancanti (DB-01/08) + cleanup jobs (DB-04/05)

### G.2 — Obbligatori prima del deploy
- Auth applicativa (SEC-01/02/03)
- Pagine `/findings`, `/webhooks` create e funzionanti
- Dashboard Remediation/Exposure/Executive che caricano dati
- Test integration sui router mutanti
- Test FSM CircuitBreaker
- Sentry attivo backend + frontend
- Init container per migrazioni in K8s (o `AUTO_MIGRATE=false` + job)
- Backup Postgres automatico
- RUNBOOK + OPERATIONS docs

### G.3 — Consigliati prima del deploy
- Prometheus exposition + 4-5 alert rules
- Leader election scheduler
- Distributed rate-limiter
- Encryption webhook secret
- Test E2E Playwright smoke
- Test a11y axe-core

### G.4 — Rimandabili post-MVP
- OpenTelemetry tracing distribuito
- Multi-tenant
- React Query / SWR
- TypeScript migration
- APScheduler 4 upgrade
- Light mode

### G.5 — Rischi residui accettabili
- In-process metrics (single instance OK; passare a Prometheus prima di scalare)
- Dipendenza da reverse-proxy esterno per OAuth
- Webhook secret plaintext in DB *finché* DB è in network privato e accesso DB è tracciato

### G.6 — Rischi NON accettabili
- Endpoint mutanti senza auth
- Charts non filtranti pur sembrando interattivi (UX confusa per analista in pressione)
- Nessun rate limit su `/api/cves/export`
- `AUTO_MIGRATE=true` su rolling K8s deploy

---

## H. Agent orchestration plan

### H.1 — Lista agent presenti

| Agent | Ruolo | Perimetro | Aree coperte | Limiti / ambiguità |
|---|---|---|---|---|
| **api-integration-engineer** | Client HTTP resilienti per provider CVE | Token bucket, circuit breaker, retry/backoff, timeout, metriche di provider | Ingestion (VulnCheck, NVD, EPSS, KEV, CIRCL, OpenCVE) | Non scrive logica di business |
| **backend-architect** | Architettura backend (boundary, contratti, queue, pipeline) | API design, data model, service boundaries | API/router refactor, async pattern review | Sovrappone parzialmente con system-architect |
| **code-reviewer** | Review code Python async post-implementazione | Type ann., SQL injection, async/await, idempotency, OpSec | Reviewer trasversale | Non scrive codice |
| **cpe-version-matcher** | Match versione installata vs range CVE | CPE alias, version range, ambiguità | `app/resolution/version_matcher.py` | Molto specifico — rischio under-utilizzo |
| **data-engineer-inventory** | Pipeline CSV asset, normalizzazione, dedup | Schema CSV, data quality | Inventory ingest, normalizzazione vendor/product | Sovrappone con cpe-version-matcher su normalizzazione |
| **database-architect** | Schema, indici, migration, retention | DDL, query plan, history audit | Tutto `alembic/`, tuning DB | — |
| **devops-platform-engineer** | Container, compose, CI/CD, env, monitoring | Dockerfile, k8s, pipeline, alert | Deploy, hardening infrastrutturale | — |
| **frontend-architect** | UI/UX SecOps dashboard | Wireframe, design system, navigazione | Tutta `frontend/src/` | Non specifica testing FE |
| **fullstack-dev-agent** | Implementazione end-to-end greenfield | CSV upload, REST + form FE, auth | Implementazione iniziale features cross-stack | Rischio sovrapposizione con frontend-architect / python-backend-engineer |
| **product-owner-secops** | Requisiti, user story, roadmap | Backlog, acceptance criteria | Pianificazione, prioritizzazione | — |
| **python-backend-engineer** | Implementazione FastAPI/asyncpg/httpx | Project structure, async pattern, structlog, arq | Tutto `backend-py/app/` | — |
| **qa-testing-agent** | Test design e implementazione | Unit, integration, contract, E2E, security, regression | Tutto `tests/` | — |
| **reporting-governance-agent** | Reporting, governance, compliance | Dashboard exec, KEV board, SLA, MTTR, audit, lifecycle finding, risk acceptance | `app/api/routers/{dashboard,risk_acceptance,audit}.py`, snapshot | — |
| **security-architect** | Threat model, RBAC, hardening | Auth, RBAC, file upload, audit, headers | Tutto livello security cross-stack | — |
| **solution-architect** | HLD, blueprint nuovi sistemi | Component diagram, tech choice | Greenfield/grossi refactor | Sovrappone con system-architect |
| **system-architect** | HLD + ADR + interface contracts | C4 component, ADR, layer contract | ADR repo-level, decisioni cross-layer | Sovrappone con solution-architect e backend-architect |
| **vulnerability-intelligence** | Strategia enrichment CVE/KEV/EPSS | Sourcing, prioritization rules | Logic prioritizzazione, multi-source | — |

**Sovrapposizioni notate:** `solution-architect` ↔ `system-architect` ↔ `backend-architect`. Soluzione: usare `system-architect` per ADR repo-level, `backend-architect` per refactor backend, `solution-architect` solo per nuovi greenfield.

### H.2 — Mappatura task → agent (riassunto cross-sprint)

| Sprint | Task | Owner | Reviewer | Motivazione | Acceptance |
|---|---|---|---|---|---|
| 1 | S1.1 Auth strategy ADR | security-architect | system-architect | sec è proprietario del threat model | ADR + diagramma in `docs/` |
| 1 | S1.2 JWT middleware | python-backend-engineer | security-architect | implementazione async FastAPI | Test 401/403 verdi |
| 1 | S1.3 Auth su tutti i router | python-backend-engineer | code-reviewer | refactor di massa | Coverage authn 100% endpoint mutanti |
| 1 | S1.4 Rimozione backend Node | devops-platform-engineer | system-architect | infra cleanup | Repo non lo contiene più |
| 1 | S1.5 Rate limit | security-architect | python-backend-engineer | sec policy + impl | 429 verificato |
| 1 | S1.6 Security headers | security-architect | code-reviewer | sec policy | Header presenti |
| 1 | S1.7 Audit log su mutations | python-backend-engineer | reporting-governance-agent | reporting valida coerenza audit | Riga in `audit_log` per ogni mutation |
| 2 | S2.1 Findings UI | frontend-architect → fullstack-dev-agent | qa-testing-agent | architect disegna, fullstack implementa, qa valida | Smoke E2E verde |
| 2 | S2.2 Webhooks UI | frontend-architect → fullstack-dev-agent | qa-testing-agent | come sopra | Smoke E2E verde |
| 2 | S2.3 Reports pages | reporting-governance-agent → fullstack-dev-agent | frontend-architect | reporting domain expert | SLA/MTTR/audit calcolati |
| 2 | S2.4 Inventory page | frontend-architect → fullstack-dev-agent | data-engineer-inventory | data-engineer valida CSV pipeline | Upload CSV verde |
| 2 | S2.5 Wire dashboards | frontend-architect → fullstack-dev-agent | qa-testing-agent | implementazione + qa | Dati visibili |
| 2 | S2.6 Charts cliccabili | frontend-architect | qa-testing-agent | quick win UX | Filter applicato |
| 2 | S2.7 ErrorBoundary | frontend-architect | code-reviewer | resilienza UI | Crash sintetico contenuto |
| 2 | S2.8 Router integration tests | qa-testing-agent | python-backend-engineer | test pattern + endpoint signature | Coverage ≥ 80% router |
| 2 | S2.9 Circuit breaker FSM tests | qa-testing-agent | api-integration-engineer | api-int è proprietario del pattern | 100% modulo |
| 2 | S2.10 pytest-cov gate | qa-testing-agent | devops-platform-engineer | CI integration | CI fallisce sotto 70% |
| 2 | S2.11 Indici + cleanup | database-architect | python-backend-engineer | DDL + chiamata da app | Query plan EXPLAIN ok |
| 2 | S2.12 Transaction findings | database-architect | code-reviewer | atomicità DB | crash test verde |
| 3 | S3.1 Vitest + RTL | qa-testing-agent | frontend-architect | qa setup, fe valida API | 30+ test |
| 3 | S3.2 Playwright | qa-testing-agent | frontend-architect | come sopra | Smoke nightly |
| 3 | S3.3 axe-core | qa-testing-agent | frontend-architect | a11y | 0 serious/critical |
| 3 | S3.4 UI primitives | frontend-architect | code-reviewer | design system | Markup duplicato -50% |
| 3 | S3.5 Keyboard CVETable | frontend-architect | qa-testing-agent | a11y | Tab+Enter naviga |
| 3 | S3.6 Sentry | devops-platform-engineer | python-backend-engineer + frontend-architect | infra observability cross-stack | Crash sintetico in Sentry |
| 3 | S3.7 Prometheus | devops-platform-engineer | python-backend-engineer | metric exposition | Scrape locale |
| 3 | S3.8 OpenTelemetry | devops-platform-engineer | api-integration-engineer | tracing cross-provider | Trace in Tempo |
| 3 | S3.9 Loading/empty/error | frontend-architect | qa-testing-agent | UX standard | screenshot tre-state |
| 4 | S4.1 K8s manifest | devops-platform-engineer | system-architect | infra design | Rolling update verde |
| 4 | S4.2 Init container migrations | devops-platform-engineer | database-architect | safe migration pattern | una sola esecuzione |
| 4 | S4.3 CI image build + scan | devops-platform-engineer | security-architect | supply chain | Trivy gate verde |
| 4 | S4.4 uv lock + pin | devops-platform-engineer | python-backend-engineer | reproducible build | hash uguali |
| 4 | S4.5 Backup Postgres | database-architect | devops-platform-engineer | DB owner + infra cron | restore mensile verde |
| 4 | S4.6 Soft-delete products | database-architect | reporting-governance-agent | audit preservato | DELETE non perde history |
| 4 | S4.7 Webhook secret encryption | security-architect | database-architect | sec at rest | Lettura DB diretta cifrata |
| 4 | S4.8 Leader election scheduler | python-backend-engineer | devops-platform-engineer | impl + infra | 3 replicas, 1 esecutore |
| 4 | S4.9 Distributed rate-limit | security-architect | python-backend-engineer | rate limit policy multi-instance | rate consistente |
| 4 | S4.10 Docs operative | product-owner-secops | system-architect | doc planning + review tecnica | 5 doc + link in README |
| 4 | S4.11 Alert rules | devops-platform-engineer | reporting-governance-agent | alerting + governance | alert testati |
| 4 | S4.12 Test di carico | qa-testing-agent | python-backend-engineer + devops | perf | report con p95/p99 |

### H.3 — Gap analysis

**Responsabilità non coperte / poco coperte:**
1. **Frontend test engineering** — `qa-testing-agent` esiste ma è generalista. Considerare uno specializzato.
2. **Site Reliability / On-call runbook** — `devops-platform-engineer` è orientato a build/deploy, non a "incident response". Manca RUNBOOK ownership chiara.
3. **Performance engineer** — nessuno specializzato; oggi `qa-testing-agent` + `python-backend-engineer` lo coprono ad-hoc.
4. **Auth specialist / IAM** — `security-architect` lo copre ma è ad ampio raggio. Per S1 può bastare; per multi-tenant futuro servirà più focus.
5. **UX writer / i18n** — l'app è IT/EN mista, nessun owner.
6. **Compliance / privacy** — non c'è un agent dedicato GDPR/audit retention.

**Sovrapposizioni che vanno disambiguate:**
- `solution-architect` vs `system-architect` vs `backend-architect` → regola: system-arch per ADR cross-cutting, backend-arch per refactor backend layer, solution-arch solo per nuovi sistemi
- `frontend-architect` vs `fullstack-dev-agent` → fe-arch progetta, fullstack implementa
- `data-engineer-inventory` vs `cpe-version-matcher` → data-eng per pipeline CSV, cpe-vm per logica matching/normalizzazione

### H.4 — Nuovi agent proposti

#### Nuovo agent #1 — **frontend-test-engineer**
- **Nome:** frontend-test-engineer
- **Missione:** progettare e implementare la strategia di testing per il frontend Next.js (component, integration, E2E, accessibility)
- **Responsabilità:** setup Vitest+RTL; setup Playwright; test componenti interattivi (modali, table, forms); E2E happy-path delle 8 pagine principali; a11y con axe-core; screenshot regression
- **Non deve occuparsi di:** test backend (qa-testing-agent), design UI (frontend-architect)
- **Input richiesti:** componenti FE finalizzati; lista pagine; lista user-flow critici dal product-owner-secops
- **Output attesi:** suite Vitest verde, suite Playwright nightly, axe-core in CI, badge coverage frontend nel README
- **Quando usarlo:** Sprint 3 (S3.1, S3.2, S3.3) e per ogni nuova pagina FE
- **Agent con cui collabora:** frontend-architect, qa-testing-agent, devops-platform-engineer (CI), product-owner-secops (priorità flow)
- **Prompt operativo:**
  > You are a frontend testing specialist for a Next.js 14 + React 18 + Tailwind dashboard. Your job is to design and implement Vitest + React Testing Library component tests for interactive components (modals with focus traps, tables, filter bars, forms) and Playwright E2E tests covering at least these flows: CSV upload → product list → CVE detail → finding status change → audit log; webhook create → test → delivery; risk acceptance create → approve → expire. Always include axe-core a11y assertions. Output Vitest config, Playwright config, package.json scripts, and CI workflow snippets compatible with `.github/workflows/ci.yml`. Aim for ≥ 50% statement coverage on `frontend/src/components/` and zero critical/serious axe violations on every Playwright page visit. Do not modify production app code; only tests, configs, and CI YAML.

#### Nuovo agent #2 — **sre-runbook-agent**
- **Nome:** sre-runbook-agent
- **Missione:** scrivere e mantenere RUNBOOK e procedure di incident response
- **Responsabilità:** procedure recovery (circuit breaker stuck, sync job orfani, deadlock DB, restore PG); alert rules con runbook URL; chaos drill scripts; documentazione on-call
- **Non deve occuparsi di:** scrivere codice applicativo, architettura
- **Input richiesti:** elenco failure mode da `system-architect` + `python-backend-engineer`; alert da `devops-platform-engineer`
- **Output attesi:** `docs/RUNBOOK.md`, `docs/INCIDENT_RESPONSE.md`, alert→runbook mapping, post-mortem template
- **Quando usarlo:** Sprint 4 (S4.10, S4.11) e dopo ogni incident reale
- **Agent con cui collabora:** devops-platform-engineer, security-architect, database-architect, reporting-governance-agent
- **Prompt operativo:**
  > You are a Site Reliability Engineer specialized in observability runbooks for a FastAPI + Postgres + Redis CVE management platform with APScheduler. Produce a `docs/RUNBOOK.md` covering at minimum: (1) circuit breaker stuck OPEN > 5 min, (2) sync job stuck in 'running' > 30 min, (3) Postgres long-running query > 60s, (4) Redis OOM eviction, (5) APScheduler job not firing, (6) `/api/health/ready` failing, (7) restore from `pg_dump`. Each entry must include: detection (alert query / log signature), immediate mitigation, root-cause investigation steps, escalation path, post-incident actions. Cross-link Prometheus alert rules in `monitoring/alerts.yml` to runbook anchors. Do not modify application code; only documentation, alert YAML, and chaos scripts.

#### Nuovo agent #3 — **performance-engineer** *(opzionale, solo se compaiono problemi di scala)*
- **Nome:** performance-engineer
- **Missione:** definire baseline performance, eseguire load test, individuare colli di bottiglia
- **Responsabilità:** k6/locust scripts, profilazione asyncpg/httpx, EXPLAIN ANALYZE su query critiche, raccomandazioni indexing/cache
- **Non deve occuparsi di:** funzionalità nuove
- **Input richiesti:** SLO target (p95 < 500ms, ecc.), traffic profile dal product-owner
- **Output attesi:** report di carico, regression test perf in CI nightly
- **Quando usarlo:** Sprint 4 (S4.12) e prima di ogni release maggiore
- **Agent con cui collabora:** qa-testing-agent, python-backend-engineer, database-architect, devops-platform-engineer
- **Prompt operativo:**
  > You are a performance engineer for a FastAPI async backend. Build a k6 load profile that hits these endpoints with realistic mixes: GET /api/cves (60%), GET /api/findings (20%), GET /api/dashboard (10%), POST /api/products (5%), PATCH /api/findings/{id} (5%). Targets: p95 < 500ms at 100 RPS. Produce: k6 JS scripts under `tests/perf/`, GitHub Actions nightly workflow, and a markdown report template. Use `EXPLAIN (ANALYZE, BUFFERS)` to attach query plans for any p95 > target. Recommend indices, cache, or query rewrites. Do not modify production code; only `tests/perf/`, CI YAML, and recommendations in `docs/PERFORMANCE.md`.

> **Decisione:** i primi due agent (`frontend-test-engineer`, `sre-runbook-agent`) sono **fortemente consigliati**. Il `performance-engineer` è da creare solo se Sprint 4 task S4.12 mostra problemi.

### H.5 — Sequenza esecuzione & sincronizzazione

```
Sprint 1 (auth + cleanup) ────► Sprint 2 (FE pages + tests) ────► Sprint 3 (a11y + obs) ────► Sprint 4 (deploy + docs)

Punti di sincronizzazione:
- Fine S1: review cross di security-architect + system-architect → "auth strategy approvata"
- Fine S2: review cross di product-owner-secops + qa-testing-agent → "feature complete + coverage gate"
- Fine S3: review cross di devops-platform-engineer + reporting-governance-agent → "observability operativa"
- Fine S4 (release gate): review cross-agent finale (security-architect, system-architect, qa-testing-agent, devops-platform-engineer, reporting-governance-agent) → "production sign-off"

Parallelismo nel singolo sprint:
- S1.4 (cleanup backend Node) parallelo a S1.1/1.2/1.3 (auth)
- S1.5 e S1.6 (rate limit + headers) parallel a S1.3 (auth router)
- S2.1..S2.5 (FE pages) parallel a S2.8..S2.12 (test backend + DB)
- S3.1/S3.2 (FE test) parallel a S3.6/S3.7/S3.8 (observability)
- S4.1..S4.4 (k8s/CI) parallel a S4.5..S4.7 (DB/security)

Serializzazioni obbligate:
- S1.2 prima di S1.3, S1.7
- S2.5 prima di S2.6
- S2.8/S2.9 prima di S2.10
- S4.2 prima di S4.1 deploy reale
```

### H.6 — Handoff process tra agent
1. Owner produce deliverable + apre PR con descrizione self-contained
2. Reviewer fa review puntuale (no rifare lavoro)
3. `code-reviewer` agent opzionale per check trasversali (no SQLi, no asset egress, async correttezza)
4. Acceptance test owner = qa-testing-agent
5. Merge → memoria aggiornata in `~/.claude/agent-memory/<agent>/` con il pattern stabilito

---

## I. Risk register

| ID | Descrizione | Area | Probabilità | Impatto | Severità | Mitigazione | Owner | Blocker prod |
|---|---|---|---|---|---|---|---|---|
| R1 | Endpoint mutanti senza auth → tampering API key, finding manipulation | security | High | High | **Critical** | Sprint 1: reverse-proxy auth + JWT middleware | security-architect | **Sì** |
| R2 | Multi-instance K8s con `AUTO_MIGRATE=true` causa race su Alembic | deploy | Medium | High | High | Init container + `AUTO_MIGRATE=false` | devops-platform-engineer | **Sì** |
| R3 | Scheduler senza leader-election → delta_sync N volte → rate limit ban da VulnCheck | ingestion | Medium | High | High | Redis lock leader-election | python-backend-engineer | **Sì** |
| R4 | Charts non cliccabili → analista in pressione perde tempo | UX | High | Medium | High | onClick recharts, sprint 2 | frontend-architect | No (downgrade UX) |
| R5 | DELETE products cascata distrugge audit trail | governance | Medium | High | High | Soft-delete + audit pre-delete | database-architect | No (compliance) |
| R6 | Webhook secret plaintext in DB; un dump DB esposto leakerebbe | security | Low | High | Medium-High | PGCrypto encryption sprint 4 | security-architect | No |
| R7 | Zero error tracking → bug silenti in prod | obs | High | Medium | High | Sentry sprint 3 | devops-platform-engineer | **Sì** |
| R8 | Frontend zero test → regressioni invisibili | qa | High | High | High | Vitest + Playwright sprint 3 | frontend-test-engineer (nuovo) | **Sì** |
| R9 | DoS triviale (no rate limit) | security | High | Medium | High | slowapi sprint 1 | security-architect | **Sì** |
| R10 | Backend Node legacy ancora nel repo → deploy errato | infra | Low | High | Medium | Cancellare sprint 1 | devops-platform-engineer | No |
| R11 | API key VulnCheck loaded da env: rotazione manuale | ops | Medium | Medium | Medium | Documentare in OPERATIONS.md | security-architect | No |
| R12 | DB bloat su `sync_jobs`/`webhook_deliveries` → query lente | DB | Medium | Medium | Medium | Cleanup job sprint 2 | database-architect | No |
| R13 | Default password compose deboli; dev runs su localhost senza override → DB esposto se port forwardato | security | Low | High | Medium | Default vuoti + healthcheck refuse | devops-platform-engineer | No |
| R14 | `/api/cves/export` LIMIT 10000 → DoS memoria | perf | Medium | Medium | Medium | Cursor pagination sprint 2 | python-backend-engineer | No |
| R15 | APScheduler 3.x EOL imminente | dependency | Low | Medium | Low | Plan upgrade post-MVP | devops-platform-engineer | No |
| R16 | Mancato OpenAPI export → integrazioni esterne difficili | docs | Low | Low | Low | Esportare openapi.json sprint 4 | devops-platform-engineer | No |
| R17 | Mancanza CSP/HSTS → XSS lateral | security | Medium | Medium | Medium | Headers sprint 1 | security-architect | No |
| R18 | OpsecAwareClient non usato ovunque (es. live.py, cpe_suggest.py) | security/opsec | Low | Medium | Medium | Wrapper factory unificato | security-architect | No |
| R19 | Validazione coercive frontend assente → richieste malformate al backend (rilevate poi) | UX | Medium | Low | Low | Form primitives + validator sprint 3 | frontend-architect | No |
| R20 | Nessun backup Postgres → data loss permanente | DR | Low | Critical | High | pg_dump cron sprint 4 | database-architect | **Sì** |

**Blocker prod totali (Sì): R1, R2, R3, R7, R8, R9, R20**

---

## J. Definition of production-ready

L'app è **production-ready** quando **tutti** i seguenti criteri minimi sono verdi:

### Sicurezza
- [ ] Ogni endpoint mutante richiede autenticazione e autorizzazione (JWT + role check)
- [ ] Rate limit attivo (per-IP per-endpoint) e testato
- [ ] Header sicurezza (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) presenti
- [ ] CORS limitato a una lista esplicita (no `*` in `production`)
- [ ] `pip-audit` e `npm audit` in CI senza CVE Critical
- [ ] Trivy scan immagini in CI senza CVE Critical
- [ ] Secret webhook cifrato a riposo
- [ ] Default deboli rimossi
- [ ] `.env` non in git (verificato)

### Stabilità
- [ ] Circuit breaker FSM testato (100% modulo)
- [ ] Scheduler con leader-election in K8s multi-replica
- [ ] Migrations applicate via init container, non lifecycle app
- [ ] Body size limit applicato
- [ ] Pool DB con `acquire_timeout`

### Test
- [ ] Coverage backend ≥ 70% (gate CI)
- [ ] Tutti gli endpoint mutanti hanno almeno happy + 401/403 + 422
- [ ] Vitest + Playwright smoke verdi in CI
- [ ] axe-core 0 violation `serious`/`critical`
- [ ] k6 baseline 100 RPS p95 < 500ms verde

### Frontend
- [ ] 4 dashboard A/B/C/D caricano dati e gestiscono loading/empty/error
- [ ] Pagine `/findings`, `/webhooks`, `/reports`, `/inventory` esistenti e funzionanti
- [ ] Charts interattivi (filtri al click)
- [ ] CVETable keyboard-navigable
- [ ] Error boundary su ogni pagina
- [ ] Form primitive condivise

### Deploy
- [ ] Manifest k8s + HPA + init-container migrations
- [ ] CI build immagini + scan + push registry
- [ ] `uv.lock` committato; build riproducibile
- [ ] `backend/` Node legacy rimosso
- [ ] Backup Postgres automatico + restore testato

### Logging / Audit
- [ ] structlog JSON su stdout
- [ ] Tutte le mutazioni in `audit_log`
- [ ] Sentry attivo backend + frontend
- [ ] Mascheratura secret nei log verificata

### Documentazione
- [ ] `docs/OPERATIONS.md` (auth, scaling, secrets)
- [ ] `docs/RUNBOOK.md` (incident response)
- [ ] `docs/ARCHITECTURE.md` (ADR + C4)
- [ ] `docs/DEPLOY_K8S.md`
- [ ] `CHANGELOG.md`
- [ ] README aggiornato

### Performance
- [ ] Indici DB per ogni query nel critical path
- [ ] Query slow log o logging delle query > 500ms
- [ ] Cleanup jobs su `sync_jobs`, `webhook_deliveries`
- [ ] No `LIMIT 10000` non paginato

### Gestione errori
- [ ] Error handler globale, no leak interni
- [ ] OpSec violation registrata in audit
- [ ] 5xx tracciate in Sentry
- [ ] Validazione 422 senza leak schema interno

### Rollback
- [ ] Migration `downgrade` documentate (anche solo "no-op safe")
- [ ] Rolling deploy K8s con readiness gate
- [ ] Procedura rollback container (image:previous-tag) in RUNBOOK

### Monitoraggio
- [ ] Endpoint `/metrics` Prometheus scrapeable
- [ ] Alert rules: circuit OPEN, sync stuck, 5xx rate, p95 latency
- [ ] Dashboard Grafana minima (RPS, p95, errors, sync state)

---

## Top 10 azioni da fare SUBITO (ordinate)

1. **Decidere e formalizzare la strategia auth** (reverse-proxy oauth2-proxy davanti vs in-app JWT vs entrambi). Owner: `security-architect`. Output: ADR. → senza questo, tutto Sprint 1 è bloccato.
2. **Cancellare la cartella `backend/` Node legacy.** Owner: `devops-platform-engineer`. Effort 30 min. Riduce confusione + superficie di attacco.
3. **Aggiungere `slowapi` rate-limiter globale** (default 100 r/m GET, 20 r/m POST, 5 r/m export). Owner: `security-architect`. Mitiga R9 e DoS export.
4. **Aggiungere middleware Security Headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). Owner: `security-architect`. 1 ora.
5. **Proteggere `PATCH /api/system/config`** (almeno Bearer admin) **in via tampone** anche prima dell'auth completa, perché oggi sovrascrive le API key dei provider in chiaro. Owner: `python-backend-engineer`.
6. **Aggiungere indice `idx_sync_jobs_target` + cleanup job per `sync_jobs` e `webhook_deliveries`.** Owner: `database-architect`. Migration 0009.
7. **Click handler su `SeverityChart` + `TimelineChart` e keyboard su `CVETable` rows.** Owner: `frontend-architect`. Mezza giornata. Sblocca UX.
8. **Wire dei dashboard Remediation/Exposure/Executive** con le API esistenti + `<ErrorBoundary>` di pagina. Owner: `frontend-architect` + `fullstack-dev-agent`. 1 giorno.
9. **Configurare `pytest-cov` + soglia coverage 70% bloccante** in `.github/workflows/ci.yml`. Owner: `qa-testing-agent` + `devops-platform-engineer`. 2 ore.
10. **Aprire i 3 issue/task per i nuovi agent proposti** (`frontend-test-engineer`, `sre-runbook-agent`, opzionale `performance-engineer`) e creare i file `.claude/agents/*.md` con i prompt operativi forniti in §H.4. Owner: `product-owner-secops`.

---

*Fine review.*
