# CVE Management Platform

> Piattaforma di vulnerability management che ingerisce CVE da fonti autorevoli, le correla con un inventario software interno e produce **finding prioritizzati** per il ciclo di remediation.

**Stack**: Python 3.12 · FastAPI · asyncpg · Valkey (Redis-compatible) · PostgreSQL 16 · Next.js 14
**Architettura**: 4-layer (Data → Ingestion → Resolution → Query) · single-instance · OpSec-aware

---

## Indice

1. [Cos'è](#cosè)
2. [Architettura](#architettura)
3. [Modello dati](#modello-dati)
4. [Algoritmo di prioritizzazione](#algoritmo-di-prioritizzazione)
5. [OpSec & rete](#opsec--rete)
6. [Quick start](#quick-start)
7. [API di riferimento](#api-di-riferimento)
8. [Layout del repository](#layout-del-repository)
9. [Integrazioni esterne — analisi `vulnx` & `CVE-Intel`](#integrazioni-esterne--analisi-vulnx--cve-intel)
10. [Roadmap di integrazione consigliata](#roadmap-di-integrazione-consigliata)
11. [Operation runbook](#operation-runbook)
12. [Testing](#testing)
13. [Troubleshooting](#troubleshooting)

---

## Cos'è

La piattaforma risolve tre problemi tipici del vulnerability management aziendale:

| Problema | Risposta della piattaforma |
|---|---|
| Le feed CVE sono enormi e rumorose | Ingest centralizzato (VulnCheck NVD++ / NIST NVD) con delta-sync incrementale ogni ora |
| Mappare versione installata → CVE è ambiguo | Resolution layer con CPE normalizer + version range matcher (semver, OpenSSL patch letters, pre-release) e confidence `CERTAIN`/`UNCERTAIN` |
| Mille CVE ma quale risolvo prima? | Priority score 0–100 che combina **EPSS** (exploit probability), **CVSS** (severity), **CISA KEV** (sfruttamento confermato), **recency** |

L'utente carica l'inventario (CSV o API), la piattaforma risolve i CPE, scarica le CVE pertinenti, le arricchisce con EPSS + KEV e genera finding tracciabili attraverso una FSM (`open → in_review → remediated | accepted_risk | …`).

---

## Architettura

### Vista a 4 layer

```
┌─────────────────────────────────────────────────────────────────────────┐
│  L1 ── DATA               cves · products · findings · sync_jobs       │
│        (PostgreSQL 16, JSONB GIN-indexed, history tables)               │
├─────────────────────────────────────────────────────────────────────────┤
│  L2 ── INGESTION          VulnCheckClient → NvdClient → EpssClient     │
│        TokenBucket rate governor · CircuitBreaker per provider         │
│        APScheduler: delta_sync 1h · epss 24h · kev 6h                  │
├─────────────────────────────────────────────────────────────────────────┤
│  L3 ── RESOLUTION         CpeNormalizer · VersionMatcher · cache       │
│        rapidfuzz vendor/product matching · semver+patch range eval     │
├─────────────────────────────────────────────────────────────────────────┤
│  L4 ── QUERY              Tier 1 local DB → Tier 2 CIRCL fallback      │
│        Tier 3 OpenCVE poll · cache 2 min · OpSec gate per provider     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Flusso dati end-to-end

```
                 inventario CSV
                        │
                        ▼
              ┌───────────────────┐
              │  Resolution Layer │  ← rapidfuzz · NVD CPE API
              │  product → CPE    │
              └───────────────────┘
                        │ normalized_cpe + confidence
                        ▼
              ┌───────────────────┐         ┌──────────────────┐
   ingest ──▶ │  CVE mirror DB    │ ◀─────  │  EPSS / KEV      │
              │  (cves table)     │         │  enrichment loop │
              └───────────────────┘         └──────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │  Match engine     │  versionStartIncluding ≤ v < versionEndExcluding
              │  produce finding  │  match_confidence: CERTAIN | UNCERTAIN
              └───────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │  Priority engine  │  EPSS×40 + CVSS(0-25) + KEV(+25) + Recency(0-10)
              └───────────────────┘
                        │
                        ▼
                   API + UI
              dashboard / findings / live search
```

### Componenti

| Componente | File | Ruolo |
|---|---|---|
| FastAPI app | `backend-py/app/main.py` | startup + DI di pool, redis, scheduler, clients |
| Rate governor | `app/ingestion/rate_governor.py` | TokenBucket per provider (asyncio.Semaphore) |
| Circuit breaker | `app/ingestion/circuit_breaker.py` | FSM CLOSED → OPEN → HALF_OPEN, status su `/api/health` |
| VulnCheck client | `app/ingestion/vulncheck_client.py` | NVD++ ingestion (76.95% CPE coverage) |
| NVD client | `app/ingestion/nvd_client.py` | fallback NIST + delta sync |
| EPSS client | `app/ingestion/epss_client.py` | FIRST.org v3, batch fetch |
| KEV client | `app/ingestion/kev_client.py` | CISA catalog daily |
| CIRCL client | `app/query/circl_client.py` | Tier-2 fallback su cache miss |
| OpenCVE client | `app/query/opencve_client.py` | Tier-3 background poll |
| Sync queue | `app/workers/sync_job_worker.py` | DB-backed queue (`FOR UPDATE SKIP LOCKED`), polled 5s |
| Scheduler | `app/workers/scheduler.py` | APScheduler — delta/epss/kev jobs |
| Version matcher | `app/resolution/version_matcher.py` | semver + OpenSSL patch + pre-release |
| Priority engine | `app/models/priority.py` | score 0–100 |

---

## Modello dati

Tabelle principali (DDL completo in `backend-py/alembic/versions/0001_core_tables.py`):

- **`cves`** — mirror locale con `raw_payload JSONB` (GIN indexed), CVSS v2/v3, EPSS score+percentile, flag `is_kev` con `kev_added_date`, `published_at`, `last_modified_at`.
- **`products`** — inventario: `name · vendor · version` + `normalized_cpe` con `cpe_confidence` ∈ {`certain`, `uncertain`, `manual`}; counters `cve_count` / `critical_count` denormalizzati per dashboard.
- **`cpe_resolutions`** — cache delle risoluzioni name→CPE con `match_score` rapidfuzz.
- **`findings`** — relazione M:N product↔CVE con `status` (FSM), `match_confidence`, `priority_score`, `assigned_to`, `due_date`, `notes`.
- **`findings_history`** — audit trail di ogni cambio di stato (`old_status → new_status`, attore, motivo).
- **`sync_jobs`** — coda DB-backed con `target_id`, `priority`, `attempts`, lock con `FOR UPDATE SKIP LOCKED`.
- **`sync_state`** — checkpoint per source (last_success_at, last_mod_date, total_ingested, last_error).
- **`epss_history`** — serie storica score EPSS per CVE (cascade su delete CVE).

---

## Algoritmo di prioritizzazione

`compute_priority_score()` in `app/models/priority.py`:

```
score = round(EPSS × 40)                 # 0 – 40   (probabilità reale di sfruttamento)
      + CVSS_band                        # 0 – 25   (severity tecnica)
        ├ CRITICAL / cvss ≥ 9.0  →  25
        ├ HIGH     / cvss ≥ 7.0  →  18
        ├ MEDIUM   / cvss ≥ 4.0  →  10
        └ LOW                    →   4
      + (is_kev ? 25 : 0)                # 0 / 25   (CISA conferma exploit attivo)
      + recency_bonus                    # 0 – 10
        ├ ≤ 30 giorni  →  10
        ├ ≤ 90 giorni  →   6
        ├ ≤ 365 giorni →   3
        └ oltre        →   0
       (cap 100)
```

Etichette: ≥80 `CRITICAL PRIORITY` · ≥60 `HIGH` · ≥40 `MEDIUM` · <40 `MONITOR`.

> **Nota di design**: pesare EPSS al 40% e KEV al 25% (al posto di un CVSS dominante) riflette la dottrina post-2022 di FIRST/SSVC: la severity tecnica conta meno della probabilità che qualcuno *stia davvero* sfruttando la CVE.

---

## OpSec & rete

Vincolo di prodotto: **l'inventario asset non lascia mai il perimetro per query routine**.

| Fonte | Tier | Cosa esce | Note |
|---|---|---|---|
| VulnCheck NVD++ | Ingest | nessun dato cliente — solo `lastModified` filter | API key richiesta, free tier |
| NIST NVD | Ingest | nessun dato cliente | rate limit 5 req/30s senza key, 50 con key |
| FIRST EPSS | Enrich | solo `cve_id` (mai dati interni) | batched |
| CISA KEV | Enrich | nulla — feed pubblico statico | scarica intero catalog |
| CIRCL | Tier 2 fallback | `vendor` + `product` espliciti | mai `hostname`/`ip`/`asset_id` |
| OpenCVE | Tier 3 polling | `vendor`/`product` subscription | background, opzionale |
| NVD CPE suggest | Live | termini di ricerca utente | usato solo dalla Live Search UI |

Il `query_engine` (`app/query/query_engine.py`) implementa la regola: **prima il DB locale, sempre**. CIRCL si attiva *solo* su `total == 0` e con CPE risolto. OpenCVE è in background, mai nell'hot path.

---

## Quick start

### Prerequisiti

| Tool | Versione | Install |
|---|---|---|
| Python | ≥ 3.12 | `brew install python@3.12` |
| uv | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Docker | ≥ 24 | Docker Desktop |
| docker compose | v2 | bundled con Docker Desktop |

### Full stack (Docker Compose)

```bash
cp .env.example .env
# minimo: POSTGRES_PASSWORD, REDIS_PASSWORD, VULNCHECK_API_KEY

docker compose up --build
docker compose logs -f backend
```

- Frontend → http://localhost:3000
- API → http://localhost:3001
- API docs (Swagger) → http://localhost:3001/api/docs
- Health → http://localhost:3001/api/health

### Dev locale (senza Docker per il backend)

```bash
cd backend-py
uv venv --python 3.12
uv sync --extra dev

cd .. && docker compose up postgres valkey -d

cd backend-py
DATABASE_URL="postgresql://cve_user:<pass>@localhost:5433/cve_management" \
  uv run alembic upgrade head

DATABASE_URL="postgresql://cve_user:<pass>@localhost:5433/cve_management" \
REDIS_URL="redis://:<pass>@localhost:6380" \
VULNCHECK_API_KEY="<key>" \
  uv run uvicorn app.main:app --reload --port 8000
```

### Variabili di ambiente principali

| Var | Required | Default | Descrizione |
|---|---|---|---|
| `DATABASE_URL` | sì | — | DSN asyncpg PostgreSQL |
| `REDIS_URL` | sì | — | Valkey/Redis URL |
| `VULNCHECK_API_KEY` | sì\* | — | NVD++ — fonte primaria CVE (\*free tier) |
| `NVD_API_KEY` | no | — | alza il rate limit a 50 req/30s |
| `OPENCVE_API_KEY` | no | — | abilita Tier-3 polling |
| `ALLOWED_ORIGIN` | no | `http://localhost:3000` | CORS origin |
| `AUTO_MIGRATE` | no | `true` | esegue Alembic in startup |
| `DELTA_SYNC_INTERVAL_HOURS` | no | `1` | frequenza delta sync |
| `LOG_LEVEL` | no | `INFO` | `DEBUG` / `INFO` / `WARNING` |

---

## API di riferimento

Tutti gli endpoint sono prefissati con `/api`. Documentazione interattiva: `/api/docs`.

### Inventory

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/products` | lista prodotti + active sync job |
| `POST` | `/api/products` | crea prodotto + enqueue sync |
| `POST` | `/api/products/bulk` | import bulk (max 500/req) |
| `POST` | `/api/products/resync-all` | re-sync globale (priority 100) |
| `POST` | `/api/products/{id}/sync` | sync manuale singolo prodotto |
| `GET` | `/api/products/{id}/sync-status` | stato del job + counters |
| `DELETE` | `/api/products/{id}` | elimina + invalida cache |

### CVEs

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/cves` | lista filtrabile (severity, kev, min_epss, min_priority, keyword, year) |
| `GET` | `/api/cves/{cve_id}` | dettaglio + `affected_products` |
| `GET` | `/api/cves/{cve_id}/intel` | **(P3)** intel aggregato: core CVE + EPSS + KEV + PoC/Nuclei + affected + priority breakdown. Query `?refresh=true` forza un round-trip a vulnx (subject to circuit breaker / daily-limit). Cache Redis 10 min. Risponde con `_meta.degraded=true` se vulnx non è disponibile. |
| `GET` | `/api/cves/export` | CSV con BOM (Excel-friendly), max 10k row |

### Findings

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/findings` | lista con `status`, `owner`, paginazione |
| `GET` | `/api/findings/stats` | counters per stato (FSM) |
| `PATCH` | `/api/findings/{product_id}/{cve_id}` | aggiorna stato/owner/due/note + history |
| `GET` | `/api/findings/{product_id}/{cve_id}/history` | audit trail |

### Live (real-time, fonte esterna)

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/live` | NVD live (q / cpe / id, severity, date range) |
| `GET` | `/api/circl?vendor=…&product=…` | CIRCL search |
| `GET` | `/api/circl/products?vendor=…` | autocomplete prodotti CIRCL |
| `GET` | `/api/cpe-suggest?q=…` | NVD CPE autocomplete |

### Dashboard

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/dashboard` | aggregati + top product + EPSS distribution + priority distribution (cache 5 min) |
| `GET` | `/api/dashboard/timeline` | serie temporale 12 mesi (CRITICAL/HIGH/KEV) |

### System & Health

| Verb | Path | Descrizione |
|---|---|---|
| `GET` | `/api/health` | status + circuit breakers + sync_state + scheduler jobs |
| `GET` | `/api/health/ready` | readiness probe (k8s-friendly) |
| `GET` | `/api/health/metrics` | counters HTTP + per-provider + latency p50/p95/p99 |
| `GET` | `/api/system/status` | latency probe di tutti i servizi esterni |
| `GET` | `/api/system/config` | configurazione runtime con secret mask |
| `PATCH` | `/api/system/config` | override config in Valkey (sopravvive restart) |

### Esempi

```bash
# Aggiungi un prodotto manualmente
curl -X POST http://localhost:3001/api/products \
  -H "Content-Type: application/json" \
  -d '{"name":"nginx","vendor":"nginx","version":"1.18.0"}'

# Trigger sync manuale
curl -X POST http://localhost:3001/api/products/1/sync

# Aggiorna lo stato di un finding
curl -X PATCH http://localhost:3001/api/findings/1/CVE-2024-1234 \
  -H "Content-Type: application/json" \
  -d '{"status":"in_review","actor":"analyst@example.com","reason":"Investigating"}'

# Stato sync + circuit breakers
curl -s http://localhost:3001/api/health | jq '{sync_state, circuit_breakers}'

# Metriche provider
curl -s http://localhost:3001/api/health/metrics | jq '.providers'
```

---

## Layout del repository

```
cve-management/
├── backend-py/                    # backend Python primario
│   ├── app/
│   │   ├── api/routers/           # products, cves, findings, dashboard, live,
│   │   │                          # cpe_suggest, circl_router, system, health
│   │   ├── core/                  # config, db pool, cache, logging, metrics, migrations
│   │   ├── ingestion/             # VulnCheck/NVD/EPSS/KEV clients,
│   │   │                          # rate_governor, circuit_breaker, enrichment
│   │   ├── models/                # nvd, product, finding, priority (Pydantic v2)
│   │   ├── query/                 # query_engine multi-tier · CIRCL · OpenCVE · local_query
│   │   ├── resolution/            # cpe_normalizer · version_matcher · cache
│   │   └── workers/               # product_sync · sync_job_worker · scheduler
│   ├── alembic/versions/          # 0001 core · 0002 sync · 0003 hardening · 0004 cascade
│   └── tests/{unit,integration,contract}
├── frontend/                      # Next.js 14 (App Router)
│   └── src/{app,components,lib}
│       └── components/            # CVE, Dashboard, LiveSearch, Products, Settings
├── backend/                       # ⚠️  legacy Node.js — sostituito dal Python (vedi CLAUDE.md)
├── docker-compose.yml
├── .env.example
└── CLAUDE.md                      # developer guide (dettaglio operativo)
```

---

## Integrazioni esterne — analisi `vulnx` & `CVE-Intel`

### Stato attuale della piattaforma vs. proposte

La tua piattaforma copre **mirror + matching + prioritizzazione + remediation tracking**. Manca un asse importante: la **exploitability operativa** — *esiste un PoC pubblico? c'è un template Nuclei già pronto? c'è un advisory dettagliato di un security vendor?*

EPSS dà la *probabilità statistica*, KEV conferma *exploit attivo nel wild*, ma nessuno dei due ti dice se c'è un exploit *eseguibile* — informazione che cambia drammaticamente la velocità di risposta.

### `projectdiscovery/vulnx`

CLI moderna su database CVE centralizzato di ProjectDiscovery. **Capability rilevanti per noi**:

- ricerca Lucene (69 campi: `severity:critical AND is_kev:true AND has_template:true`)
- flag derivati: `is_kev`, `is_template` (Nuclei), `has_poc` (GitHub PoCs), `is_remote`
- output JSON deterministico (compatibile pipe/pipeline)
- batch CVE input (lista o file)
- API key opzionale per togliere rate limit

### `samugit83/redamon` — CVE-Intel

Wrapper agent-friendly su `vulnx` che produce **JSON strutturato per consumo automatizzato**. Aggrega 7 fonti pubbliche (NVD, KEV, EPSS, HackerOne, GitHub PoC, Nuclei templates, CPE). Tre subcommand: `id`, `search`, `filters`. Filosofia: *"always-pass output discipline"* con `--json --limit N --fields` per ottimizzare token.

### Cosa puoi prendere — concretamente

| Idea | Effort | Valore | Dove agganciarla |
|---|---|---|---|
| **1. Aggiungere flag `has_public_poc` e `has_nuclei_template` alla tabella `cves`** | S (1 migration + nuova colonna) | ⭐⭐⭐⭐ | Migration 0005 + enrichment job |
| **2. 4° tier nel `query_engine` per arricchimento exploitability** | M | ⭐⭐⭐⭐ | `app/query/query_engine.py` |
| **3. Estendere il priority score con bonus PoC/template** | S | ⭐⭐⭐ | `app/models/priority.py` |
| **4. Endpoint `/api/cves/{id}/intel`** che ritorna l'aggregato JSON enriched | S | ⭐⭐⭐ | nuovo router `intel.py` |
| **5. Mini-DSL Lucene-like** per il filtro CVE in UI | L | ⭐⭐ | parser dedicato + traduzione in WHERE |
| **6. Tab "Live: Exploitability" nella Live Search** che interroga vulnx per CVE-id | M | ⭐⭐⭐ | nuovo router live + componente FE |

Tutte queste integrazioni sono **OpSec-compatibili**: vulnx riceve solo `cve_id` o `vendor/product`, mai dati di asset.

---

## Roadmap di integrazione consigliata

### Fase 1 — Exploitability flags (1–2 giorni)

**Obiettivo**: avere in DB locale, per ogni CVE già mirrorrata, due flag in più: `has_public_poc`, `has_nuclei_template`.

1. Migration Alembic 0005:
   ```sql
   ALTER TABLE cves
       ADD COLUMN has_public_poc       BOOLEAN NOT NULL DEFAULT FALSE,
       ADD COLUMN has_nuclei_template  BOOLEAN NOT NULL DEFAULT FALSE,
       ADD COLUMN exploitability_updated_at TIMESTAMPTZ;
   CREATE INDEX idx_cves_poc      ON cves(has_public_poc)      WHERE has_public_poc;
   CREATE INDEX idx_cves_template ON cves(has_nuclei_template) WHERE has_nuclei_template;
   ```

2. Nuovo client `app/ingestion/vulnx_client.py` (HTTP, niente CLI):
   - rate governor dedicato (chiave `vulnx`), default 60 req/min
   - circuit breaker dedicato
   - signature `async def fetch_intel(cve_ids: list[str]) -> dict[str, IntelRecord]`

3. Nuovo job APScheduler `vulnx_refresh` (default 24h, simile a `epss_refresh`):
   - select `cve_id` da `cves` con `exploitability_updated_at IS NULL OR < NOW() - 7d`
   - batch da 50 verso vulnx
   - update `has_public_poc`, `has_nuclei_template`, `exploitability_updated_at`

4. Frontend: badge `PoC` e `Template` accanto a KEV nelle tabelle CVE/Findings.

### Fase 2 — Priority score 2.0 (mezza giornata)

```python
# app/models/priority.py — aggiungi parametri opzionali
def compute_priority_score(
    cvss_score, severity, epss_score, is_kev, published_at,
    has_public_poc: bool = False,        # NEW
    has_nuclei_template: bool = False,   # NEW
):
    score = ... # come oggi
    if has_nuclei_template:
        score += 8        # exploit verificabile in massa → urgente
    elif has_public_poc:
        score += 5        # PoC esiste, deve essere weaponizzato
    return min(100, max(0, score))
```

Il cap rimane 100; lo score esistente continua a funzionare se i flag mancano (default `False`).

### Fase 3 — Endpoint intel unificato (mezza giornata)

```http
GET /api/cves/CVE-2024-1234/intel
```
Ritorna un payload formattato come quello di CVE-Intel — superset dei dati locali + flag exploitability + reference URLs (CPE, advisories, exploit-db). Utile per integrazioni downstream (SIEM, ticketing) e per agent LLM interni.

### Fase 4 — 4° tier query (1–2 giorni)

```
Tier 1: local DB        ─── always first
Tier 2: CIRCL fallback  ─── total == 0
Tier 3: OpenCVE poll    ─── background
Tier 4: vulnx           ─── on-demand: enrichment exploitability
                            (NON è un fallback: è una richiesta esplicita
                            quando l'utente apre il dettaglio CVE)
```

Trigger: chiamata a `/api/cves/{id}` con flag `?enrich=true`. Il client vulnx popola/aggiorna i flag exploitability lazily se la riga è "stale".

### Fase 5 (opzionale) — DSL Lucene-like (1 settimana)

Sostituire i 7 query param con un singolo `q=…` parser-driven:

```
severity:critical AND (is_kev:true OR has_template:true) AND epss:>0.5
```

Implementazione consigliata: `pyparsing` o `lark` → AST → `WHERE` SQL parametrizzato (mai string interpolation).

---

## Operation runbook

### Sync state

```bash
curl -s http://localhost:3001/api/health | jq '.sync_state'
```

Output tipico:
```json
[
  {"source":"vulncheck_nvd","last_success_at":"2026-05-02T07:01:23Z",
   "last_mod_date":"2026-05-02T06:00:00Z","total_ingested":284511,"last_error":null}
]
```

### Circuit breakers

Stati possibili: `CLOSED` (normale), `OPEN` (provider rotto, skip per cooldown), `HALF_OPEN` (probe).
Reset manuale: nessuno — sono FSM auto-recover. Per forzarne uno via dev console, riavvia il backend.

### Coda job

```bash
docker compose exec postgres psql -U cve_user -d cve_management -c \
  "SELECT job_type, status, COUNT(*) FROM sync_jobs GROUP BY 1,2 ORDER BY 1,2;"
```

Job stuck in `running` da troppo tempo → il worker è morto. Il polling è ogni 5s, lock con `FOR UPDATE SKIP LOCKED` quindi non c'è rischio di doppio-take.

### Migrazioni

```bash
cd backend-py
uv run alembic upgrade head             # apply pending
uv run alembic revision --autogenerate -m "vulnx_flags"
uv run alembic downgrade -1             # rollback
uv run alembic current                  # versione attuale
```

### Cache invalidation

```bash
docker compose exec valkey valkey-cli -a "<pass>" KEYS 'dashboard:*' | xargs -I{} \
  docker compose exec valkey valkey-cli -a "<pass>" DEL {}
```

Il backend già invalida `dashboard:*` su ogni create/delete prodotto e ogni patch finding.

---

## Testing

```bash
cd backend-py

# unit + contract (no Docker)
uv run pytest tests/unit/ tests/contract/ -v

# integration (testcontainers: PostgreSQL + Redis)
uv run pytest tests/integration/ -v -s

# coverage report
uv run pytest --cov=app --cov-report=term-missing

# singolo file
uv run pytest tests/unit/test_version_matcher.py -v
```

Layer di test:

- **unit** — pure functions: version matcher, priority engine, CPE normalizer
- **contract** — mock HTTP via `respx` per ogni provider esterno (NVD, VulnCheck, EPSS, KEV, CIRCL, OpenCVE)
- **integration** — testcontainers PostgreSQL+Redis per query engine, sync queue, FSM finding

---

## Troubleshooting

| Sintomo | Causa probabile | Fix |
|---|---|---|
| `startup.vulncheck_key_missing` warning ma il backend si avvia | `VULNCHECK_API_KEY` mancante | la piattaforma funziona ma senza ingestion primaria — registrati su vulncheck.com (free tier) |
| Health `degraded` su `valkey` | password sbagliata o porta occupata | confronta `REDIS_URL` in `.env` con `valkey/...` in compose |
| Tutti i prodotti restano `sync_status=pending` | scheduler non parte | verifica `scheduler_jobs` su `/api/health`; se vuoto, controlla i log per `startup.scheduler_started` |
| CVE 0 ma il prodotto ha CPE risolto | rate-limit NVD attivo | con `NVD_API_KEY` impostata il limite va da 5 a 50 req/30s |
| Live Search NVD ritorna 429 | rate limit NVD | la cache è 2 min: aspetta o aggiungi `NVD_API_KEY` |
| `priority_score = NULL` | enrichment EPSS non ancora passato | il job gira ogni 24h. Forza con un manual sync prodotto, oppure abbassa `EPSS_REFRESH_INTERVAL_HOURS` |
| Frontend riceve CORS error | `ALLOWED_ORIGIN` non matcha | il default è `http://localhost:3000`. In produzione setta esplicitamente |

---

## Licenza & contributi

Vedere `CLAUDE.md` per la guida sviluppatore di dettaglio (struttura del codice, pattern asyncpg, convenzioni di logging strutturato, anti-pattern Node.js identificati nel rewrite).

Architettura completa e ADR: `~/.claude/plans/lovely-splashing-zephyr.md`.
