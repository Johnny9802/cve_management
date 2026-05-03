# Proposte di implementazione

> Documento di lavoro per il prossimo ciclo evolutivo della **CVE Management Platform**.
> Ogni proposta è autosufficiente: motivazione, design, contratti, schema DDL, test plan, stima effort, rischi.

**Versione documento**: 1.0 — 2026-05-02
**Stato**: bozza per discussione

---

## Indice

- [Riepilogo esecutivo](#riepilogo-esecutivo)
- [Roadmap consigliata](#roadmap-consigliata)
- [P1 — Exploitability flags (PoC / Nuclei template)](#p1--exploitability-flags-poc--nuclei-template)
- [P2 — Priority score 2.0](#p2--priority-score-20)
- [P3 — Endpoint `/api/cves/{id}/intel`](#p3--endpoint-apicvesidintel)
- [P4 — Quarto tier `vulnx` nel query engine](#p4--quarto-tier-vulnx-nel-query-engine)
- [P5 — DSL Lucene-like per la ricerca CVE](#p5--dsl-lucene-like-per-la-ricerca-cve)
- [P6 — Pannello "Live: Exploitability" in UI](#p6--pannello-live-exploitability-in-ui)
- [P7 — Webhook outbound per finding ad alta priorità](#p7--webhook-outbound-per-finding-ad-alta-priorità)
- [P8 — Risk acceptance workflow & SLA tracking](#p8--risk-acceptance-workflow--sla-tracking)
- [P9 — RBAC e audit log applicativo](#p9--rbac-e-audit-log-applicativo)
- [P10 — Hardening OpSec & data egress monitor](#p10--hardening-opsec--data-egress-monitor)
- [Appendice A — Convenzioni implementative](#appendice-a--convenzioni-implementative)
- [Appendice B — Glossario](#appendice-b--glossario)

---

## Riepilogo esecutivo

La piattaforma copre già: ingestion CVE, risoluzione CPE, version matching, priority score, finding FSM, query engine multi-tier. Quello che manca per fare il salto di qualità è:

1. **Exploitability operativa** — sappiamo *se è grave* (CVSS) e *se è sfruttata* (KEV/EPSS), non sappiamo *se esiste un exploit pronto*.
2. **Workflow di remediation enterprise** — SLA, accettazione rischio formale, escalation.
3. **Distribuzione delle informazioni** — webhook, RBAC, intel API consumabile da altri sistemi (SIEM, ticketing).

Le proposte coprono i tre ambiti, prioritizzate per **valore/effort**.

| Proposta | Effort | Valore | Dipendenze |
|---|---|---|---|
| P1 — Exploitability flags | S (1–2 gg) | ⭐⭐⭐⭐ | — |
| P2 — Priority score 2.0 | S (½ gg) | ⭐⭐⭐ | P1 |
| P3 — Endpoint intel | S (½ gg) | ⭐⭐⭐ | P1 |
| P4 — Tier 4 vulnx | M (1–2 gg) | ⭐⭐⭐⭐ | P1 |
| P5 — DSL Lucene | L (1 sett) | ⭐⭐ | — |
| P6 — Live Exploitability UI | M (2 gg) | ⭐⭐⭐ | P1, P3 |
| P7 — Webhook outbound | M (1–2 gg) | ⭐⭐⭐⭐ | — |
| P8 — SLA & risk acceptance | M (2–3 gg) | ⭐⭐⭐⭐ | — |
| P9 — RBAC & audit | L (1 sett) | ⭐⭐⭐ | — |
| P10 — OpSec egress monitor | S (1 gg) | ⭐⭐⭐ | — |

---

## Roadmap consigliata

```
Sprint 1  (1 settimana)   →  P1 + P2 + P3 + P10
Sprint 2  (1 settimana)   →  P4 + P6 + P7
Sprint 3  (1 settimana)   →  P8 + P9
Backlog                    →  P5 (DSL) — quando il volume di CVE giustifica una query language
```

Logica: prima si aumenta la **qualità del dato** (P1–P3), poi la **distribuzione** (P4, P6, P7), poi i **workflow enterprise** (P8, P9). P10 in parallelo a P1 perché definisce i guardrail per le nuove integrazioni esterne.

---

## P1 — Exploitability flags (PoC / Nuclei template)

### Scope

Aggiungere alla tabella `cves` due flag derivati dall'intel di ProjectDiscovery (via `vulnx`):

- `has_public_poc BOOLEAN` — esiste almeno un PoC pubblico (GitHub, exploit-db) collegato a questa CVE
- `has_nuclei_template BOOLEAN` — esiste un template Nuclei ufficiale o community per questa CVE

Più una colonna di staleness:

- `exploitability_updated_at TIMESTAMPTZ`

### Motivazione

EPSS dice *probabilità statistica*, KEV dice *exploit attivo nel wild*. Ma né l'uno né l'altro rispondono alla domanda operativa più importante:

> "Se non patcho oggi, *quanto è facile* per un attaccante sfruttarmi?"

Un Nuclei template alza l'urgenza in modo drammatico — significa che chiunque abbia 3 minuti può scansionarti in massa. Un PoC pubblico è il passo immediatamente prima.

### Design

**Migration Alembic 0005**
```python
# alembic/versions/0005_exploitability_flags.py
def upgrade() -> None:
    op.execute("""
        ALTER TABLE cves
            ADD COLUMN has_public_poc BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN has_nuclei_template BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN exploitability_updated_at TIMESTAMPTZ
    """)
    op.execute("""
        CREATE INDEX idx_cves_has_poc
            ON cves(has_public_poc) WHERE has_public_poc
    """)
    op.execute("""
        CREATE INDEX idx_cves_has_template
            ON cves(has_nuclei_template) WHERE has_nuclei_template
    """)
```

**Nuovo client** `app/ingestion/vulnx_client.py`
```python
class VulnxClient:
    """ProjectDiscovery vulnerability intel — JSON-only, batch-friendly.

    OpSec: invia solo cve_id o vendor/product. Mai dati di asset.
    """
    BASE_URL = "https://cloud.projectdiscovery.io/api/v1"

    def __init__(self, settings, governor):
        self.governor = governor       # rate-limit dedicato
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(30.0),
            headers={
                "User-Agent": "cve-management/0.1 (internal)",
                "Authorization": f"Bearer {settings.vulnx_api_key}" if settings.vulnx_api_key else "",
            },
        )

    async def fetch_intel(self, cve_ids: list[str]) -> dict[str, IntelRecord]:
        """Batch lookup. Ritorna mapping cve_id → IntelRecord."""
        # Implementazione paginata, max 50 CVE/batch
        ...
```

**Modello**
```python
# app/models/intel.py
@dataclass(frozen=True, slots=True)
class IntelRecord:
    cve_id: str
    has_public_poc: bool
    has_nuclei_template: bool
    poc_urls: list[str]            # solo per /intel endpoint, NON in DB
    template_paths: list[str]      # idem
    fetched_at: datetime
```

**Job APScheduler** `vulnx_refresh`
- frequenza default: **24h** (variabile `VULNX_REFRESH_INTERVAL_HOURS=24`)
- query staleness:
  ```sql
  SELECT cve_id FROM cves
   WHERE exploitability_updated_at IS NULL
      OR exploitability_updated_at < NOW() - INTERVAL '7 days'
   ORDER BY
       CASE WHEN is_kev THEN 0 ELSE 1 END,
       COALESCE(cvss_v3_score, cvss_v2_score, 0) DESC
   LIMIT 5000
  ```
  Stesso pattern di `epss_refresh`: prima KEV+CVSS alti.
- batch da 50, circuit breaker dedicato

**Configurazione**
```env
VULNX_API_KEY=                              # opzionale, alza il rate limit
VULNX_REFRESH_INTERVAL_HOURS=24
VULNX_BASE_URL=https://cloud.projectdiscovery.io/api/v1
VULNX_DAILY_LIMIT=10000
```

### Test plan

- **unit** `tests/unit/test_vulnx_client.py` — parsing risposta, costruzione batch, gestione errori
- **contract** `tests/contract/test_vulnx_contract.py` — `respx` mock con risposte realistiche da vulnx, including 200/429/500/timeout
- **integration** `tests/integration/test_vulnx_refresh.py` — testcontainer + mock vulnx, verifica:
  - flag scritti in DB
  - `exploitability_updated_at` aggiornato
  - re-run idempotente (no scrittura inutile)
  - circuit breaker apre dopo N errori

### Effort & rischi

- **Effort**: 1–2 giorni full-stack (migration + client + job + test).
- **Rischi**:
  - *vulnx API instabile / rate limit aggressivo* → mitigazione: governor + circuit breaker già pattern consolidato; fallback `has_*=NULL` (non `False`) se la sorgente non è interrogabile, evitando falsi negativi.
  - *Free tier insufficiente* → con 5000 CVE/giorno saturiamo presto; mitigazione: refresh 7 giorni invece di 24h sui non-KEV, oppure API key paid.
  - *Cambi schema upstream* → contract test sì, ma annual review consigliata.

---

## P2 — Priority score 2.0

### Scope

Estendere `compute_priority_score()` con due nuovi segnali derivati da P1. Mantenere il cap a 100 e la backward-compatibility (default `False`).

### Design

```python
# app/models/priority.py
def compute_priority_score(
    cvss_score: float | None,
    severity: str | None,
    epss_score: float | None,
    is_kev: bool,
    published_at: datetime | None,
    has_public_poc: bool = False,           # NEW
    has_nuclei_template: bool = False,      # NEW
) -> int:
    score = 0
    # ... logica attuale invariata ...

    # 5. Exploitability bonus (mutuamente esclusivi: si premia il più alto)
    if has_nuclei_template:
        score += 8         # exploit weaponizzato per scan di massa
    elif has_public_poc:
        score += 5         # PoC esiste, weaponization in arrivo

    return min(100, max(0, score))
```

**Razionale dei pesi**: il bonus massimo (8) è *minore* del KEV (+25) e dell'EPSS al massimo (+40). Motivo: PoC/template indicano *capacità tecnica* di sfruttamento, non *esecuzione attiva*. Restano sotto KEV in dignità di segnale.

### Backfill

Il `priority_score` su `findings` è denormalizzato. Va ricalcolato dopo il primo passaggio del job vulnx:

```python
# app/workers/scheduler.py — job priority_recompute
async def recompute_priorities(pool):
    """Ricalcola priority_score per i finding con CVE arricchite negli ultimi 25h."""
    await pool.execute("""
        UPDATE findings f
           SET priority_score = ...,         -- chiamata SQL al motore o ricalcolo Python
               updated_at     = NOW()
          FROM cves c
         WHERE c.cve_id = f.cve_id
           AND c.exploitability_updated_at > NOW() - INTERVAL '25 hours'
           AND f.status IN ('open', 'in_review')
    """)
```

In pratica conviene farlo in Python (non SQL) per non duplicare la logica: query batch, ricalcolo, executemany.

### Test plan

- `tests/unit/test_priority.py` casi:
  - flag entrambi `False` → score identico al precedente (regression-safe)
  - solo PoC → +5
  - solo template → +8
  - entrambi → +8 (non +13: mutuamente esclusivi)
  - cap 100 con KEV+CVSS critical+EPSS=0.99+template

### Effort & rischi

- **Effort**: ½ giornata.
- **Rischi**: *score inflation* — dopo il primo refresh, molti finding salgono di banda. Mitigazione: comunicare il cambio in un'audit history specifica (`priority_recompute` come evento) e mostrare in UI il delta vs. valore precedente.

---

## P3 — Endpoint `/api/cves/{id}/intel`

### Scope

Espone un payload JSON unificato che aggrega tutto ciò che la piattaforma sa o può sapere su una CVE specifica, inclusi i dati che NON conserviamo in DB (PoC URL, template path, reference list completa).

### Motivazione

- Consumo diretto da agent LLM interni che fanno triage
- Esposizione verso SIEM/ticketing (un solo endpoint = un solo contratto)
- Permette di sostituire molteplici chiamate frontend con una unica `/intel`

### Contratto

```http
GET /api/cves/CVE-2024-1234/intel
GET /api/cves/CVE-2024-1234/intel?refresh=true
```

```json
{
  "cve_id": "CVE-2024-1234",
  "source": "local+vulnx",
  "core": {
    "severity": "CRITICAL",
    "cvss_v3_score": 9.8,
    "cvss_v3_vector": "AV:N/AC:L/...",
    "published_at": "2024-03-15T00:00:00Z",
    "last_modified_at": "2024-04-02T00:00:00Z",
    "description": "...",
    "cwe": ["CWE-79"]
  },
  "exploitation": {
    "is_kev": true,
    "kev_added_date": "2024-03-20",
    "epss_score": 0.873,
    "epss_percentile": 0.991,
    "has_public_poc": true,
    "has_nuclei_template": true
  },
  "exploits": {
    "poc_urls": ["https://github.com/.../exploit"],
    "template_paths": ["http/cves/2024/CVE-2024-1234.yaml"]
  },
  "references": [
    {"url": "https://...", "type": "advisory"},
    {"url": "https://...", "type": "vendor"},
    {"url": "https://...", "type": "patch"}
  ],
  "affected_products": [
    {"id": 12, "name": "openssl", "version": "3.0.1", "finding_status": "open", "priority_score": 87}
  ],
  "priority": {
    "score": 87,
    "label": "CRITICAL PRIORITY",
    "factors": {
      "epss_contribution": 35,
      "cvss_contribution": 25,
      "kev_contribution": 25,
      "recency_contribution": 0,
      "exploitability_contribution": 8
    }
  },
  "_meta": {
    "fetched_at": "2026-05-02T10:30:00Z",
    "vulnx_freshness_hours": 6
  }
}
```

### Implementazione

Nuovo router `app/api/routers/intel.py`:
```python
@router.get("/api/cves/{cve_id}/intel")
async def cve_intel(
    cve_id: str,
    refresh: bool = False,
    pool: asyncpg.Pool = Depends(_get_pool),
    vulnx: VulnxClient = Depends(_get_vulnx),
    redis: Redis = Depends(_get_redis),
):
    cve_id = cve_id.upper()
    if not _CVE_ID_RE.match(cve_id):
        raise HTTPException(400, "Invalid CVE ID format")

    cache_key = f"intel:{cve_id}"
    if not refresh:
        cached = await redis.get(cache_key)
        if cached:
            return json.loads(cached)

    # Compose: local CVE + EPSS history + finding affected_products + vulnx exploits
    # Se exploitability_updated_at < 24h e refresh=False → skip vulnx
    # Altrimenti chiamare vulnx (con circuit breaker)
    ...

    await redis.setex(cache_key, 600, json.dumps(payload))   # 10 min cache
    return payload
```

### Test plan

- **contract**: payload schema validato con `pydantic` model `IntelResponse`
- **integration**: end-to-end con CVE seed + mock vulnx, verifica composizione corretta dei 4 sotto-blocchi

### Effort

½ giornata (la maggior parte del lavoro è già fatto da `cves.py` + `findings`; il nuovo è la composizione e il blocco `priority.factors`).

---

## P4 — Quarto tier `vulnx` nel query engine

### Scope

Aggiungere un Tier 4 al `query_engine.py` che arricchisce **on-demand** (non in fallback) i dati exploitability quando l'utente apre il dettaglio di una CVE o quando un trigger esterno lo richiede.

### Motivazione

Oggi il `query_engine` ha:
- Tier 1: local DB (sempre)
- Tier 2: CIRCL (fallback su `total == 0`)
- Tier 3: OpenCVE (background poll)

Manca un livello *attivo on-demand* per l'arricchimento. P4 lo introduce con disciplina rigorosa: **mai nel hot path delle liste**, solo su `GET /api/cves/{id}` o richiesta esplicita.

### Design

```python
# app/query/query_engine.py
async def query_cves_for_product(
    product_id, pool, redis, circl_client, circuit_breakers,
    filters: QueryFilters | None = None,
    enrich_exploitability: bool = False,    # NEW — non default True!
):
    result = await query_findings(pool, product_id, filters)

    # Tier 2 — CIRCL fallback (come oggi)
    if result.total == 0:
        ...

    # Tier 4 — vulnx enrichment (nuovo, opt-in)
    if enrich_exploitability and result.total > 0:
        stale_cves = [
            f.cve_id for f in result.data
            if f.exploitability_updated_at is None
            or f.exploitability_updated_at < datetime.utcnow() - timedelta(hours=24)
        ]
        if stale_cves:
            asyncio.create_task(
                _vulnx_lazy_enrich(stale_cves, pool, redis, ...)
            )
            # NON aspettare: aggiorna in background, restituisce subito i dati attuali
    ...
```

**Pattern lazy enrichment**: la richiesta utente ritorna subito con i dati che abbiamo. Il refresh vulnx parte in background. Alla prossima query lo stato è aggiornato. Questo evita di bloccare l'UI per CVE arricchite raramente.

### OpSec

vulnx riceve solo `cve_id` (lista). Nessun dato di asset, hostname, versione. Compliant con il vincolo "asset inventory mai fuori perimetro".

### Test plan

- verificare che il Tier 4 NON parte se `enrich_exploitability=False`
- verificare che il task background non blocca la risposta principale
- verificare che la seconda query *vede* i dati arricchiti

### Effort

1–2 giorni (il pattern lazy enrichment richiede gestione attenta di lifecycle del task in background — usare `app.state` per tenere traccia, evitare task orfani allo shutdown).

---

## P5 — DSL Lucene-like per la ricerca CVE

### Scope

Sostituire i 7+ query parameter di `/api/cves` con un singolo parametro `q=…` parser-driven.

### Esempio

Oggi:
```
GET /api/cves?severity=CRITICAL,HIGH&kev=true&min_epss=0.5&keyword=openssl
```

Domani:
```
GET /api/cves?q=severity:(CRITICAL OR HIGH) AND is_kev:true AND epss:>0.5 AND keyword:openssl
GET /api/cves?q=has_template:true AND NOT is_kev:true AND severity:CRITICAL
GET /api/cves?q=cve_id:CVE-2024-* AND priority:>80
```

### Motivazione

- I power user (analisti SOC) preferiscono query expressive
- Pattern consolidato (Splunk, Elastic, Lucene) — curva di apprendimento bassa
- `vulnx` e `CVE-Intel` usano la stessa sintassi → consistenza cross-tool

### Implementazione

**Stack**: `lark-parser` (più leggibile di `pyparsing` per grammatiche complete).

```python
# app/query/dsl.py
from lark import Lark, Transformer

GRAMMAR = r"""
    start: expr
    expr: term (boolop term)*
    term: NOT? (atom | "(" expr ")")
    atom: field ":" value
    field: CNAME
    value: range | wildcard | exact | quoted
    range: ">" NUMBER | "<" NUMBER | NUMBER ".." NUMBER
    wildcard: WORD ("*" WORD?)+
    exact: WORD
    quoted: ESCAPED_STRING
    boolop: "AND" | "OR"
    %import common.CNAME
    %import common.WORD
    %import common.NUMBER
    %import common.ESCAPED_STRING
    %import common.WS
    %ignore WS
"""

class QueryToSql(Transformer):
    """Trasforma l'AST in (where_clause, args_list) per asyncpg."""
    # Whitelist tassativa dei campi → no SQL injection
    ALLOWED_FIELDS = {
        "cve_id", "severity", "is_kev", "epss", "cvss",
        "priority", "has_poc", "has_template", "year", "keyword",
    }
    ...
```

**Mai** string interpolation: ogni valore va in `args` con placeholder `$N`. La whitelist dei campi blocca query arbitrarie.

### Coesistenza

Mantenere i parametri legacy come scorciatoia. Se entrambi presenti, `q` ha precedenza (con warning header).

### Test plan

- **unit** estesi: 30+ casi della grammatica
- **fuzz test** con `hypothesis`: input random non deve mai causare exception non gestite
- **security test**: input con SQL classico (`'; DROP TABLE cves; --`) ritorna 400, mai esecuzione

### Effort

1 settimana: la grammatica si scrive in mezza giornata, i test seri ne richiedono 3–4.

### Rischi

- *Accettare query "valide" sintatticamente ma semanticamente folli* (es. `cvss:1000`) → validazione range per ogni campo
- *Curva di apprendimento utente* → mantenere parametri legacy, aggiungere autocomplete UI in P6

---

## P6 — Pannello "Live: Exploitability" in UI

### Scope

Nuovo tab nella sezione **Live Search** del frontend che, dato un CVE-ID, mostra i dati di exploitability provenienti da vulnx.

### Mockup funzionale

```
┌──────────────────────────────────────────────────────────────┐
│  🎯  Live: Exploitability                                     │
├──────────────────────────────────────────────────────────────┤
│  CVE ID: [ CVE-2024-1234              ]  [ Cerca ]            │
├──────────────────────────────────────────────────────────────┤
│  CVE-2024-1234                                  [CRITICAL]    │
│  RCE in OpenSSL 3.0.x via crafted certificate                │
│                                                                │
│  ╔═══════════ EXPLOITABILITY ═══════════╗                     │
│  ║  ✅ Public PoC available              ║                     │
│  ║  ✅ Nuclei template ready             ║                     │
│  ║  ⚠️  CISA KEV — added 2024-03-20      ║                     │
│  ║  📊 EPSS 0.873 (99.1 percentile)      ║                     │
│  ╚════════════════════════════════════════╝                   │
│                                                                │
│  PoC links:                                                    │
│  • github.com/researcher/cve-2024-1234 ↗                      │
│  • exploit-db.com/exploits/12345 ↗                            │
│                                                                │
│  Nuclei template:                                              │
│  • http/cves/2024/CVE-2024-1234.yaml ↗                        │
│                                                                │
│  Affected in your inventory: [3 products] →                    │
└──────────────────────────────────────────────────────────────┘
```

### Implementazione

- Nuovo componente `frontend/src/components/LiveSearch/Exploitability.jsx`
- Endpoint backend: già coperto da P3 (`/api/cves/{id}/intel?refresh=true`)
- Loading state + error state coerente con altri tab

### Effort

2 giorni frontend (componente + tab + state mgmt). Backend già fatto da P3.

---

## P7 — Webhook outbound per finding ad alta priorità

### Scope

Quando un finding raggiunge o supera una soglia di priority configurabile, la piattaforma invia un POST HTTP a un endpoint registrato dall'utente (Slack incoming webhook, Microsoft Teams, generic ticketing API).

### Motivazione

- Eliminare il polling manuale della dashboard
- Integrare il flusso di alerting con i canali aziendali esistenti
- Tracciabilità: webhook registrato + delivery log in audit

### Design

**Nuova tabella `webhooks`**
```sql
CREATE TABLE webhooks (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    secret          TEXT,                    -- HMAC-SHA256 per signature
    event_types     TEXT[] NOT NULL,         -- ['finding.high_priority', 'finding.kev_match', ...]
    min_priority    INT,                     -- filtro extra
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ,
    last_error_at   TIMESTAMPTZ,
    last_error      TEXT
);

CREATE TABLE webhook_deliveries (
    id            BIGSERIAL PRIMARY KEY,
    webhook_id    BIGINT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL,
    payload       JSONB NOT NULL,
    status_code   INT,
    response_body TEXT,
    attempts      INT NOT NULL DEFAULT 0,
    delivered_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliv_pending ON webhook_deliveries(webhook_id, delivered_at)
  WHERE delivered_at IS NULL;
```

**Eventi supportati (v1)**
- `finding.created_high_priority` (priority ≥ 80)
- `finding.kev_match` (un finding referenzia una CVE KEV)
- `finding.exploitability_changed` (PoC/template appena scoperti per finding open)
- `cve.published_critical` (nuova CVE in sync con CVSS ≥ 9.0 che riguarda almeno 1 prodotto)

**Worker delivery**
```python
# app/workers/webhook_worker.py
async def deliver_webhook(delivery_id: int, pool: asyncpg.Pool):
    """Tentativo singolo. Schedule retry se errore (1m, 5m, 30m, 2h, 12h, give-up)."""
    ...
```

Retry policy: exponential backoff con jitter, max 5 tentativi. Dopo il 5° fallimento → `webhook_disabled` event interno + email/log.

**Sicurezza**
- HMAC SHA-256 firma del body (`X-Signature: sha256=…`) usando `webhook.secret`
- Timeout 10s
- Allowlist host opzionale (variabile `WEBHOOK_HOST_ALLOWLIST`)
- **Mai inviare l'inventario completo** — payload contiene solo `cve_id`, `priority_score`, `severity`, `affected_count`. Niente hostname/IP.

### API

```http
POST   /api/webhooks                    # registra webhook
GET    /api/webhooks                    # lista
PATCH  /api/webhooks/{id}               # update
DELETE /api/webhooks/{id}
POST   /api/webhooks/{id}/test          # invia evento sintetico
GET    /api/webhooks/{id}/deliveries    # cronologia delivery
```

### Test plan

- **contract**: payload Slack-compatible verificato
- **integration**: webhook con HTTPbin (testcontainer), verifica retry policy
- **security**: signature HMAC + replay protection (timestamp ± 5 min)

### Effort

1–2 giorni.

### Rischi

- *SSRF* se non c'è host allowlist → mitigazione: blacklist `localhost`, range RFC1918, link-local, metadata cloud (`169.254.169.254`)
- *Amplificazione di alert* (un singolo job sync che marca 500 nuovi KEV) → mitigazione: dedup window 5 min per `(webhook_id, event_type, cve_id)`

---

## P8 — Risk acceptance workflow & SLA tracking

### Scope

Formalizzare il workflow di "rischio accettato" come oggi è solo uno status finale informale, e introdurre **SLA per severity** con tracking di breach.

### Motivazione

- Compliance audit (ISO 27001 / NIS2): "perché questo finding è aperto da 90 giorni?" deve avere una risposta strutturata
- Misurazione MTTR (mean time to remediation) per severity
- Escalation automatica su SLA breach

### Design

**Nuova tabella `risk_acceptances`**
```sql
CREATE TABLE risk_acceptances (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    requested_by    TEXT NOT NULL,
    approved_by     TEXT,                    -- NULL fino ad approvazione
    justification   TEXT NOT NULL,
    expires_at      DATE NOT NULL,           -- non si può accettare a vita
    status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at      TIMESTAMPTZ
);

CREATE INDEX idx_risk_acc_finding ON risk_acceptances(finding_id);
CREATE INDEX idx_risk_acc_expires ON risk_acceptances(expires_at) WHERE status = 'approved';
```

**SLA matrix configurabile**
```python
# Default — modificabile via /api/system/config
SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH":     30,
    "MEDIUM":   90,
    "LOW":      180,
}
SLA_KEV_OVERRIDE = 3        # KEV → 3 giorni regardless
```

**Calcolo `due_date`**: alla creazione del finding, `due_date = published_at + SLA_DAYS[severity]` (con override KEV).

**Vista materializzata `findings_sla`**
```sql
CREATE MATERIALIZED VIEW findings_sla AS
SELECT
    f.id, f.product_id, f.cve_id, f.status, f.due_date, f.created_at,
    c.severity, c.is_kev,
    CASE
        WHEN f.status IN ('remediated', 'closed', 'false_positive') THEN 'met'
        WHEN f.due_date < CURRENT_DATE THEN 'breached'
        WHEN f.due_date - CURRENT_DATE <= 7 THEN 'at_risk'
        ELSE 'on_track'
    END AS sla_state,
    CURRENT_DATE - f.due_date AS days_overdue
FROM findings f
JOIN cves c ON c.cve_id = f.cve_id;

-- refresh ogni ora via APScheduler
```

**Endpoint nuovi**
```http
POST   /api/findings/{pid}/{cve}/risk-acceptance        # richiesta
PATCH  /api/findings/{pid}/{cve}/risk-acceptance/{id}   # approva/rigetta
GET    /api/findings/sla?state=breached                 # report breach
GET    /api/findings/sla/summary                        # contatori dashboard
GET    /api/findings/mttr?period=90d                    # mean time to remediation per severity
```

### Job giornaliero `expire_risk_acceptances`

```python
async def expire_risk_acceptances(pool):
    """Marca come 'expired' le accettazioni scadute, riapre il finding sottostante."""
    await pool.execute("""
        WITH expired AS (
            UPDATE risk_acceptances
               SET status = 'expired'
             WHERE status = 'approved' AND expires_at < CURRENT_DATE
         RETURNING finding_id
        )
        UPDATE findings
           SET status = 'open',
               updated_at = NOW()
         WHERE id IN (SELECT finding_id FROM expired)
           AND status = 'accepted_risk'
    """)
```

### Test plan

- **unit** SLA matrix calculation con override KEV
- **integration** lifecycle completo: open → richiesta → approval → expired → riapertura

### Effort

2–3 giorni.

---

## P9 — RBAC e audit log applicativo

### Scope

Introdurre ruoli applicativi (oggi non c'è autenticazione esplicita, l'app assume zero-trust di rete) e un audit log strutturato di ogni azione di stato.

### Ruoli (v1)

| Ruolo | Permessi |
|---|---|
| `viewer` | read-only su tutti gli endpoint GET |
| `analyst` | tutto `viewer` + PATCH finding (status, owner, notes) + risk-acceptance request |
| `manager` | tutto `analyst` + risk-acceptance approval + webhook config |
| `admin` | tutto + sync trigger + config update + delete prodotti |

### Design

**Autenticazione**: JWT Bearer token. Provider esterno (OIDC) configurabile, oppure utenti locali nella prima iteration.

**Tabelle**
```sql
CREATE TABLE users (
    id           BIGSERIAL PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'manager', 'admin')),
    full_name    TEXT,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    actor_email TEXT NOT NULL,
    actor_role  TEXT NOT NULL,
    action      TEXT NOT NULL,        -- 'finding.update', 'product.create', 'config.patch', ...
    target      TEXT NOT NULL,        -- 'finding:42:CVE-2024-1234', 'product:7'
    diff        JSONB,                -- before/after per state-change
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_actor ON audit_log(actor_email, created_at DESC);
CREATE INDEX idx_audit_target ON audit_log(target);
```

**Middleware FastAPI**
```python
# app/api/middleware/auth.py
async def require_role(allowed: set[str]):
    async def _check(request: Request, token: str = Depends(oauth2_scheme)):
        user = await _verify_jwt(token)
        if user.role not in allowed:
            raise HTTPException(403, "Insufficient privileges")
        request.state.user = user
        return user
    return _check

# Uso nei router:
@router.delete("/api/products/{id}")
async def delete_product(..., user = Depends(require_role({"admin"}))):
    ...
```

**Audit decorator**
```python
@audit_action("finding.update", target_template="finding:{product_id}:{cve_id}")
async def update_finding(...):
    ...
```

### Effort

1 settimana (auth flow + middleware + tabelle + retrofit decorator su endpoint esistenti).

### Rischi

- *Breaking change* per integrazioni esistenti senza auth → mitigazione: variabile `AUTH_ENABLED=false` di default in dev, `true` in production
- *Race condition* su audit insert → fire-and-forget OK ma con rollback transazionale per garantire che audit + state-change siano atomici

---

## P10 — Hardening OpSec & data egress monitor

### Scope

Audit interno automatico che verifichi che **nessun dato di asset** venga inviato a provider esterni, anche per errore di codice futuro.

### Motivazione

La regola OpSec è oggi enforced *implicitamente* dal codice (chi scrive sa che CIRCL riceve `vendor/product` e basta). Vogliamo *enforcement esplicito* + alerting.

### Design

**Wrapper httpx**
```python
# app/core/http.py
class OpsecAwareClient(httpx.AsyncClient):
    """Wrapper httpx che valida il body in uscita contro pattern asset-like."""

    BLOCKLIST_PATTERNS = [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",     # IPv4
        r"\b[0-9a-f]{2}([:-])[0-9a-f]{2}\1[0-9a-f]{2}\1[0-9a-f]{2}\b",  # MAC
        r"hostname|asset_id|asset_tag",      # field name leakage
    ]

    async def request(self, method, url, **kwargs):
        body = kwargs.get("json") or kwargs.get("content") or kwargs.get("data")
        if body and self._matches_blocklist(str(body)):
            logger.error(
                "opsec.egress_blocked",
                url=url, reason="asset-like content detected"
            )
            raise OpsecViolationError("Outbound payload contains asset-like data")
        return await super().request(method, url, **kwargs)
```

Tutti i client esistenti (`NvdClient`, `VulnCheckClient`, `CirclClient`, `OpenCveClient`, `EpssClient`, `KevClient`, futuro `VulnxClient`) devono usare `OpsecAwareClient` invece di `httpx.AsyncClient`.

**Metrica `egress_blocks_total{provider, reason}`** esposta su `/api/health/metrics`. Alert se > 0.

**Test continuo**
```python
# tests/security/test_opsec_egress.py
@pytest.mark.parametrize("client_factory", [
    NvdClient, VulnCheckClient, CirclClient, OpenCveClient,
])
async def test_no_asset_data_in_request(client_factory):
    """Mock httpx, lancia operazioni normali, verifica che nessuna richiesta
    contenga IP/MAC/hostname."""
    ...
```

### Effort

1 giornata (creare il wrapper, refactor dei client esistenti, test).

### Rischi

- *Falsi positivi* su CPE che contengono numeri (`cpe:2.3:a:openssl:openssl:1.1.1`) — mitigazione: blocklist applicato solo a body request, mai a URL/path/query string normalizzati come CPE
- *Performance overhead* del regex check — mitigazione: skip per provider già whitelisted (es. NVD live search dove l'utente esplicitamente cerca un CPE che potrebbe contenere numeri "IP-like")

---

## Appendice A — Convenzioni implementative

Comuni a tutte le proposte:

### Branch & PR

- **Branch**: `feat/p1-exploitability-flags`, `feat/p7-webhooks`, …
- **PR**: una proposta = una PR (eccezione P1+P2 insieme è OK perché P2 dipende strettamente da P1).
- **Title**: `[P1] Exploitability flags (PoC + Nuclei template)`

### Code

- Type hints completi (`mypy --strict`)
- `structlog.get_logger(__name__)` — niente `print`
- SQL parametrizzato sempre, mai string interpolation
- Async-first, niente `time.sleep` o `requests` sincroni
- Docstring sul *perché*, non sul *cosa* (il codice già dice il cosa)

### Database

- Migration Alembic numerata sequenzialmente (`0005_…`)
- `CREATE INDEX IF NOT EXISTS` per idempotenza
- `WHERE` partial index per colonne booleane sparse (es. `WHERE has_public_poc`)
- Mai `CASCADE` sulle DELETE che coinvolgono history (audit go forever)

### Test

- **unit**: 100% delle pure functions
- **contract**: ogni provider esterno con `respx`, almeno 200/4xx/5xx/timeout
- **integration**: testcontainers PostgreSQL+Redis, cammino felice + 1 caso d'errore
- **security** (per P9, P10): test dedicati nel folder `tests/security/`

### Documentazione

Ogni proposta che entra in `main` aggiorna:
- `README.md` — sezione API e/o variabili env
- `CLAUDE.md` — note operative se introduce nuovo pattern
- `PROPOSTE.md` (questo file) — marca lo stato `[ ✅ Implementata ]`

---

## Appendice B — Glossario

| Termine | Significato |
|---|---|
| **CPE** | Common Platform Enumeration — formato `cpe:2.3:<part>:<vendor>:<product>:<version>` |
| **CVE** | Common Vulnerabilities and Exposures — l'identificatore univoco `CVE-YYYY-NNNNN` |
| **CVSS** | Common Vulnerability Scoring System — score 0–10 di severity tecnica |
| **EPSS** | Exploit Prediction Scoring System (FIRST.org) — probabilità 0–1 di sfruttamento nei prossimi 30 giorni |
| **KEV** | Known Exploited Vulnerabilities — catalog CISA delle CVE confermate sfruttate |
| **PoC** | Proof of Concept — codice exploit pubblico, generalmente su GitHub o exploit-db |
| **Nuclei template** | YAML file di ProjectDiscovery che descrive un check automatizzato per una CVE |
| **MTTR** | Mean Time To Remediation — media giorni tra scoperta finding e chiusura |
| **SLA** | Service Level Agreement — qui: tempo massimo concordato per remediation |
| **SSVC** | Stakeholder-Specific Vulnerability Categorization — framework decisione patch |
| **OpSec** | Operational Security — qui: vincolo "asset inventory non lascia il perimetro" |
| **FSM** | Finite State Machine — il finding è una FSM con stati e transizioni esplicite |
