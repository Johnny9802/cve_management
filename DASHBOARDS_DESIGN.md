# Dashboard Design Proposal — 4 alternatives

**Date:** 2026-05-04
**Audience:** Product owner deciding the direction of the next dashboard
work cycle.
**Goal:** four conceptually distinct dashboards, each tailored to a
specific persona, with realistic widgets, data contracts and
implementation guidance.

---

## 1. Comparative table

| Aspect | A — Executive Risk Overview | B — SOC Prioritization | C — Asset & Product Exposure | D — Remediation & Governance |
|--------|-----------------------------|------------------------|------------------------------|------------------------------|
| **Persona** | CISO, head of security, executive board | SOC analyst, vulnerability analyst | Asset owner, IT ops, product owner | Vulnerability manager, governance, auditor |
| **Question answered** | "Are we getting better? Where is the residual risk?" | "What should I patch *today* and *now*?" | "Which products / vendors / asset groups generate the most risk?" | "Are findings being closed in time? Who owns what? Is the audit trail clean?" |
| **Time horizon** | Weeks → quarters; trend-heavy | Real-time / today | Snapshot of current state | Open lifecycle / SLA windows |
| **Primary signals** | Aggregate KPIs, trends, SLA %, MTTR | Priority score, KEV, EPSS, PoC, Nuclei | Top-N vendors / products / asset groups, heat map | FSM kanban, SLA breach, owner ranking, audit log |
| **Drill-down depth** | KPI → list → CVE | CVE → product → finding | Vendor → product → version → CVE | Finding → history → audit |
| **Vanity-metric risk** | High if not designed carefully (counter inflation) | Low (every signal maps to action) | Medium (top-N can mislead) | Low (every metric maps to a process step) |
| **New backend endpoints** | several aggregations + snapshots over time | none (reuses existing) | several aggregations | mostly built (Sprint 3) — minor extensions |
| **Approx. effort** | L (1.5–2 sprints) | S (½–1 sprint) | M (1 sprint) | M (1 sprint) |
| **Refresh cadence** | Daily | Real-time / 30-60s | Daily | Every minute or on action |
| **Mobile usability** | Yes — KPIs scale | Limited — table-heavy | Limited — heat map | Yes — kanban scales |
| **Export** | PDF executive report | CSV (action queue) | CSV / PDF asset report | CSV / PDF SLA & audit report |

---

## 2. Per-dashboard detail

### A — Executive Risk Overview

#### A.1 — Target
CISO, head of security, board members, audit committee. Non-technical
or semi-technical reader who reviews the platform quarterly or
monthly.

#### A.2 — Objective
Answer "**is the security posture improving?**" with a few weighty
KPIs and trend lines. Provide an evidence-based view for budget /
staffing / SLA discussions. Avoid the temptation of showing every
metric — pick six and make them count.

#### A.3 — Layout

```
┌────────────────────────────────────────────────────────────────────┐
│  Period selector ▾  [last 30d | 90d | QTD | YTD]    Export PDF ⬇   │
├────────────────────────────────────────────────────────────────────┤
│  Risk score  90d trend ↘ −12  │  KEV exposure  ↘ −5  │ MTTR ↘ -2d  │
├────────────────────────────────────────────────────────────────────┤
│  Trend lines (single chart, dual axis)                             │
│  - Open critical / high findings over time                         │
│  - Remediation velocity (closed per week)                          │
├────────────────────────────────────────────────────────────────────┤
│  SLA compliance %       │   Critical aging buckets                 │
│  by severity            │   (0-30, 30-90, 90+ days open)           │
├────────────────────────────────────────────────────────────────────┤
│  Top affected           │   Top remediation owners                 │
│  product groups (top 5) │   (best closure rate vs target)          │
└────────────────────────────────────────────────────────────────────┘
```

#### A.4 — Widgets

* **KPI strip (3 tiles)**: Risk Score (composite 0-100, see A.6),
  KEV exposure delta, MTTR change. Each shows current value, period
  delta arrow, and a sparkline for the period.
* **Open critical/high findings trend** (line chart) with shaded area
  if SLA target line crossed.
* **Remediation velocity** (bar chart, weekly closed counts).
* **SLA compliance per severity** (horizontal bars: % met / breached).
* **Aging buckets** (stacked bar 0-30 / 30-90 / >90 days).
* **Top product groups** (table, click → C dashboard filtered).
* **Top owners** (table, click → D dashboard filtered).
* **Period selector** + **Export PDF**.

#### A.5 — Data sources

* `cves.severity`, `cves.is_kev`, `cves.epss_score`,
  `cves.exploitability_updated_at`
* `findings.status`, `findings.due_date`, `findings.priority_score`,
  `findings.assigned_to`, `findings.created_at`, `findings.updated_at`
* `findings_history.changed_at` (for MTTR & velocity)
* `risk_acceptances.status`, `risk_acceptances.expires_at`
* `audit_log` (read-only)
* **Snapshots over time** — see A.6.

#### A.6 — Backend computation

* **Risk Score (composite)**: weighted sum of:
  * % open findings with priority ≥ 80 (weight 0.4)
  * % open findings with KEV match (weight 0.3)
  * % findings SLA breached (weight 0.2)
  * MTTR rolling 90d normalised (weight 0.1)
  Computed by a new `/api/dashboard/exec` endpoint, returning the
  current value plus a sparkline series.
* **MTTR change**: reuses Sprint 3 `/api/findings/mttr?period=90d`
  with period parameter.
* **Trend snapshots**: introduce a daily snapshot table
  (`exec_snapshots`) populated by a new APScheduler job
  `daily_snapshot` that captures aggregate counts at 00:00 UTC.
  Without snapshots the trend reflects only "as of now" data.

#### A.7 — Frontend computation
Only formatting, sparkline rendering, period-selector state, PDF
generation. No client-side aggregation of large lists.

#### A.8 — Endpoints

* `GET /api/dashboard/exec?period=90d` (new) — returns all six KPIs +
  series.
* `GET /api/findings/sla/summary` (Sprint 3, exists)
* `GET /api/findings/mttr?period=90d` (Sprint 3, exists)
* `GET /api/dashboard/exec/export.pdf?period=90d` (new) — server-side
  PDF, since it is the most reliable for finance/legal usage.

#### A.9 — React components

* `<ExecHeader period onPeriodChange onExport>`
* `<KpiTrendCard label value previous trend sparkline>`
* `<TrendLineChart series xAxis annotations>`
* `<SlaCompliancePanel summary>`
* `<AgingBucketChart buckets>`
* `<TopProductGroups items onClick>`
* `<TopOwners items onClick>`
* `<DashboardLayout>` (shared by all four)

#### A.10 — How to use it (real life)

* Quarterly board review: open `/dashboard/exec?period=QTD`, export
  PDF, attach to slide deck.
* Friday after-action review: compare 7d trend vs target.
* Budget cycle: use "Top owners" + MTTR to argue for hiring or tooling.

#### A.11 — Pros / Cons

| Pros | Cons |
|------|------|
| Single source of truth for executive narrative | Needs daily snapshot infra (new table + cron) |
| PDF export ready for board packs | High risk of vanity metrics if KPIs not chosen carefully |
| Shows direction (better / worse), not absolute counts | Trend signal is weak in early days (cold-start) |
| Justifies budget asks | Useless without persistent snapshots |

#### A.12 — When to choose vs the others

Pick A first **only** if your stakeholder is the board / CISO and you
can wait 30 days for snapshots to start showing trends. Otherwise,
build B / D first and add A when there is a story to tell.

#### A.13 — Future extensions

* Compare across business units (multi-tenant).
* Forecast: linear regression on remediation velocity → ETA to clear
  backlog.
* Benchmark vs anonymised peer data (FIRST.org / industry).

---

### B — SOC Prioritization Dashboard

#### B.1 — Target
SOC analyst, vulnerability analyst. The person who at 09:05 Monday
opens the platform and asks "what should I work on?". This is the
**operational landing**.

#### B.2 — Objective
Maximise the number of correct triage decisions per minute. Surface
KEV-in-inventory, high-EPSS, public-PoC and Nuclei-template signals
without scrolling. Allow the analyst to act (open / in_review /
remediate / risk-accept) without leaving the dashboard.

#### B.3 — Layout

```
┌────────────────────────────────────────────────────────────────────┐
│  Global filter bar (chips, URL-aware)                              │
├──────────┬─────────────────────────────────────────────────────────┤
│          │ Top 10 urgent findings                                  │
│ Quick    │ - KEV match + product version + priority               │
│ filters  │ - Open / In review status pill                          │
│ (KEV /   │                                                         │
│ PoC /    ├─────────────────────────────────────────────────────────┤
│ Nuclei / │ New exploitability changes (last 7d)                    │
│ EPSS≥90% │ - PoC just appeared / Nuclei template just published    │
│ /        ├─────────────────────────────────────────────────────────┤
│ aging )  │ Aging KEV findings (>3 days breach)                      │
│          ├─────────────────────────────────────────────────────────┤
│          │ EPSS hotlist (≥0.9 EPSS but no KEV yet — early warning) │
└──────────┴─────────────────────────────────────────────────────────┘
```

#### B.4 — Widgets

* **Filter chips** (top): KEV / PoC / Nuclei / EPSS ≥ 0.5 / EPSS ≥
  0.9 / SLA breached / Owner: me. Multiple selectable, all reflected
  in the URL.
* **Top urgent findings** (8-10 rows; same component as Sprint 1's
  `UrgentCvesPanel` but scoped to findings, not just CVEs).
  Inline status picker on hover/focus.
* **New exploitability changes** (last 7 days): CVEs whose
  `exploitability_updated_at` rose AND `has_public_poc` /
  `has_nuclei_template` flipped true. This is the unique
  early-warning signal vulnx provides.
* **Aging KEV findings**: open findings with `is_kev=true` and
  `due_date < today − 3` (KEV SLA = 3 days).
* **EPSS hotlist (no KEV yet)**: open findings with EPSS ≥ 0.9
  AND `is_kev=false`. These are the next likely KEV additions —
  patching them pre-emptively is high-leverage.
* Each row: priority badge, severity, KEV/PoC/Nuclei, product, version,
  due date, owner, status pill (clickable → status picker drawer).
* **Bulk action bar** appears when ≥ 1 row selected: "mark in_review",
  "set due date", "assign", "open in detail".

#### B.5 — Data sources

* `findings.*` joined with `cves.*` and `products.*`
* `cves.exploitability_updated_at`, `has_public_poc`,
  `has_nuclei_template` (Sprint 1)
* `cves.is_kev`, `cves.epss_score`
* `products.normalized_cpe`, `products.version`
* `findings.due_date`, `findings.status`, `findings.assigned_to`,
  `findings.priority_score`

#### B.6 — Backend computation

Almost all SQL is already supported. Add:

* `GET /api/findings?sort=priority_score&status=open&top=20` — already
  works.
* `GET /api/cves?has_poc=true&has_nuclei=false&since=7d` (small
  extension to existing `/api/cves`).
* `GET /api/findings?epss_min=0.9&kev=false&status=open` — needs
  EPSS filter on findings query (small extension).

#### B.7 — Frontend computation

Filter chip state ↔ URL. Optimistic UI on status updates with toast
rollback on 4xx.

#### B.8 — React components

* `<FilterChipBar chips active onChange>`
* `<UrgentFindingsPanel rows onSelectFinding>` (extends existing
  `UrgentCvesPanel` with finding-level data)
* `<ExploitabilityDeltaPanel rows>`
* `<AgingKevPanel rows>`
* `<EpssHotlistPanel rows>`
* `<BulkActionBar selectedIds onAction>`
* `<FindingStatusPicker status onChange>`

#### B.9 — How to use it

* Daily standup landing page.
* Run shift handoff by sharing the URL with applied filters
  (`?status=open&owner=alice&kev=true`).
* Triage 50 KEV-in-inventory in 30 minutes by working top-down.

#### B.10 — Pros / Cons

| Pros | Cons |
|------|------|
| Highest analyst productivity uplift | Doesn't tell management story |
| Reuses Sprint 1-3 backend almost as-is | Limited value if inventory is empty |
| Low effort to ship | Needs the URL-state plumbing first |
| Scales with the analyst's expertise | Power-user feel may intimidate juniors |

#### B.11 — When to choose

**Default first dashboard.** Lowest risk, highest immediate value.
Choose B over A when the platform is < 6 months old or the snapshot
infra is not in place yet.

#### B.12 — Future extensions

* Saved filter presets ("My triage queue").
* Real-time WebSocket update on new KEV match.
* Quick "compare two CVEs" panel for similarity / overlapping
  affected products.
* AI summariser of the next 5 actions.

---

### C — Asset & Product Exposure Dashboard

#### C.1 — Target
Asset owner, IT operations, product owner, application security
champion who needs to know which corner of the inventory is leaking
risk.

#### C.2 — Objective
Move from "list of CVEs" to "list of *things you own* sorted by
risk". Surface concentrations: a single product version with 20
critical findings is more dangerous than 20 products with one each
— and the dashboard must make the difference visually obvious.

#### C.3 — Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  Global filter bar                                                  │
├─────────────────────────────────────────────────────────────────────┤
│  Top vendors by exposure (bar chart, clickable)                     │
│  ▓▓▓▓▓▓▓▓ apache              312 critical · 12 KEV · 8 PoC         │
│  ▓▓▓▓▓▓   microsoft           218 critical · 8 KEV  · 4 PoC         │
│  ...                                                                │
├─────────────────────────────────────────────────────────────────────┤
│  Heatmap: Product × severity × KEV                                  │
│  Each cell = product/version with colour intensity = priority avg   │
├─────────────────────────────────────────────────────────────────────┤
│  Top 10 products by KEV count │  EOL/legacy products at risk        │
├─────────────────────────────────────────────────────────────────────┤
│  Inventory coverage strip                                           │
│  Resolved CPE: 87%  ·  Unresolved: 13%  ·  Sync errors: 2%          │
└─────────────────────────────────────────────────────────────────────┘
```

#### C.4 — Widgets

* **Top vendors by exposure** (horizontal bar): rank by sum of
  priority_score of open findings, with breakdown labels (critical /
  KEV / PoC). Click → filter all panels by vendor.
* **Heat map**: rows = top 20 products, columns = severity bands +
  KEV indicator. Cell colour = average priority_score. Click cell →
  drawer with finding list.
* **Top 10 products by KEV count**: ranked table with deltas vs
  prev period.
* **EOL / legacy products at risk**: products whose latest known
  patch is > 12 months old AND have open critical findings — flagged
  for replacement, not patching.
* **Inventory coverage strip**: % CPE resolved, % synced, % with
  errors. Important quality signal.

#### C.5 — Data sources

* `products.*`, `findings.*`, `cves.*`
* CPE resolution status from `products.cpe_confidence`
* Date of last KEV addition (`cves.kev_added_date`)

#### C.6 — Backend computation

* New `GET /api/dashboard/exposure` returning:
  * `top_vendors` (sorted by `SUM(priority_score) over open findings`)
  * `top_products`
  * `heatmap_cells` (product_id, severity, kev_count, avg_priority)
  * `inventory_coverage` (resolved / unresolved / errors)
* Heat map cells must respect global filters → server-side query
  with WHERE.

#### C.7 — Frontend computation

Filter ↔ URL only. Heat-map rendering via plain CSS grid (no need
for d3) — keeps bundle slim.

#### C.8 — Endpoints

* `GET /api/dashboard/exposure?vendor=&severity=…` (new)
* `GET /api/products?has_findings=true&order=critical_count_desc` (small extension)

#### C.9 — React components

* `<TopVendorsBar items onSelectVendor>`
* `<ProductHeatmap rows columns onCellClick>`
* `<TopProductsTable items metric="kev_count" onClick>`
* `<EolFlagPanel items>`
* `<InventoryCoverageStrip stats>`
* `<DrawerProductDetail productId>` (drawer)

#### C.10 — How to use it

* Mid-quarter inventory review with IT ops.
* Identify candidates for forced upgrade ("nginx 1.14 has 12 KEVs —
  schedule an upgrade window").
* Spot CPE-resolution gaps that hide real exposure.

#### C.11 — Pros / Cons

| Pros | Cons |
|------|------|
| Bridges security and IT-ops conversations | Risky if heatmap visually saturates |
| Highlights structural problems (EOL, legacy) | Top-N misleads if a long tail is the real risk |
| Helps prioritise upgrade projects | Needs CPE-resolution to be working well |
| Coverage strip surfaces data-quality issues | New aggregation endpoint adds backend code |

#### C.12 — When to choose

Pick C when the platform has 50+ distinct products and the analyst
already has B available. Without B, this dashboard is *inspectional*
but not *actionable*.

#### C.13 — Future extensions

* Asset groups (production / staging / dev) when inventory model
  supports it.
* Vendor risk score: weighted by historical CVE rate, time-to-patch,
  number of critical CVEs in last year.
* Per-business-unit segmentation.

---

### D — Remediation & Governance Dashboard

#### D.1 — Target
Vulnerability manager, governance analyst, internal auditor. Anyone
who needs to prove that findings are being processed correctly and
that audit evidence is intact.

#### D.2 — Objective
Show the **process**, not the *catalog*. SLA breaches, owner
distribution, FSM transitions, risk-acceptance state, audit log
integrity. Surface "the work is being done" or "the work is stuck".

#### D.3 — Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  Global filter bar (period · severity · owner · status)             │
├─────────────────────────────────────────────────────────────────────┤
│  Findings pipeline (kanban-like columns, counts in headers)         │
│  Open  · In review  · Planned  · Accepted risk · Remediated · Closed│
│  drag-and-drop status change with confirmation                      │
├─────────────────────────────────────────────────────────────────────┤
│  SLA breach summary    │   Risk-acceptance lifecycle                │
│  per severity / state  │   pending · approved · expiring 7d · expired│
├─────────────────────────────────────────────────────────────────────┤
│  Owner workload                  │   Audit log (recent 50 events)   │
│  rows: owner / open / breached / │   timeline w/ actor + diff       │
│  remediated                      │                                  │
├─────────────────────────────────────────────────────────────────────┤
│  Export controls: SLA report PDF · Audit log CSV · MTTR by sev      │
└─────────────────────────────────────────────────────────────────────┘
```

#### D.4 — Widgets

* **Findings pipeline (kanban)**: each column = FSM state + count;
  drag-and-drop changes status with `<ConfirmDialog>` and audit
  entry. Click a card → detail drawer.
* **SLA breach summary**: matrix severity × state from
  `/api/findings/sla/summary`. Click cell → filtered list.
* **Risk-acceptance lifecycle**: counts of pending / approved /
  expiring (next 7 days) / expired. Click cell → filtered list of
  acceptances.
* **Owner workload table**: per assignee — open / in_review /
  breached / remediated counts, average resolution time. Click row
  → B dashboard filtered by owner.
* **Audit log timeline**: last 50 events from `audit_log` with
  actor, action, target, diff before/after. Useful both as audit
  evidence and as activity feed.
* **Export controls**: CSV for SLA, MTTR, audit; PDF for governance
  report.

#### D.5 — Data sources

* `findings.*`, `findings_history.*`, `risk_acceptances.*`,
  `audit_log.*`, `cves.severity`, `cves.is_kev`

#### D.6 — Backend computation

Most endpoints exist (Sprint 3):

* `GET /api/findings/sla/summary` — SLA matrix
* `GET /api/findings/mttr?period=90d` — MTTR
* `GET /api/audit-log?limit=50` — recent events
* `GET /api/findings?status=...` — pipeline columns

To add:

* `GET /api/dashboard/remediation` (consolidated payload to avoid
  N+1 calls)
* `GET /api/risk-acceptances/summary` — counters by status
* `GET /api/dashboard/owner-workload` — per-assignee aggregates
* `GET /api/dashboard/governance-report.pdf?period=…` — server-side
  PDF for repeatable governance evidence.

#### D.7 — Frontend computation

Drag-and-drop UI state (use `@dnd-kit/core`, ~6 kB), with optimistic
update + revert on 4xx.

#### D.8 — React components

* `<FindingsPipeline columns onMove>`
* `<FindingCard finding draggable>`
* `<SlaSummaryMatrix data onCellClick>`
* `<RiskAcceptanceLifecycle counters onSelect>`
* `<OwnerWorkloadTable rows onSelect>`
* `<AuditTimeline events>`
* `<GovernanceExportPanel onExportSlaCsv onExportAuditCsv onExportPdf>`

#### D.9 — How to use it

* Weekly remediation stand-up: open kanban, walk through "Open" and
  "In review" columns.
* Audit prep: open and export the audit log CSV + governance PDF
  for the period requested.
* SLA review: identify breached owners and reassign / escalate.

#### D.10 — Pros / Cons

| Pros | Cons |
|------|------|
| 90% of backend already built (Sprint 3) | Drag-and-drop adds a small dependency |
| Direct value for compliance / audit | Less excitement for analysts vs B |
| Owner accountability becomes visible | Risk of "blaming culture" without good support |
| PDF export = governance ready | Audit timeline can grow long quickly |

#### D.11 — When to choose

Pick D when there is at least a small backlog (≥ 30 findings) and
multiple owners, OR when an audit / certification cycle is incoming.
Excellent **second** dashboard after B.

#### D.12 — Future extensions

* SLA escalation rules ("if breached > 14d → notify CISO").
* Auto-generated weekly governance email from the dashboard.
* Sign-off workflow on risk-acceptance approvals (multi-approver).
* External system integration (Jira / ServiceNow / Confluence).

---

## 3. Final navigation proposal

### Sidebar (Sprint 1-2 of new IA)

```
┌───────────────────────────┐
│  CVE Management           │
│                           │
│  📊  Dashboards     ▾     │
│       └ Executive (A)     │
│       └ SOC Triage (B)    │
│       └ Exposure (C)      │
│       └ Remediation (D)   │
│                           │
│  📦  Inventory            │
│  🛡️   Findings             │
│  🧬  CVE Intelligence     │
│  🎯  Live Exploitability  │
│  📤  Webhooks             │
│  📈  Reports              │
│  ⚙️   Settings             │
└───────────────────────────┘
```

### Per-persona default landing

The sidebar lets the user pick, but the system also remembers a
**default dashboard per role/preference** (stored in `localStorage`
for now, in a future user model when auth is added):

| Role / preference                  | Default landing |
|------------------------------------|-----------------|
| First-time user (no preference)    | B (SOC Triage)  |
| Analyst                            | B               |
| Vulnerability Manager              | D               |
| Asset / IT operations              | C               |
| CISO / executive                   | A               |

### URL pattern

```
/dashboards/triage         → B
/dashboards/exposure       → C
/dashboards/remediation    → D
/dashboards/executive      → A
/                          → redirect to user's default
```

### Cross-dashboard navigation (drill-down)

```
A KPI tile  → B filtered list
A trend     → D pipeline filtered
B finding   → finding detail page (with audit history)
B finding   → C product page (vendor / version)
C heat-map  → B filtered by product
C vendor    → C filtered by vendor
D kanban    → finding detail
D owner     → B filtered by owner
```

Every drill-down is a URL with query params so the back button
preserves context.

### Global filter bar (shared across all four)

```
period · severity · KEV · EPSS≥ · priority≥ · vendor · product
· asset_group · status · owner
```

Stored in URL. Each dashboard reads its own subset from the URL and
ignores irrelevant ones (e.g. Executive ignores vendor / product;
Remediation ignores EPSS).

---

## 4. Roadmap — 3 sprints

### Sprint Dashboards 1 — Foundation + B

**Goal:** ship Dashboard B as the new landing, with the global filter
bar and URL-state plumbing.

**Backend**
- Extend `/api/cves` to support `has_poc` / `has_nuclei` /
  `since` query params.
- Extend `/api/findings` with `epss_min` filter (joining `cves`).
- Add lightweight `/api/dashboard/triage` aggregator (top urgent + new
  PoC + aging KEV + EPSS hotlist) so the dashboard does **one** call.

**Frontend**
- `<DashboardLayout>` shell with sidebar + global filter bar reading
  URL.
- `<FilterChipBar>` with KEV / PoC / Nuclei / EPSS≥ / aging / mine.
- `<UrgentFindingsPanel>`, `<ExploitabilityDeltaPanel>`,
  `<AgingKevPanel>`, `<EpssHotlistPanel>`.
- `<BulkActionBar>` with mark / assign / set-due actions.
- `<FindingStatusPicker>` (used inline + in detail).
- URL-state lib (`lib/url-state.js`) reading/writing
  `URLSearchParams` for filters and selection.

**Tests**
- Backend: contract for `/api/dashboard/triage`.
- Frontend: render of each panel with empty / loading / 1-row / many
  rows.

**Acceptance**
- B reachable at `/dashboards/triage`.
- All filters reflect in URL; refresh preserves state.
- Bulk action on 5 findings works against the real `/api/findings`.

---

### Sprint Dashboards 2 — D Remediation & Governance

**Goal:** ship Dashboard D using Sprint 3 backend, add risk-acceptance
summary endpoint and governance PDF.

**Backend**
- `GET /api/risk-acceptances/summary`.
- `GET /api/dashboard/owner-workload`.
- `GET /api/dashboard/remediation` (consolidated).
- `GET /api/dashboard/governance-report.pdf?period=…` —
  server-side PDF (use `weasyprint` or `reportlab`).

**Frontend**
- `<FindingsPipeline>` kanban with `@dnd-kit/core`.
- `<SlaSummaryMatrix>`, `<RiskAcceptanceLifecycle>`,
  `<OwnerWorkloadTable>`, `<AuditTimeline>`.
- Confirmation dialog for status moves with audit-entry preview.
- `<GovernanceExportPanel>` with date-range picker.

**Tests**
- Lifecycle smoke: drag-and-drop "Open" → "In review" writes
  `findings_history` + `audit_log`.
- PDF byte length sanity check on integration test.

**Acceptance**
- D reachable at `/dashboards/remediation`.
- Audit log shows the drag-and-drop entry.
- Governance PDF downloads with period header.

---

### Sprint Dashboards 3 — C Exposure + A Executive

**Goal:** ship the inspection (C) and executive (A) dashboards, plus
the daily snapshot infrastructure that Executive needs.

**Backend**
- New table `exec_snapshots` + APScheduler job `daily_snapshot`
  (00:05 UTC) that captures aggregate KPIs.
- `GET /api/dashboard/exposure`.
- `GET /api/dashboard/exec?period=…` (returns KPIs + sparklines from
  snapshots).
- `GET /api/dashboard/exec/export.pdf?period=…`.

**Frontend**
- `<TopVendorsBar>`, `<ProductHeatmap>`, `<TopProductsTable>`,
  `<EolFlagPanel>`, `<InventoryCoverageStrip>`.
- `<ExecHeader>`, `<KpiTrendCard>`, `<TrendLineChart>`,
  `<SlaCompliancePanel>`, `<AgingBucketChart>`.
- `<DashboardSelector>` defaulting per stored role preference.

**Tests**
- Snapshot job idempotency (running twice the same day produces
  one row).
- Heatmap respects global filter.

**Acceptance**
- C reachable at `/dashboards/exposure`, drilldowns into B work.
- A reachable at `/dashboards/executive`, KPIs show ≥ 7 days of
  trend after one week of snapshots.
- Default landing dashboard configurable (localStorage for now).

---

## 5. Validation checklist

Use this checklist on every dashboard before declaring it done. A
dashboard that fails ≥ 2 items is **not** ready.

### Information architecture
- [ ] One persona named, one primary question answered.
- [ ] No more than 6 widgets above the fold.
- [ ] Every widget answers a sub-question of the primary one.
- [ ] No widget lives only because the data exists.

### Decision support
- [ ] An analyst can name the decision the dashboard supports.
- [ ] Drill-down to detail is always one click away.
- [ ] Empty / cold-start state is informative, not blank.
- [ ] At least one widget supports a *bulk* action (B/D).

### Filters
- [ ] All filters reflected in URL.
- [ ] Filter state preserved on refresh and shared by URL copy-paste.
- [ ] "Reset filters" affordance present and obvious.
- [ ] Inactive filters do not visually compete with active ones.

### Data quality
- [ ] No counter shown without its denominator (e.g. "8 breached" →
  "8 / 230 breached").
- [ ] Trend arrows compare against a clearly stated baseline.
- [ ] Empty buckets do not show "0" without context.
- [ ] All values are computed server-side or via a documented
  derivation.

### Clickability hygiene
- [ ] No element looks clickable but isn't.
- [ ] No element does something but doesn't *look* clickable.
- [ ] Cards with hover effect have a defined click target.
- [ ] All clickable rows are keyboard-activable.

### Feedback
- [ ] Every action gives feedback within 250 ms (skeleton or toast).
- [ ] Errors surface inline near the element that caused them.
- [ ] Destructive actions go through `<ConfirmDialog>`.
- [ ] Background refresh is visible (last-refreshed clock).

### Accessibility
- [ ] Visible focus rings on every interactive element.
- [ ] All icons have a text alternative or aria-label.
- [ ] All charts have a textual summary or table fallback.
- [ ] `prefers-reduced-motion` honoured.

### Performance
- [ ] Single page load triggers ≤ 3 backend requests.
- [ ] Heaviest widget renders in ≤ 200 ms on cached data.
- [ ] No client-side aggregation over > 1 000 rows.
- [ ] Drill-down does not refetch what is already cached.

### Export & governance (A and D)
- [ ] PDF export deterministic across runs (same inputs → same hash).
- [ ] CSV exports include the active filters in the filename.
- [ ] Audit-log fields masked where sensitive (secret / URL).

### Cross-dashboard coherence
- [ ] Severity / KEV / Priority badges identical to the rest of the
  app.
- [ ] Filter chips match across all four dashboards.
- [ ] Drill-down preserves the global filter set.

---

## 6. Recommendation

### First to implement: **B — SOC Prioritization**

1. **Highest immediate value** for the smallest effort. The Sprint 1-3
   backend (priority score, KEV, EPSS, vulnx PoC/Nuclei flags) is
   already there — B is mostly a frontend job.
2. **Single user, single decision per click.** Easiest to validate
   with real users.
3. **Defines the IA primitives** (sidebar, global filter bar, URL
   state) that the other three dashboards reuse.
4. **No new heavy backend** — reuses `/api/cves` and `/api/findings`
   with at most three small additions.

### Second to implement: **D — Remediation & Governance**

1. The Sprint 3 backend (`risk_acceptances`, `audit_log`, `sla`,
   `mttr`) was built but is **not yet exposed** to users. Building D
   activates that investment.
2. Aligns the platform with audit / compliance use cases — opens
   doors with governance / legal stakeholders.
3. The kanban pattern is forgiving: even with limited findings the
   visual still works.

### Third: **C — Asset & Product Exposure**

1. Best value once the inventory has > 50 distinct products. Earlier
   it shows mostly empty space.
2. Requires modest new aggregation endpoints.

### Fourth: **A — Executive Risk Overview**

1. Needs at least 30 days of snapshot data to be credible.
2. PDF export is a non-trivial backend addition.
3. By the time A ships, the team has B / C / D operational and the
   executive narrative has substance to draw on.

### Why this order

* Avoids the trap of building a "vanity executive dashboard" before
  the operational data is meaningful.
* Each step builds on the previous one (shell + filters → audit
  surface → aggregation → trend).
* Maximises probability that the dashboards are *used* rather than
  *demoed*.

---

*End of design proposal. Discuss → choose → kick off Sprint
Dashboards 1.*
