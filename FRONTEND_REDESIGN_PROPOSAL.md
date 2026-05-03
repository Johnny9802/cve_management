# Frontend Redesign Proposal — CVE Management Platform

**Date:** 2026-05-03
**Audience:** SOC analyst / vulnerability analyst / engineering manager
**Goal:** transform the current single-page prototype into a triage-grade
console where the "what should I patch first today?" question gets
answered in ≤ 30 s.

---

## 1. Information architecture

### Top-level navigation (left sidebar, collapsible)

```
┌──────────────────────────────────────────────────────────────┐
│  CVE Management  ▾                                           │
│                                                              │
│  ▌ 📊  Dashboard            ← landing                        │
│  ▌ 📦  Inventory            (Software, OS)                   │
│  ▌ 🛡️   Findings             (Open · In review · Risk · SLA)  │
│  ▌ 🧬  CVE Intelligence     (catalog + detail)               │
│  ▌ 🎯  Live Exploitability  (single-CVE intel)               │
│  ▌ 📤  Webhooks             (CRUD + deliveries)              │
│  ▌ 📈  Reports              (SLA / MTTR / export)            │
│  ▌ ⚙️   Settings             (provider keys, sync, status)    │
└──────────────────────────────────────────────────────────────┘
```

### Hierarchy

```
Dashboard           = synthesis (no detail)
    │
Inventory           = source of truth
    └─ Product detail (drawer)
Findings            = action queue
    └─ Finding detail (drawer)
        └─ Risk acceptance (sub-drawer / inline form)
CVE Intelligence    = browsing
    └─ CVE detail (full page or large drawer)
Live Exploitability = single-CVE deep dive
Webhooks            = administration
Reports             = read-only summaries
Settings            = configuration
```

### Breadcrumb

Every detail page: `Findings › CVE-2024-1234 (nginx 1.18.0)` — clickable
back-segments. Drawers have an explicit "View as page →" anchor when the
URL deep-links to the same content.

### URL routes (Next.js file-based routing)

```
/                                 → Dashboard
/inventory                        → Inventory list
/inventory?type=os                → Inventory filtered (Software | OS)
/inventory/[productId]            → Product detail (pushed page)
/findings                         → Findings list (default tab: open)
/findings?status=accepted_risk    → tab filter
/findings/[productId]/[cveId]     → Finding detail
/cves                             → CVE catalog
/cves/[cveId]                     → CVE detail
/cves/[cveId]/intel               → Live Exploitability (deep link)
/webhooks                         → Webhooks
/webhooks/[id]/deliveries         → Delivery log
/reports/sla                      → SLA report
/reports/mttr                     → MTTR
/settings                         → Settings
```

URL = state ⇒ deep-linking, browser-back, shareable.

### Primary user flows

```
SOC analyst — Mon 09:00 triage
  Dashboard (KEV breached today: 3)
   → click "3" KPI ⇒ /findings?sla_state=breached&kev=true
   → row click ⇒ /findings/12/CVE-2024-1234 (drawer)
   → "Mark in_review", assign owner, set due_date or request risk
   → close drawer ⇒ back to filtered list

Manager — review pending risk acceptances
  Sidebar > Findings > tab "Risk acceptance"
   → table of pending / approved / rejected
   → "Approve" ⇒ confirmation dialog ⇒ writes audit_log

Onboarding — first-time analyst
  Dashboard with empty state and big "Upload inventory" CTA
   → /inventory upload CSV (drag&drop)
   → auto-redirect to /inventory once parsed
   → real-time sync progress per row

Live drill-down on a CVE seen elsewhere
  Anywhere ⇒ keyboard `g i` (or top-bar "Go to CVE…") ⇒ /cves/CVE-2024-1234
  Or ⇒ "🎯 Live Exploitability" sidebar entry, paste id, refresh=true
```

---

## 2. Page-by-page structure

### 2.1 Dashboard

**Above the fold (no scroll, ≤ 1.5 cards depth):**

```
┌─────────────────────────────────────────────────────────────────────┐
│ TopBar                                                              │
├─────────────────────────────────────────────────────────────────────┤
│ Today (2026-05-03)                                                  │
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│ │ KEV in    │ │ SLA       │ │ Critical  │ │ Findings  │ │ Active  │ │
│ │ inventory │ │ breached  │ │ priority  │ │ open      │ │ webhook │ │
│ │   23      │ │   8       │ │   42      │ │  316      │ │  fail   │ │
│ │ ↗ +3 7d   │ │ ↗ +2 24h  │ │ ↘ -5 24h  │ │ —         │ │   1     │ │
│ └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│ Each KPI tile = clickable; opens the corresponding filtered list    │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────┐ ┌──────────────────────────────┐
│ Top 10 urgent findings           │ │ KEV urgency board            │
│ (priority desc)                  │ │ - 3 due in 7d                │
│ - row click ⇒ /findings/.../...  │ │ - 5 due in 30d               │
└──────────────────────────────────┘ └──────────────────────────────┘

┌──────────────────────────────────┐ ┌──────────────────────────────┐
│ Last 7 days exploitability       │ │ Recent uploads               │
│ delta — CVEs with new PoC/Nuclei │ │ (parsed N rows, sync N CVEs) │
└──────────────────────────────────┘ └──────────────────────────────┘
```

* All KPIs are interactive (filter shortcuts).
* No pie-chart/timeline at top (moved to /reports). Dashboard tells
  you *what to do* — not *the shape of the catalog*.
* "Last refreshed 12s ago" + manual refresh + 30s auto-refresh
  indicator.

### 2.2 Inventory

**Tabs:** Software · Operating Systems
**Filters bar:** vendor, version, severity (max), confidence, only-with-findings
**Upload CSV:** prominent drop zone always visible at top when empty;
when populated, moves to a "+ Import" button + drawer.

```
┌─────────────────────────────────────────────────────────────────┐
│ Inventory                  [+ Add product]  [⤓ Import CSV]      │
├─────────────────────────────────────────────────────────────────┤
│ [ Software (47) ] [ Operating Systems (12) ]                    │
│ FilterBar: vendor / version / sync status / has_findings        │
├─────────────────────────────────────────────────────────────────┤
│ DataTable (Product, Vendor, Version, CPE, Sync, Findings, KEV)  │
│ Row click ⇒ /inventory/{id} (drawer w/ findings list & re-sync) │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Findings

**Tabs:** Open · In review · Planned · Accepted risk · Remediated · SLA breached
**Bulk actions:** mark in_review, set owner, change due_date, export CSV.
**Each row:**

```
[priority badge] CVE-XXXX  product version  KEV?  PoC  Nuclei  due_date  status  owner
                                                                          ↑
                                                      cliccando questa colonna
                                                      apre StatusPicker chip
```

Drawer su row click: full finding detail con status FSM, due-date picker,
risk-acceptance form, history audit, link al CVE detail.

### 2.4 CVE Intelligence

**Filter bar:** severity, KEV, EPSS≥, has_poc, has_nuclei, year, keyword,
priority≥. All filters are persisted in URL query.
**Quick chips** on top: KEV only / EPSS≥0.5 / PoC available / Nuclei template.
**Row click ⇒ /cves/[id]** (full page CVE detail, not modal).

### 2.5 Live Exploitability

Standalone page (not a tab inside LiveSearch):

```
┌─────────────────────────────────────────────────┐
│ Live Exploitability               [refresh=on]   │
│ [ CVE-2024-1234 ] [ Cerca ]                      │
├─────────────────────────────────────────────────┤
│ <CveDetailPanel>                                 │
│   Header (severity / priority / KEV / freshness) │
│   Description                                    │
│   Exploitability section (PoC / Nuclei / EPSS)   │
│   Priority breakdown (factors)                   │
│   Affected products in inventory (mini-table)    │
│   References                                     │
└─────────────────────────────────────────────────┘
```

### 2.6 Webhooks

**Page:** list of webhooks with badge "✅ healthy / ⚠ failed / ⏸ disabled".
**Drawer per webhook:** edit URL/secret/event_types/min_priority, **Test
button**, delivery log (last 50 attempts).
**Empty state:** wizard "What is a webhook? + Create your first one".

### 2.7 Reports

**Pages:** SLA summary · MTTR · Trend (uses data from Sprint 3 endpoints).
Each page: KPIs + chart + downloadable CSV/PDF.

### 2.8 Settings

**Sections:** Provider status (cards) · API keys (config table) · Sync
jobs (start/stop, last run) · About (version, contact).

---

## 3. Component model

### Shell components
- `<AppShell>` — sidebar + topbar + page content + global toast portal
- `<Sidebar>` — collapsible nav with active route highlight
- `<TopBar>` — breadcrumb + global "Go to CVE…" search + refresh + last-refreshed hint
- `<PageHeader>` — title, subtitle, primary action(s)

### Data display
- `<KpiCard variant="clickable|static" trend?>`
- `<DataTable columns rows onRowClick? sort onSort emptyState loadingState>`
- `<FilterBar>` + `<FilterChip removable onRemove>`
- `<DetailDrawer side="right" widthRatio={0.5}>`
- `<EmptyState icon title body action?>`
- `<ErrorState title body retryAction?>`
- `<LoadingSkeleton type="row|card|chart">`

### Domain badges (consolidated)
- `<SeverityBadge severity size>`
- `<KevBadge clickable?>`  (small red pill "KEV")
- `<EpssBadge value>` (e.g. `EPSS 87% (P99)`)
- `<ExploitabilityBadge poc nuclei size>` (combined PoC+Nuclei pill)
- `<PriorityScoreBadge score variant="compact|full|breakdown">`
- `<FindingStatusBadge status size>` (covers all 7 FSM statuses)
- `<SourceBadge source>` (replace emoji with text)
- `<SlaBadge state="met|on_track|at_risk|breached">`
- `<MatchBadge confidence>` (replace ✓/~ with explicit text)

### Domain panels
- `<CveDetailPanel cveId>` — used by /cves/[id] page AND by Live Exploitability AND by Finding drawer
- `<ProductDetailPanel productId>` — used by /inventory/[id] page AND by drawer
- `<FindingDetailPanel finding>` — full FSM, audit history, risk-acceptance form
- `<RiskAcceptanceForm finding mode="request|review">`
- `<WebhookForm mode="create|edit" onTest>`

### Interaction primitives
- `<RefreshButton ariaLabel onClick busy>`
- `<ConfirmDialog title body destructive? onConfirm onCancel>`
- `<Toast type=info|success|warning|error message />` via `<ToastProvider>`
- `<KbdShortcut keys=["g","i"] description>` (hint in topbar `?` modal)

### Layout primitives
- `<Drawer>`, `<Modal>` — both with focus trap + Escape + restore-focus
- `<TabGroup tabs activeKey onChange>` (URL-aware)
- `<Tooltip placement>`

---

## 4. Interaction rules (design law)

These are non-negotiable rules every component must satisfy:

1. **Clickable affordance.** If an element has hover/cursor-pointer it
   MUST do something; if it does something it MUST have hover/cursor-pointer.
2. **Card hover = card click.** A card with hover effect must be
   click-or-keyboard activable. Otherwise drop the hover.
3. **Row click = open detail.** A `<DataTable>` row that is clickable
   uses `<tr role="button" tabIndex={0}>` plus `cursor-pointer` plus a
   hover background. Pressing Enter/Space must trigger the click.
4. **Badges that filter** are visually pillsh, with `aria-pressed`,
   `cursor-pointer`, hover halo, and a tooltip "Click to filter by …".
5. **Badges that inform** (severity, KEV) are flat, no hover, no
   cursor-pointer; they get a tooltip with the meaning of the value.
6. **Every action button** has: `loading` state, `disabled` reason
   tooltip, success/error toast.
7. **Destructive action** (delete product, delete webhook, reject risk
   acceptance) goes through `<ConfirmDialog>` with explicit "Type
   {name} to confirm" for catastrophic ones.
8. **External link** has `<ExternalLinkIcon>` next to label and opens
   in a new tab with `rel="noopener noreferrer"`.
9. **Disabled element** must have `title` or `aria-describedby`
   explaining why it is disabled.
10. **Modals & drawers** trap focus, close on Escape, restore focus on
    close, never reuse the page scroll.
11. **Empty / Loading / Error states** are mandatory for every list and
    detail surface — no blank screen ever.
12. **No silent auto-refresh** — show "Last refreshed X ago" + spinner
    when refreshing.
13. **Filters in URL** — every list page reflects state in query string.
14. **Reduced motion** — `prefers-reduced-motion` disables pulses /
    spins / animations.
15. **Focus rings** — every interactive element has `focus-visible:ring-2 ring-indigo-500 ring-offset-2`.

---

## 5. Visual hierarchy

| Layer | Goes here | Example |
|---|---|---|
| Top of page (above fold) | The single thing the analyst should act on now | "8 SLA breached today" |
| Mid page | Working surface | finding table, CVE list |
| Detail drawer / page | Full context once user has selected a row | priority breakdown, history, references |
| Footer-level | Operational metadata | sync state, last refreshed |

**Risk vs priority distinction**: badges separate
- Technical risk (severity / CVSS) → red/orange/yellow/blue
- Operational priority (priority_score 0-100) → indigo gradient with
  numeric label
- SLA pressure → distinct (purple → urgent / amber → at risk)

The three never share the same colour on the same page.

---

## 6. SOC analyst workflow

```
1. open  /                       — dashboard
2. see   "8 SLA breached" KPI    — click
3.        /findings?sla=breached
4. row click on the highest-priority breach
5.        drawer with finding detail (left half remains list)
6. see   priority breakdown + affected product version + history
7. set   status=in_review, owner=me, due_date= today + 7
8. or    request risk-acceptance with justification
9. close drawer (or `Esc`)
10. ⇒ row updates without a full reload
11. when done with the queue, navigate to /reports/sla to file the
    weekly summary, click "Export PDF"
```

Every step has < 2 clicks and a clear visual feedback.

---

## 7. Design principles

1. **Less noise.** One purpose per screen; the analyst can name what
   she is doing without reading the title.
2. **Priorities are loud, severity is calm.** Priority is the action
   signal; severity is the technical context.
3. **Click-affordance integrity.** No element looks like a button if it
   isn't.
4. **Progressive disclosure.** The list shows the seven things needed
   to triage; the drawer shows the rest.
5. **Persistent filters.** State lives in the URL; analysts share links.
6. **Coherent badges.** A `<KevBadge>` looks the same in every page; a
   `<PriorityScoreBadge>` always renders the same way for the same
   value.
7. **Accessibility first.** Keyboard, screen reader, reduced motion,
   focus rings, semantic HTML.
8. **Never silent.** Every action gives feedback within 250 ms (skeleton
   or toast).

---

*Implementation roadmap: see `FRONTEND_IMPLEMENTATION_PLAN.md`.*
