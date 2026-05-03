# Frontend Review — CVE Management Platform

**Date:** 2026-05-03
**Reviewer:** Senior Frontend Architect + UX/UI + QA persona
**Stack reviewed:** Next.js 14 App Router · React 18 · Tailwind 3.4 · recharts · axios · jspdf
**Scope:** `frontend/src/**` end-to-end, all components, layout, design system, accessibility surface, clickability.

---

## Executive summary

The frontend ships the basic dashboard a SOC analyst needs (KPIs, products, CVE
table, NVD/CIRCL live search, settings) but the experience is a **single-page
modal-driven prototype** rather than a tool optimised for triage. Three
strategic gaps stand out:

1. **Coverage gap.** The backend exposes findings lifecycle (status FSM),
   webhooks, risk acceptance, SLA / MTTR (Sprint 3) and live exploitability
   intel (Sprint 1 P3 + Sprint 2 P6) — but the UI offers **no Findings tab,
   no SLA board, no Webhook manager, no Risk-Acceptance flow, no inventory
   distinction Software vs OS**. The platform under-uses what the backend
   already provides.

2. **Clickability gap.** Multiple visual elements look interactive but
   aren't (KPI tiles, severity pie slices, timeline bars, single-emoji
   columns). The asymmetry "looks like a button → does nothing" is the
   number-one usability complaint. Conversely, several real interactions
   (CSV drop zone, badge filters in CVEDetailModal, status buttons hidden
   under modal scroll) lack obvious affordance.

3. **Architecture gap.** A single 165-line `page.jsx` uses tab-state to
   route. There is no `AppShell`, no sidebar, no breadcrumb, no
   `PageHeader`, no shared `EmptyState` / `ErrorState` /
   `LoadingSkeleton` primitives, no shared `Badge` family. Every component
   re-implements the same patterns with slight drift.

The build is functional and the visual language (dark indigo on slate) is
coherent enough; with a focused 4-sprint redesign (see
`FRONTEND_REDESIGN_PROPOSAL.md`) the platform can move from
"informative but cluttered" to "actionable for SOC triage".

---

## 1. Stack & structure

| Aspect | State |
|---|---|
| Framework | Next.js 14 App Router (file-based routing **not used**: app has 1 `page.jsx`) |
| Language | JavaScript (.jsx); no TypeScript |
| Styling | Tailwind 3.4 utility classes (no design tokens, no shared component library) |
| Charts | recharts |
| HTTP | axios via `lib/api.js` |
| State management | Local `useState` + props drilling — no global store |
| Routing | Tab state in `page.jsx`, no URLs ⇒ no deep-linking, no shareable filters |
| Tests | none (no `package.json` test script, no eslint, no typecheck) |
| Build | only `next dev` / `next build` / `next start` |
| Accessibility | ad-hoc; some `aria-label`, no focus traps in modals, missing roles, no keyboard shortcuts |

### Folder layout

```
src/
  app/{layout,page,globals.css}.jsx         # single page
  lib/{api,utils}.js                        # API client + format helpers
  components/
    Dashboard/{StatsBar, SeverityChart, TimelineChart}.jsx
    Products/{ProductsGrid, AddProductModal}.jsx
    CVE/{CVETable, CVEFilters, CVEDetailModal, ExportButtons}.jsx
    LiveSearch/{LiveSearchPanel, Exploitability}.jsx
    Settings/{SettingsPanel, ApiStatusGrid, ApiStatusCard, ConfigTable}.jsx
```

No `AppShell`, `Layout`, `Drawer`, `Page` primitives. Settings panel mounts
always but renders `null` when `active=false` (anti-pattern: should mount
conditionally).

---

## 2. Blocking usability issues

| #  | Issue                                                                                  | Where                                            |
|----|----------------------------------------------------------------------------------------|--------------------------------------------------|
| B1 | No way to view **Findings** with status / SLA / due-date / risk-acceptance             | nowhere in UI (backend exposes `/api/findings/*`) |
| B2 | No way to **manage Webhooks** (create/test/deliveries log)                             | nowhere                                          |
| B3 | No way to **request / approve risk acceptance**                                        | nowhere (only finding status buttons in modal)   |
| B4 | No **SLA board** (breached / at_risk lists, MTTR)                                       | nowhere                                          |
| B5 | No **Operating-System vs Software** distinction in Inventory                            | ProductsGrid mixes both                          |
| B6 | KPI cards (StatsBar) and chart elements look clickable but **don't filter**             | StatsBar, SeverityChart, TimelineChart           |
| B7 | The "**Cerca NVD Live**" tab now also hosts vulnx Exploitability, mixing 5 incompatible modes (keyword / cpe / circl / id / exploit) | LiveSearchPanel |
| B8 | Inventory upload CSV is **buried** inside `+ Aggiungi` modal → CSV tab → drop area; first-time user can't find it | AddProductModal |
| B9 | The "drop zone" in CSV upload has cursor-pointer + click-to-open but **no real drag-and-drop handler** | AddProductModal |
| B10| **Refresh button ↻** in header has no loading state, no label, no tooltip               | `app/page.jsx`                                   |
| B11| **30s auto-refresh** invisible — analyst can't tell data is live or stale               | `app/page.jsx`                                   |
| B12| No deep-linking on filters / selected product / open CVE — refresh of browser **loses state** | router-less                                |
| B13| Modals have no focus-trap and no Escape-to-close                                        | AddProductModal, CVEDetailModal                  |
| B14| No global error boundary; an axios failure in StatsBar leaves the whole row blank silently | All Dashboard children                        |
| B15| No empty state on dashboard when there are zero products                               | only inside ProductsGrid; rest of dashboard is bare |

---

## 3. Visual issues

| # | Issue | Where |
|---|---|---|
| V1 | KPI tiles styled identically to clickable cards but not actionable | StatsBar |
| V2 | Severity pie slices have hover tooltip but no click filter | SeverityChart |
| V3 | Timeline bars same as V2 | TimelineChart |
| V4 | The "🔴" emoji in CVETable KEV column is a literal character with only `title=` — invisible to keyboard users, ambiguous (red dot ≠ semantic) | CVETable |
| V5 | Match column shows just ✓ or ~ → cryptic without legend | CVETable |
| V6 | Status buttons in CVEDetailModal (`open`, `in_review`, `false_positive`, `accepted_risk`, `planned`, `remediated`, `closed`) are 7 toggles in one row → visually noisy | CVEDetailModal |
| V7 | Many emoji used inconsistently as icons (📊 🔍 ⚙ 🔴 ⟳ ✕ 📂 ↻ ✓ ~) — locale-pack & accessibility risk | All components |
| V8 | Tailwind buttons lack a consistent focus-visible ring — keyboard users cannot tell what is focused | All buttons |
| V9 | "+ Aggiungi" button is a small primary action against 6 large stats above; visual hierarchy mismatched | ProductsGrid |
| V10| Selected-product chip (`indigo bg + ✕ rimuovi`) appears above filters but is also embedded with filters — duplicates location | `app/page.jsx` |
| V11| `LiveSearchPanel` re-implements its own results table (separate from `CVETable`) → drift in styling | LiveSearchPanel |
| V12| Exploitability tab inside LiveSearchPanel hides the rest of the panel chrome (severity filters, etc.) but doesn't actually need to live there | LiveSearchPanel |
| V13| Source badges in CVETable use country-flag-like emoji (📦 / 🔴 / 🔵) — semantics unclear | CVETable |
| V14| `confidenceBadge` returns identical class for `cpe_search` and `certain` but distinct title only — invisible difference | utils.js |

---

## 4. Navigation issues

| # | Issue |
|---|---|
| N1 | No sidebar / left rail; only 3 top tabs (Dashboard, Live, Settings). Adding Findings, Webhooks, Reports = expand top tabs to 6+ horizontally — won't scale |
| N2 | No URL routes ⇒ no back-button, no shareable links |
| N3 | No breadcrumb in detail views (CVE detail is a modal, not a page) |
| N4 | "Cerca NVD Live" label inaccurate (now covers 5 sources) |
| N5 | Tab state lives inside `page.jsx`; sub-tabs (Live's 5 modes, Settings sections) live in their own state — no consistent "where am I" |
| N6 | Refresh button refreshes only Dashboard endpoints, not CVE list — surprising |
| N7 | Selected product is shown as a chip but tapping a different product also un-toggles selection by clicking the same item twice — non-obvious |

---

## 5. Clickability issues

See dedicated section §10 below.

---

## 6. Feedback gaps

| # | Issue |
|---|---|
| F1 | After PATCH finding status, the modal gives no toast / banner — only the button updates colour |
| F2 | After CSV import, only a 3-column counter is shown — no list of failed rows beyond raw count |
| F3 | After PDF export, no success / error toast (alert() used in catch block) |
| F4 | After re-sync of a product, "↻" runs but no spinner; the row badge updates after a 2s setTimeout — fragile |
| F5 | Errors from axios are surfaced as `err.response?.data?.error || err.message` but the rendering varies (`<p className=red-400>` in some forms; nothing in others) |
| F6 | No global toast system; each component reinvents inline messaging |
| F7 | Empty-state copy is inconsistent ("Nessun CVE nel database locale.", "Nessun prodotto. Aggiungi…") — both useful but visually dissimilar |

---

## 7. Coherence problems

| # | Issue |
|---|---|
| C1 | Three different `Priority` visualisations: a tiny bar in `CVETable.PriorityBar`, a card in `CVEDetailModal.PriorityCard`, a stacked horizontal bar in `Exploitability.Factors` |
| C2 | Severity rendering: `severityBg(...)` used in CVETable + CVEDetailModal + LiveSearchPanel — same function but each calls a slightly different markup wrapper |
| C3 | `confidenceBadge(...)` used in CVETable + CVEDetailModal — but `cpe_search` vs `certain` produce visually identical output |
| C4 | `Match` icons (✓ / ~) vs `Source` icons (📦 / 🔴 / 🔵) — different semantics, same row, no header-level legend |
| C5 | Status buttons style in CVEDetailModal `STATUS_OPTIONS` differ from any other "filter chip" pattern in the rest of the app |
| C6 | `severityColor` (text only) and `severityBg` (text + bg + border) — used inconsistently across components |
| C7 | LiveSearchPanel re-defines its own `PriorityMini` instead of reusing `CVETable.PriorityBar` |

---

## 8. Responsive issues

| # | Issue |
|---|---|
| R1 | Header `max-w-screen-2xl px-6` is fine on desktop; tabs do not collapse on mobile (overflow-x not handled) |
| R2 | `lg:grid-cols-4` on dashboard collapses to 1 column on `<lg`, but the products list (max-h 420px) and timeline chart compete for vertical space |
| R3 | `CVETable` has `overflow-x-auto` but 10 columns make horizontal scroll the default on tablets; no priority-column hide |
| R4 | `CVEDetailModal` is `max-w-3xl max-h-90vh` — on phones it fills the screen but the close button only sits inside the modal, no close-on-Escape |
| R5 | Filters bar wraps with `flex-wrap` — at 768-1024px width the date pickers and select boxes line-break unevenly |
| R6 | Settings cards (`md:grid-cols-2 lg:grid-cols-3`) work, but ApiStatusCard's "Test" button is at the bottom-right and on small width pushes the latency number below |
| R7 | `LiveSearchPanel` mode tabs (`flex bg-gray-800 rounded-lg`) overflow horizontally on narrow widths |

---

## 9. Accessibility issues

| # | Issue |
|---|---|
| A1 | No `<main>`, `<nav>`, `<aside>` semantic landmarks (only `<header>` and `<main>` in `page.jsx`) |
| A2 | Tabs in header use `<button>` (good) but lack `role="tab"`, `aria-selected`, `aria-controls`, focus management |
| A3 | Modals don't trap focus; pressing Tab leaves the modal |
| A4 | Modals don't restore focus to the opener on close |
| A5 | No `aria-label` on the global Refresh button (only the icon "↻") |
| A6 | KEV indicator (🔴) — single emoji has no text alternative |
| A7 | Confidence (✓/~) — same as A6 |
| A8 | `cursor-pointer` applied to non-interactive `<div>`s (e.g. ProductsGrid items use `<div onClick>` instead of `<button>`) ⇒ not in tab order |
| A9 | CSV drop zone is a `<div>` with `onClick` — keyboard users can't activate |
| A10| Some buttons rely solely on colour to convey state (filter active vs inactive) |
| A11| No `prefers-reduced-motion` respect; pulse / spin animations always on |
| A12| Form `<label>`s in `Field` component don't use `htmlFor`/`id` linkage |

---

## 10. CLICKABILITY_ISSUES

| File | Component | Element | Problem | Current behaviour | Expected | Severity | Fix |
|---|---|---|---|---|---|---|---|
| `Dashboard/StatsBar.jsx` | StatsBar | The 6 KPI tiles | Tile look is identical to clickable cards (rounded-xl + border + colour) | static `<div>` | Click → filter CVE list (e.g. "Critical" tile filters severity=CRITICAL) — or remove the card border/hover | MAJOR | Convert to `<button>` and propagate filter; OR remove rounded-border styling so they look static |
| `Dashboard/SeverityChart.jsx` | SeverityChart | Pie slices | Tooltip on hover suggests interactivity | recharts pie segment, no `onClick` | Click slice → filter CVE table by severity | MAJOR | Add `onClick={(e) => onSliceClick(e.name)}`, lift filter to parent |
| `Dashboard/TimelineChart.jsx` | TimelineChart | Bars | Hover highlights but no click | static | Click bar → filter CVE table by month + severity stack | MAJOR | Wire `onClick` on `<Bar>` |
| `CVE/CVETable.jsx` | KEV column | 🔴 emoji | Looks decorative; only `title` attr | static span | Render proper `<KevBadge>` with text "KEV" + tooltip; ideally a filter shortcut "show only KEV" | MAJOR | New `<KevBadge clickable onClick={...}>` |
| `CVE/CVETable.jsx` | Match column | ✓ / ~ | Single character; meaning unclear | static badge | Replace with `<MatchBadge confidence>` showing "Confirmed" / "Uncertain" + icon | MAJOR | Replace with explicit text badge |
| `CVE/CVETable.jsx` | Source column | 📦 NVD / 🔴 CIRCL / 🔵 VulnCheck | Emoji-flag confusing | static span | Use icon-stable component (`<SourceBadge source>`) with consistent colour and text | MINOR | Replace emoji with text-only badge or stable Lucide icon |
| `Products/ProductsGrid.jsx` | Product card | Whole `<div>` | Uses `<div onClick>` with `cursor-pointer` and hover; not in tab order, no keyboard | clickable but inaccessible | Convert to `<button>` (or `<a>` to `/products/{id}`) so it joins the focus order | MAJOR | Refactor wrapper element |
| `Products/ProductsGrid.jsx` | Sync / Delete actions | "↻" / "✕" icons inside card | Only visible on `group-hover` ⇒ keyboard users never see them | hidden until hover | Always visible at sm or behind a kebab menu | MAJOR | Show always at md, drop the `opacity-0 group-hover:opacity-100` |
| `Products/AddProductModal.jsx` | CSV Drop zone | Full `<div>` | "Clicca o trascina" but only `onClick` is wired (no `onDrop`) | only opens file picker | Add proper `onDragOver`/`onDrop` and adjust copy if drag not implemented | MAJOR | Implement DnD or change copy to "Clicca per selezionare" |
| `Products/AddProductModal.jsx` | CPE example button | Looks like underlined link | Actually a `<button>` that fills the input | works | Style as obvious "Use example" button | MINOR | Change wrapper class to button-styled |
| `CVE/CVEDetailModal.jsx` | Status buttons (7) | 7 toggles in a row | Visually noisy | functional | Group into a `<select>` or a prominent "Change status →" dropdown; keep history visible | MAJOR | Replace with a compact `StatusPicker` |
| `CVE/CVEDetailModal.jsx` | Backdrop | `<div onClick={onClose}>` | Closes modal but no Escape key | works | Add `useEffect` keydown handler for Escape | MAJOR | Add Escape handler + focus trap |
| `app/page.jsx` | Header `↻` button | Single emoji | No tooltip, no loading state | works | Add `aria-label="Refresh data"`, show spinner during fetch | MAJOR | Wrap in a `<RefreshButton>` primitive |
| `app/page.jsx` | Selected-product chip "✕ rimuovi" | Looks like text but is button | Functional | Already works | Convert to a uniform chip with `<X>` icon and consistent style | MINOR | Replace with `<FilterChip>` primitive |
| `LiveSearch/LiveSearchPanel.jsx` | Mode tabs | Pill toggles | Now 5 modes — narrow widths overflow | overflow-x not handled | Add overflow-x-auto OR migrate to dropdown on small | MAJOR | Add scroll container |
| `LiveSearch/LiveSearchPanel.jsx` | Result rows | clickable rows | Use `<tr onClick>` ⇒ keyboard cannot activate | clickable | Add `tabIndex={0}` + `onKeyDown` for Enter/Space, OR wrap row id in a button | MINOR | Add keyboard support |
| `LiveSearch/Exploitability.jsx` | Affected-products rows | `<tr onClick>` opens detail | Same as above | clickable | Same fix | MINOR | Add keyboard support |
| `Settings/SettingsPanel.jsx` | Conditional render via `active` prop | Mounted always; renders null if inactive | wastes a render and hooks effect | works | Mount conditionally from `app/page.jsx` like other tabs | MINOR | Remove `active` prop, render only when `tab==='settings'` |
| `Settings/ConfigTable.jsx` | Tooltip ⓘ icon | Inline helper | Only shows on hover (no focus) | works on mouse | Trigger on focus-within too | MINOR | Add `onFocus`/`onBlur` |
| `CVE/ExportButtons.jsx` | PDF button error | Uses `alert(...)` | Modal dialog | works | Use the same toast / error inline as other components | MINOR | Replace with toast |
| `CVE/CVEFilters.jsx` | KEV button | Toggles `kev` filter | OK | works | Add tooltip "Show only CISA KEV CVEs" + `aria-pressed` | MINOR | Add a11y attrs |
| `CVE/CVEFilters.jsx` | Reset button | Visible when "any value not 1/50" | Heuristic, brittle | works most of the time | Compute "any non-default" explicitly | MINOR | Refactor predicate |
| `Dashboard/StatsBar.jsx` | KPI tile colours | Different bg per severity | Visual but no semantics | decorative | Either make clickable filters or unify to neutral cards | MAJOR | See first row above |
| `Dashboard/SeverityChart.jsx` | Legend | None present | recharts default omitted | works | Add `<Legend>` with click-to-toggle visibility | MINOR | Pass `<Legend onClick>` |
| `app/page.jsx` | Auto-refresh `setInterval(loadDashboard, 30000)` | No visual indicator | Silent | confusing | Show a small "Last refreshed 14s ago" with progress | MINOR | Lift state from `loadDashboard` |

---

## 11. Priorità di intervento

### P0 — Must fix before next release
- B1, B2, B3, B4 (missing core surfaces — Findings / Webhooks / Risk / SLA)
- B6 + V1-V3 (KPI / chart fake-clickable surfaces)
- A3, A4, A6, A7, A8 (accessibility)
- B13 (modal Escape + focus trap)

### P1 — Strong UX uplift
- N1, N2 (introduce sidebar + URL routes)
- C1-C7 (consolidate Badge primitives into a design system)
- F6 (global toast system)
- B5 (Inventory split: Software vs OS)
- V8 (focus-visible rings)

### P2 — Polishing
- V7 (replace emoji icons with consistent Lucide icons)
- R1-R7 (responsive tightening)
- F4, F5 (sync feedback consistency)
- A1, A2 (semantic landmarks + tab roles)
- N6 (refresh scope semantics)

---

*See `FRONTEND_REDESIGN_PROPOSAL.md` for the target IA and component
model, `FRONTEND_IMPLEMENTATION_PLAN.md` for the 4-sprint plan, and
`FRONTEND_VALIDATION.md` for what was verified in this session.*
