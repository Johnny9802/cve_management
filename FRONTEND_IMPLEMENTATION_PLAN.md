# Frontend Implementation Plan — 4 sprints

**Date:** 2026-05-03
**Reference docs:** `FRONTEND_REVIEW.md`, `FRONTEND_REDESIGN_PROPOSAL.md`
**Stack constraints:** keep Next.js 14 + Tailwind + recharts + axios.
No new heavy library unless justified. No TypeScript migration in this
plan (separate decision).

Sprints are sized to land in 1-2 working weeks each.

---

## Sprint Frontend 1 — UX foundations

**Objective:** establish a coherent shell, the design-system primitives
and clean up clickability; do NOT change information architecture yet
to avoid breaking existing flows during the rollout.

### Components / files
- NEW   `src/components/Shell/AppShell.jsx`
- NEW   `src/components/Shell/Sidebar.jsx`
- NEW   `src/components/Shell/TopBar.jsx`
- NEW   `src/components/Shell/PageHeader.jsx`
- NEW   `src/components/UI/Badge/{Severity,Kev,Epss,Exploitability,PriorityScore,FindingStatus,Source,Sla,Match}.jsx`
- NEW   `src/components/UI/Button/{Button,RefreshButton,IconButton}.jsx`
- NEW   `src/components/UI/Feedback/{Toast,ToastProvider,EmptyState,ErrorState,LoadingSkeleton}.jsx`
- NEW   `src/components/UI/Overlay/{Modal,Drawer,ConfirmDialog,Tooltip}.jsx`
- NEW   `src/components/UI/Form/{TextField,Select,Textarea}.jsx`
- NEW   `src/lib/keyboard.js` (Esc handler hook, focus trap)
- NEW   `src/lib/url-state.js` (read/write URLSearchParams)
- NEW   `src/styles/tokens.css` (CSS custom properties for spacing / radii / focus-ring)
- EDIT  `src/app/globals.css` — add focus-visible ring utility, reduced-motion
- EDIT  `src/app/layout.jsx` — wrap with `<ToastProvider>`
- EDIT  `src/app/page.jsx` — use `AppShell`; keep current top tabs as
  routes mapped to same content (no IA change yet)

### Clickability fixes
- StatsBar — convert tiles into proper `<KpiCard variant="static">`
  for now (no filter wiring yet, but remove faux affordance)
- ProductsGrid items — convert root `<div>` to `<button>`
- AddProductModal CSV drop zone — wire `onDragOver` / `onDrop` for
  real drag&drop or change copy if not implementing
- CVE table KEV column — render `<KevBadge>` instead of raw emoji
- CVE table Match column — render `<MatchBadge>` instead of `~/✓`
- CVE table Source column — render `<SourceBadge>` instead of emoji
- Header refresh — `<RefreshButton aria-label busy>`
- Modals — Escape handler + focus trap via `useFocusTrap`
- Status buttons in CVEDetailModal — replace with compact
  `<FindingStatusPicker>` that uses `<FindingStatusBadge>`

### Risks
- Sidebar collapse on small screens may break first-time-user flow:
  ship behind a feature flag `sidebar` toggle for one release if
  conservative.
- Keyboard focus trap in modals can break native form interactions if
  badly implemented — use `react-focus-trap` or a vetted pattern.

### Tests
- Manual: each Badge family renders in isolation in `/devtools` test
  page (gated by env var) — basic render test.
- Manual: keyboard Tab order across header → sidebar → main → modal.
- Smoke: run `npm run build` and verify no warning regression.

### Acceptance criteria
- No element on the dashboard has cursor-pointer or hover bg unless
  it does something.
- Every interactive element has a visible focus ring.
- All modals close with Escape, trap focus, restore focus to opener.
- All badges across the app come from the `Badge/` family — no
  inlined `bg-*` classes for severity/KEV/priority/source/match.
- `npm run build` clean.
- Toast appears on every API success/error.

---

## Sprint Frontend 2 — Dashboard & Inventory

**Objective:** turn the landing into an action queue, separate
Inventory into its own route with Software / OS tabs, fix CSV upload
flow.

### Components / files
- NEW   `src/app/page.jsx`             — Dashboard 2.0
- NEW   `src/app/(dashboard)/loading.jsx` and `error.jsx`
- NEW   `src/app/inventory/page.jsx`   — Inventory list (URL-aware)
- NEW   `src/app/inventory/[id]/page.jsx` — Product detail page
- NEW   `src/components/Dashboard/UrgentFindings.jsx`
- NEW   `src/components/Dashboard/KevUrgencyBoard.jsx`
- NEW   `src/components/Dashboard/RecentExploitabilityChanges.jsx`
- NEW   `src/components/Dashboard/RecentUploads.jsx`
- NEW   `src/components/Inventory/InventoryTable.jsx`
- NEW   `src/components/Inventory/ProductDetailDrawer.jsx`
- NEW   `src/components/Inventory/ImportCsvDrawer.jsx`
- EDIT  `src/components/Products/ProductsGrid.jsx` → split / deprecate
- EDIT  `src/components/Products/AddProductModal.jsx` → keep for "single
  add", move CSV to `ImportCsvDrawer`
- NEW   `src/lib/api/inventory.js`     — typed wrappers (jsdoc)

### Risks
- Existing single-page state (selected product → CVE table filter)
  must keep working: implement new pages incrementally and route the
  old `tab=dashboard` URL to `/`.
- CSV parsing was happening client-side; ensure new drawer keeps the
  same parser (move into `lib/csv.js`).

### Tests
- Snapshot of UrgentFindings with mock data (3 rows including KEV).
- Manual: upload a 100-row CSV → drawer shows progress → redirect to
  `/inventory` → rows visible.
- Click a KPI card → navigate to filtered list, URL contains query.
- Clear filters via header `<ResetButton>` → URL drops query params.

### Acceptance criteria
- All KPI tiles on Dashboard click into filtered lists.
- Inventory has Software / Operating Systems tabs in URL.
- CSV import is reachable from Dashboard ("Upload inventory" CTA on
  empty state) AND from Inventory's "+ Import" button.
- Product detail uses `<ProductDetailPanel>` reusable in the drawer
  and the page.
- All URL routes work on browser-back / refresh.

---

## Sprint Frontend 3 — CVE & Findings

**Objective:** ship a real CVE detail page, the Findings queue with
status FSM and SLA, and the priority explanation.

### Components / files
- NEW   `src/app/cves/page.jsx`            — CVE catalog
- NEW   `src/app/cves/[cveId]/page.jsx`    — full-page CVE detail
- NEW   `src/components/CVE/CveCatalogTable.jsx`
- NEW   `src/components/CVE/CveDetailPanel.jsx`  — reused in modal
- NEW   `src/app/findings/page.jsx`         — list with tabs
- NEW   `src/app/findings/[productId]/[cveId]/page.jsx`
- NEW   `src/components/Findings/FindingsTable.jsx`
- NEW   `src/components/Findings/FindingDetailDrawer.jsx`
- NEW   `src/components/Findings/FindingStatusPicker.jsx`
- NEW   `src/components/Findings/SlaBoard.jsx`
- NEW   `src/components/Findings/RiskAcceptanceForm.jsx`
- NEW   `src/components/Findings/AuditHistoryList.jsx`
- NEW   `src/lib/api/findings.js` (uses /api/findings/sla, /mttr,
        /risk-acceptance endpoints from Sprint 3 backend)
- EDIT  `src/components/CVE/CVEDetailModal.jsx` → wraps `CveDetailPanel`
        for backward compatibility, then can be deprecated

### Risks
- The status FSM has 7 states; ensure the picker works even when
  some transitions are not allowed by backend (handle 422).
- Risk acceptance form needs justification + future expires_at; client
  validation must mirror server.
- SLA badge state must come from backend's `/api/findings/sla` to
  avoid drift.

### Tests
- `/findings?sla_state=breached` returns rows where SLA badge =
  breached.
- Risk acceptance: requester ≠ approver enforced client-side too.
- CVE detail page renders all sections with mock data; missing
  optional fields collapse without errors.
- Keyboard: focus a finding row, press Enter → drawer opens; Esc → drawer closes.

### Acceptance criteria
- `/findings` page covers Open / In review / Planned / Accepted risk /
  Remediated / SLA breached as URL-aware tabs.
- Each finding row exposes `<PriorityScoreBadge>`, `<SeverityBadge>`,
  `<KevBadge>`, `<SlaBadge>`, due date, owner, status picker.
- Bulk actions "mark in_review" + "set due" + "export CSV" work.
- CVE detail page has its own URL.
- Risk acceptance request → approve flow goes through `<ConfirmDialog>`
  and audit log entry is visible in the drawer's history list.

---

## Sprint Frontend 4 — Live Exploitability, Webhooks & Reports

**Objective:** finish the redesign by promoting Live Exploitability to
its own page, adding the Webhooks console and the Reports section.

### Components / files
- NEW   `src/app/live-exploitability/page.jsx`
- NEW   `src/components/LiveExploitability/{Search,IntelView}.jsx`
        (extracted from `Exploitability.jsx`)
- NEW   `src/app/webhooks/page.jsx`
- NEW   `src/app/webhooks/[id]/page.jsx`
- NEW   `src/components/Webhooks/WebhooksTable.jsx`
- NEW   `src/components/Webhooks/WebhookForm.jsx`
- NEW   `src/components/Webhooks/DeliveryLog.jsx`
- NEW   `src/app/reports/sla/page.jsx`
- NEW   `src/app/reports/mttr/page.jsx`
- NEW   `src/components/Reports/SlaSummaryView.jsx`
- NEW   `src/components/Reports/MttrView.jsx`
- NEW   `src/components/Reports/ExportControls.jsx`
- EDIT  `src/components/Settings/SettingsPanel.jsx` → become a real page
- NEW   `src/app/settings/page.jsx`
- NEW   `src/components/LiveSearch/LiveSearchPanel.jsx` → simplified
        without the Exploitability mode (back to keyword/cpe/circl/id)

### Risks
- Webhook URLs surfaced in delivery log might leak secrets in the
  payload preview — ensure the audit-masking that the backend does is
  also enforced client-side when rendering.
- Webhook test button can spam the receiver — add debounce + 5 s
  cool-down.
- LiveExploitability page uses `?refresh=true` by default; ensure we
  do NOT loop on every render (single fetch on input commit).

### Tests
- `/webhooks` lists existing webhooks; "Test" button shows the response
  status code and the masked URL.
- `/reports/sla` renders KPIs (breached / at_risk / on_track / met) and
  per-severity counters; Export CSV downloads the same data.
- `/live-exploitability/CVE-2024-1234` deep link opens with the right
  search prefilled and triggers `?refresh=true` once.
- LiveSearchPanel returns to 4 modes (no exploit). Existing tests
  still pass.

### Acceptance criteria
- Sidebar 8 entries (Dashboard / Inventory / Findings / CVE Intel /
  Live Exploitability / Webhooks / Reports / Settings) all reachable
  by URL.
- All endpoints from `/api/webhooks/*`, `/api/findings/sla*`,
  `/api/findings/mttr` are consumed by UI.
- Reduced-motion preference honoured across the site.
- Build clean, no console errors on production build.

---

## Cross-cutting decisions

| Decision | Rationale |
|---|---|
| Keep JavaScript (no TS migration) | TS migration is a 2-week scope on its own; do later. Use jsdoc for typing helpers. |
| Add a tiny icon set (Lucide) | Replaces emoji icons project-wide; small bundle. |
| URL-driven state | Already needed by the IA. Use `useSearchParams` + `useRouter`. |
| Toast system | Build a 50-line custom one; do not pull react-hot-toast for now. |
| Modal/Drawer | Build on top of `@headlessui/react` (Tailwind-friendly, accessible) — single tiny dependency. |
| Tests | Add Vitest + React Testing Library at Sprint Frontend 1. Keep tests in `frontend/__tests__/`. |
| Lint | Add `eslint-config-next` (already implicit in Next 14) + `eslint-plugin-jsx-a11y`. |

---

## Per-sprint deliverables checklist

| Sprint | Build | Lint | Tests | A11y | Acceptance |
|---|---|---|---|---|---|
| 1 | clean | new eslint clean | smoke render | focus trap, focus rings | shell + design system + clickability fix |
| 2 | clean | clean | URL-state tests | tab order across nav | dashboard 2.0 + inventory routes + CSV import |
| 3 | clean | clean | risk-acceptance lifecycle, SLA badge | screen-reader on FSM picker | findings + CVE detail pages |
| 4 | clean | clean | webhooks form + reports view | reduced motion | 8 sidebar entries, deep-link works |

Each sprint exits with `FRONTEND_VALIDATION_SPRINT_N.md` documenting
the test/lint/build outputs and any deferred items.
