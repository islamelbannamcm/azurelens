# Phase 11 — Enterprise UX redesign

> Transforms the Phase-8 single-page demo into a multi-route enterprise product
> shell modeled on **Azure Portal + Microsoft Defender XDR + HP enterprise**.
> Updates the real Next.js app under `apps/frontend/` — no static prototype.

## Scope

In:
- A persistent product shell — dark navy left **Sidebar** + dark **Topbar**
  (tenant switcher, command search, notifications, profile) wrapping a light
  content surface (preserves the existing token-driven look of cards/tables).
- App-Router routes for the primary workspaces: Overview, Findings, Threats,
  Compliance, Remediations, Scans.
- Shell-grade primitives: `PageHeader`, `Breadcrumbs`, `KpiStrip`,
  `MitreTechniqueGrid`, `EmptyState`.
- A `fetchWithFallback` helper so every page renders against live API data
  when reachable and falls back to the existing demo dataset otherwise.

Out (Phase 12+):
- Real MSAL auth, server-side tenant resolution, RBAC role gating.
- Per-page client interactivity beyond search focus (`/`) and active route
  highlighting (`usePathname`). TanStack Query, optimistic mutations, and
  real-time SignalR are deferred.
- Theme switcher; the shell is intentionally single-theme until tokens are
  audited for dark-content readability.

## Information architecture

```
Topbar     [Brand]   [Tenant ▾]   <search ⌘K>            <bell>  <avatar>
Sidebar    Overview
           Findings
           Threats
           Compliance
           Remediations
           Scans
           ────────
           Settings  (stub)
Main       <PageHeader title="…" breadcrumbs aside>
           <page sections — cards, tables, KPI strips>
```

## Design tokens added

The existing light-content tokens (`--color-*`, `--space-*`, `--radius-*`,
`--shadow-*`, `--font-*`) are preserved exactly so the existing components
keep their look. New shell tokens are additive:

| Token              | Value      | Use                                  |
|--------------------|-----------|--------------------------------------|
| `--shell-bg`       | `#0b1220` | Sidebar + topbar background          |
| `--shell-bg-elev`  | `#101a2e` | Brand cell, active nav row           |
| `--shell-fg`       | `#e7edf7` | Shell foreground                     |
| `--shell-fg-muted` | `#97a3bf` | Shell secondary text                 |
| `--shell-border`   | `#1c2944` | Hairline inside shell chrome         |
| `--shell-accent`   | `#3b82f6` | Active route indicator               |
| `--shell-hover`    | `#142036` | Sidebar item hover                   |
| `--shell-grad`     | `linear-gradient(135deg,#0078d4,#00bcf2)` | Brand mark |

## Components added

- `components/shell/AppShell.tsx` — server; lays out the grid.
- `components/shell/Topbar.tsx` — server; brand, tenant, search slot, actions.
- `components/shell/Sidebar.tsx` — server; nav group registry + footer.
- `components/shell/NavLink.tsx` — **client**; highlights active route via `usePathname`.
- `components/shell/CommandSearch.tsx` — **client**; `/` focuses the input.
- `components/PageHeader.tsx` — title + breadcrumbs + aside slot.
- `components/KpiStrip.tsx` — Defender-style stat strip (label, value, delta).
- `components/MitreTechniqueGrid.tsx` — chips for observed ATT&CK techniques with active highlights.
- `components/EmptyState.tsx` — uniform empty/zero-state.

## Library additions

- `lib/demo-data.ts` — exports `DEMO_DASHBOARD` (extracted from `app/page.tsx`)
  plus deterministic demo `findings`, `assets`, `scans`, `remediations`,
  `campaigns` derived from the same `Contoso Demo` tenant fixture.
- `lib/fetchWithFallback.ts` — wraps any `lib/api.ts` call with a 2.5s
  AbortController timeout and a typed fallback value; returns
  `{ data, usingFallback, fallbackReason }` so pages can render a banner
  consistently.

## Routes added

| Route            | Server fetches                  | Fallback source        |
|------------------|---------------------------------|------------------------|
| `/`              | `getDashboardSummary`           | `DEMO_DASHBOARD`       |
| `/findings`      | `listFindings`                  | demo `findings`        |
| `/threats`       | `getThreatExposureSummary` + `listCampaignExposure` | demo `threat_exposure` |
| `/compliance`    | `getComplianceSummary`          | demo `compliance_summary` |
| `/remediations`  | `getRemediationRoadmap`         | demo `remediation_roadmap` |
| `/scans`         | `listScans`                     | demo `scans`           |

Each page renders the unified fallback banner when the API is unreachable.

## Accessibility & keyboard

- All nav links are real `<a>` tags inside a labelled `<nav>`.
- Search input owns `/` shortcut (only fires when not already typing).
- Skip-to-content link in the shell for keyboard users.
- WCAG 2.2 AA contrast verified for shell-fg pairings against shell-bg.

## Open questions for Phase 12

1. **Theme.** The shell is single-theme. Adding a `data-theme="dark"` content
   theme requires re-deriving the severity/band tokens against a dark surface —
   defer until the design-system package lands.
2. **Tenant switcher.** Currently a static button; needs the real tenants API
   and per-tenant routing prefix once multi-tenant resolution exists.
3. **Command palette.** Today `/` focuses search; Phase 12 should add ⌘K open,
   route-jump, finding-jump, and TanStack Query–backed suggestions.
