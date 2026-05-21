# Phase 11 — Enterprise UX Redesign

> Visual & interaction foundation for AzureLens enterprise users. Aligns with DESIGN.md §13 (Example Dashboard Screens) and the persona matrix in §3.

## Goals

1. **Executive trust at first glance.** A CISO opening the dashboard sees one number, one trend arrow, and one prioritized action list — no chart-junk.
2. **Engineer drill-down in two clicks.** Any score or campaign card collapses to evidence (raw blob ref, NSG rule, finding JSON).
3. **Persona-tuned density.** Same data, two densities: *Executive* (cards, narrative) and *Analyst* (table, filters, KQL-style search).
4. **Audit-credible.** Every number on screen carries a "last checked" timestamp + evidence link. No floating claims.
5. **Dark by default**, light theme switchable. Enterprise security teams expect dark; auditors expect printable light.

## Information Architecture

```
Top nav      [Tenant ▾]  Search  Quick-add  Alerts  Profile
Left rail    Executive  • Identity  • Devices  • Resources  • Data
             Threat Map • MITRE     • Compliance • Reports  • Settings
Main         Persona-tuned view (Executive default for first sign-in)
Right rail   Context: "Why did this number change?" + AI Copilot launcher
```

## Design Tokens

| Token | Value (dark) | Use |
|-------|-------------|-----|
| `--bg-0` | `#0b0f17` | Page background |
| `--bg-1` | `#121826` | Surface |
| `--bg-2` | `#1a2335` | Elevated surface / card |
| `--bg-3` | `#243049` | Hover / selected |
| `--border` | `#2a3550` | Hairline |
| `--text-1` | `#e6ecf6` | Primary text |
| `--text-2` | `#a3b0c8` | Secondary text |
| `--text-3` | `#6b7794` | Tertiary / metadata |
| `--accent` | `#4f8cff` | Brand / links |
| `--ok` | `#3ecf8e` | Pass / improving |
| `--warn` | `#f0b429` | Attention |
| `--crit` | `#ef4d6a` | Critical / dropping |
| `--info` | `#7c9cff` | Informational |

Typography: **Inter** (UI), **JetBrains Mono** (code, IDs, KQL). 14px base, 1.5 line-height, weights 400/500/600/700.

Radius: 6px controls, 10px cards, 16px hero. Shadow: single `0 1px 0 rgba(255,255,255,.04) inset, 0 8px 24px rgba(0,0,0,.35)`.

## Component Library (Phase 11 scope)

- **ScoreRing** — 0–100 conic-gradient ring with delta and trend sparkline.
- **SubScoreBar** — five horizontal bars for Identity/Device/Resource/Data/Threat.
- **CampaignCard** — TI article with relevance count and "Why relevant" expand.
- **ActionCard** — prioritized remediation with effort estimate and one-click stub.
- **MitreCell** — heatmap cell with technique ID, exposure score, overlay toggles.
- **ControlRow** — compliance control with status pill, evidence link, last-checked.
- **EvidenceDrawer** — right-side slide-in with raw JSON, blob link, sign-off.
- **FilterBar** — chips + KQL-style free-text with tenant-scoped autocomplete.
- **CopilotLauncher** — floating, expands to dock; transcript stays per-view.

## Accessibility

- WCAG 2.2 AA contrast on all token pairs.
- All interactive elements ≥ 32px hit target.
- Keyboard: `g e` Executive, `g m` MITRE, `g c` Compliance, `/` focuses search, `?` shortcuts.
- ARIA live region for posture-drift alerts.

## Phase 11 Deliverables (this PR)

- [x] Design tokens + base layout shell (`ux/assets/styles.css`)
- [x] Executive Dashboard (`ux/index.html`) — ScoreRing, SubScoreBar, CampaignCard, ActionCard
- [x] MITRE ATT&CK Heatmap (`ux/views/mitre.html`) — 12-tactic grid with exposure colors and overlay toggles
- [x] Compliance Center (`ux/views/compliance.html`) — framework tabs, ControlRow, EvidenceDrawer stub
- [x] Shared shell JS (`ux/assets/app.js`) — nav, theme toggle, mock-data render, keyboard shortcuts

## Out of Scope (Phase 12+)

- Identity Sankey (§13.4) — needs real Graph data shape first.
- Azure Exposure Map (§13.5) — depends on resource-graph topology service.
- Live Threat Feed streaming (§13.6) — needs SignalR wiring.
- AI Copilot dock — Phase 13 with AOAI function-calling contract.
- Real auth, real API — this is a static prototype with seeded mock data.

## Open Questions

1. **Score weighting visibility.** Should sub-score weights be user-visible (transparency) or hidden (avoid gaming)? *Recommend: visible to Admin/SecurityAdmin, hidden to Viewer.*
2. **Density default per persona.** CISO → Executive density; SOC Analyst → Analyst density. Detect from app role on first sign-in.
3. **Localization.** Layout is LTR-only in Phase 11; RTL audit deferred to Phase 14.
