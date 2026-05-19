# apps/frontend

Next.js (App Router) + TypeScript skeleton for the AzureLens web experience.

## Purpose

Role-aware web UI for the **Cloud Threat & Compliance Exposure Analyzer**. Surfaces tenant posture, compliance heatmaps, identity/device risk, live threat-campaign exposure, prioritized remediation backlog, and the AI copilot — all gated by the user's role (see `docs/SECURITY_MODEL.md` § 4 RBAC matrix).

## Future Responsibilities

- **Auth**: MSAL.js (Authorization Code + PKCE) against the customer's Entra ID tenant; silent-SSO refresh; in-memory token storage (no `localStorage`).
- **Tenant context**: tenant selector + `tenant_id` claim validated on every API call.
- **Pages** (planned, none implemented yet):
  - `/` Executive Overview
  - `/identity` Identity Risk
  - `/azure` Azure Exposure
  - `/devices` Device Posture
  - `/compliance/[framework]` Compliance Center
  - `/threats` Threat Exposure (MITRE heatmap, campaign-to-asset)
  - `/remediation` Prioritized backlog (Kanban)
  - `/reports` Executive / Technical / Audit
  - `/copilot` AI conversational assistant
  - `/admin/connectors`, `/admin/roles`, `/admin/billing`
- **State**: TanStack Query for server state; Zustand for minimal client state.
- **Dashboards**: Power BI Embedded JS SDK with Row-Level Security keyed on `tenant_id` + role.
- **Security**: strict CSP, no inline scripts, Trusted Types, SameSite=Strict cookies, HSTS.
- **i18n / a11y**: planned (deferred to post-MVP).

## Local Development (planned)

> The skeleton intentionally does not install dependencies or run yet. These steps document the future workflow.

```bash
cd apps/frontend
nvm use                   # (planned .nvmrc -> Node 20 LTS)
pnpm install              # lockfile to be added in a follow-up branch
pnpm dev                  # http://localhost:3000
pnpm typecheck
pnpm lint
pnpm test
```

Required environment (never commit):

| Variable | Purpose |
|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | Backend API base, e.g. `http://localhost:8000` |
| `NEXT_PUBLIC_ENTRA_CLIENT_ID` | Multi-tenant app client id (public) |
| `NEXT_PUBLIC_ENTRA_AUTHORITY` | e.g. `https://login.microsoftonline.com/common` |
| `NEXT_PUBLIC_API_SCOPE` | Backend API scope, e.g. `api://azurelens-api/.default` |

Use `.env.local` (gitignored). Do **not** put secrets in `NEXT_PUBLIC_*`.

## Status

Skeleton only — no routing logic, no auth wiring, no API calls. See `docs/ROADMAP.md` Phase 1 for the implementation milestone.
