# AzureLens — Development Guide

How to work in the AzureLens monorepo. Covers prerequisites, per-package setup, branching, commits, code style, secrets, and CI expectations.

> Foundation phase scope: **no business logic, no Microsoft API calls, no Azure deploys yet.** This guide documents the *workflow* and *contracts* future contributions must follow. See `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, and `docs/ROADMAP.md` for the *what* and *why*.

---

## 1. Prerequisites

| Tool | Version |
|---|---|
| Node.js | 20 LTS (use `nvm` to match `.nvmrc` once added) |
| pnpm (preferred) or npm | latest LTS |
| Python | 3.11.x |
| Terraform | 1.7+ |
| Azure CLI | latest |
| Git | 2.40+ |

Optional but recommended:
- `direnv` for `.envrc`-driven environment loading.
- `pre-commit` (planned config in a later branch) to mirror CI locally.

---

## 2. Repository Layout (skeleton)

```
azurelens/
├── apps/
│   ├── frontend/                 Next.js (TypeScript) — UI shell only
│   └── api/                      FastAPI — health endpoint only
├── services/
│   ├── scanner/                  Python — empty entry point
│   ├── threat-intel/             Python — empty entry point
│   ├── risk-engine/              Python — empty entry point
│   └── ai-engine/                Python — empty entry point
├── infra/
│   └── terraform/                Terraform placeholders (no resources yet)
├── ci/                           Holding dir for the CI workflow (see § 9.1)
├── docs/                         Design + this guide
├── .gitignore
└── README.md
```

Future paths (created in later phases) are listed in `README.md` and `docs/ARCHITECTURE.md` § 3.

---

## 3. Per-Package Setup

### 3.1 `apps/frontend` (Next.js + TypeScript)

```bash
cd apps/frontend
nvm install 20 && nvm use 20
npm install                 # pnpm install once a workspace is added
npm run dev                 # http://localhost:3000
npm run typecheck
npm run lint
```

Environment (use `.env.local`, gitignored):

```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
NEXT_PUBLIC_ENTRA_CLIENT_ID=<set later in Phase 1>
NEXT_PUBLIC_ENTRA_AUTHORITY=https://login.microsoftonline.com/common
NEXT_PUBLIC_API_SCOPE=api://azurelens-api/.default
```

### 3.2 `apps/api` (FastAPI)

```bash
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
curl http://localhost:8000/api/v1/health
ruff check .
mypy .
pytest
```

Environment (use `.env`, gitignored):

```
AZURELENS_ENV=local
# secrets are NOT placed here in non-local environments — resolved via Managed Identity
```

### 3.3 `services/scanner`, `services/threat-intel`, `services/risk-engine`, `services/ai-engine`

```bash
cd services/<svc>
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m <pkg>.main --once     # pkg = scanner | threat_intel | risk_engine | ai_engine
ruff check .
mypy .
pytest
```

### 3.4 `infra/terraform`

```bash
cd infra/terraform
terraform fmt -recursive
terraform init -backend=false   # backend is configured in CI, not here
terraform validate
```

No `terraform apply` is wired in this phase. Phase 1 introduces the modules and the OIDC-federated deploy pipeline.

---

## 4. Branching & Commits

- **Trunk**: `main`. Direct pushes disabled (once branch protection is enabled).
- **Feature branches**: `feature/<scope>-<short-description>`.
  - Current: `feature/platform-foundation`.
- **Conventional commits** are encouraged: `feat(api): …`, `fix(scanner): …`, `docs: …`, `ci: …`, `chore: …`.
- One logical change per PR. Keep PRs reviewable.
- Squash-merge into `main` by default; preserve a single message per logical unit of work.

---

## 5. Code Style

| Language | Tool |
|---|---|
| TypeScript / React | `eslint` (Next preset), `tsc --noEmit` |
| Python | `ruff` (lint + import sort), `mypy --strict`, `pytest` |
| Terraform | `terraform fmt -recursive`, `terraform validate` |
| YAML | 2-space indent, no tabs |
| Shell | (none yet) — when added: `shellcheck`, `set -euo pipefail` |

CI must remain the source of truth. If CI passes, code style is acceptable; if it fails, do not bypass — fix the underlying issue.

---

## 6. Secrets

**The repository contains no secrets and never will.** This is non-negotiable.

- Local dev: `.env` / `.env.local` (gitignored). Use placeholder values; never commit a working secret.
- Cloud: Azure Key Vault, accessed via **Managed Identity**. Container Apps / Functions mount Key Vault references — there are no secret values in app settings.
- CI: GitHub Actions uses **OIDC federation** to Azure for any cloud action; no long-lived PATs or client secrets are stored.

If a secret is ever committed by accident:
1. Rotate it immediately in the source system.
2. Notify security.
3. Purge from history only after step 1 (`git filter-repo`); a rewrite is invasive — coordinate.

See `docs/SECURITY_MODEL.md` § 5 (Key & Secret Management).

---

## 7. Multi-Tenant Invariants

Even at skeleton stage, write code as if the invariants below are already enforced. They will be enforced by middleware, RLS, partition keys, and CI tests in Phase 1:

- Every persisted record carries `tenant_id`.
- Every Cosmos query specifies `tenant_id` as the partition key.
- Every SQL query is filtered by `tenant_id` (RLS will enforce, but write the explicit filter too).
- Every event in Service Bus / Event Grid carries `tenant_id` in application properties.
- Every AI Search query carries `filter=tenant_id eq '<id>'`.
- Every Blob path starts with `tenants/{tenant_id}/`.

A cross-tenant data leak is a P0 defect and an automatic release block.

See `docs/SCHEMA_DESIGN.md` § 12.

---

## 8. Testing Expectations

The skeleton commits **do not** include tests yet, but the contract is:

- Engines (compliance, risk, AI) require ≥ 80% coverage.
- Property-based tests (`hypothesis`) for the risk-scoring formula.
- Contract tests for connector clients (recorded responses; no live calls in CI).
- End-to-end synthetic tests for tenant isolation (cross-tenant read MUST fail).

Test scaffolding lands alongside the first real feature in Phase 1.

---

## 9. CI

CI runs on every push and PR:

- **Frontend**: install + `tsc --noEmit`.
- **Python services**: editable install + `ruff` + `mypy`.
- **Terraform**: `fmt -check` + `init -backend=false` + `validate`.

Phase 1 adds: per-service unit tests, container image build + sign, IaC validation against PSRule, SAST via CodeQL, dependency review, and OIDC-federated deploy to dev.

### 9.1 One bootstrap caveat

The MCP token used to seed this branch did not have GitHub's `workflow` OAuth scope, so the CI YAML was committed to `ci/ci.yml` instead of `.github/workflows/ci.yml`. To activate it, anyone with a normal developer token (or via the GitHub web UI) needs to:

```bash
git mv ci/ci.yml .github/workflows/ci.yml
rm ci/README.md
git commit -m "ci: activate foundation CI workflow"
git push
```

No content changes are required; the YAML is the production-intended workflow.

---

## 10. Adding a New Service

Until packages and codegen exist, follow this convention:

1. Create `services/<name>/` with: `README.md`, `pyproject.toml`, `<name>/__init__.py`, `<name>/main.py`.
2. Match the existing skeletons (config via `pydantic-settings`, console script, structured logging).
3. Add the path to the CI `python` matrix in `ci/ci.yml` (or `.github/workflows/ci.yml` once moved).
4. Update `README.md` repository layout and add a section in `docs/ARCHITECTURE.md` § 4.
5. Record any architectural deviation as an ADR (`docs/adr/NNNN-title.md`) — ADR template lands in a later branch.

---

## 11. Where to Find Things

| Concern | File |
|---|---|
| What the product is | `README.md` |
| System design | `docs/ARCHITECTURE.md` |
| Roadmap / milestones | `docs/ROADMAP.md` |
| Identity, RBAC, secrets, network, data | `docs/SECURITY_MODEL.md` |
| STRIDE threat model & mitigations | `docs/THREAT_MODEL.md` |
| Data models / partitioning | `docs/SCHEMA_DESIGN.md` |
| Azure services catalog & SKUs | `docs/AZURE_SERVICES.md` |
| How to develop (this file) | `docs/DEVELOPMENT_GUIDE.md` |

---

## 12. Definition of Done (for any change)

A change is done when:

1. CI is green.
2. All relevant design docs are updated in the same PR.
3. Tenant-isolation invariants are upheld (or explicitly evaluated as N/A in the PR description).
4. No secrets or PII added to code, logs, or comments.
5. Telemetry (logs/metrics/traces) added where new code path warrants it.
6. A reviewer can run the change locally using only this guide.
