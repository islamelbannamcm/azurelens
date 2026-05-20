# AzureLens — Cloud Threat & Compliance Exposure Analyzer (CTCEA)

> **Azure-native, AI-augmented Cloud Security Posture, Compliance, and Live Threat Exposure platform for Azure and Microsoft 365 tenants.**

AzureLens is an enterprise-grade, multi-tenant SaaS (also deployable as a dedicated single-tenant ISV solution inside the customer's Azure subscription) that continuously scans an organization's Azure tenant, Microsoft 365 environment, identities, devices, resources, policies, and configurations, then maps the findings against **live threat intelligence**, **MITRE ATT&CK**, and **major compliance frameworks** (CIS, NIST CSF, ISO 27001, SOC 2, GDPR, Microsoft Cloud Security Benchmark, Azure Well-Architected, Zero Trust, M365 baselines).

It behaves like a unified combination of **Defender for Cloud CSPM + Secure Score + Sentinel TI + Purview compliance + MITRE ATT&CK exposure + AI security advisor**, but presented through a **single executive-friendly and technically rigorous experience**.

---

## Project status

**Current branch:** `feature/platform-foundation`
**Current phase:** **9 — Local run, Docker, and Azure deployment preparation** (see `docs/ROADMAP.md`).

| # | Phase | Status |
|---|---|---|
| 0 | Platform Foundation (design + docs) | done |
| 1 | Phase 2 — API contracts + shared domain models | done (skeleton) |
| 2 | Phase 3 — Scanner plugin interfaces + orchestration contracts | done (skeleton) |
| 3 | Phase 4 — Threat Intelligence ingestion contracts + correlation | done (skeleton) |
| 4 | Phase 5 — Risk scoring engine + explainability model | done |
| 5 | Phase 6 — AI engine contracts + prompt safety + report generation | done (skeleton) |
| 6 | Phase 7 — Demo MVP data layer + API integration | done |
| 7 | Phase 8 — Frontend demo dashboard | done |
| 8 | **Phase 9 — Local run + Docker + Azure deployment preparation** | **this branch** |

After Phase 9 the demo runs end-to-end on a laptop and the Azure deployment story is documented + scaffolded. Phase 1 production wiring (auth, persistence, real connectors, AI inference) is the next milestone.

---

## Quick start

Two paths — both render the same Contoso Demo dashboard. **Neither requires any Azure subscription, Microsoft Graph access, or external API keys.**

### Docker Compose (one command, both services)

```bash
cp .env.example .env          # placeholders only; no real secrets
docker compose up --build
# → API   http://localhost:8000
# → Web   http://localhost:3000
```

### Native (active development)

```bash
# Backend
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd apps/frontend
npm install
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
```

Smoke check:

```bash
curl -s http://localhost:8000/api/v1/health
curl -s http://localhost:8000/api/v1/dashboard/summary | head -c 400
```

Full runbook (including the frontend-only path that works with no backend at all) is in **[`docs/LOCAL_RUNBOOK.md`](docs/LOCAL_RUNBOOK.md)**.

---

## What you'll see

A clean executive-friendly security dashboard for the fictional **Contoso Demo** tenant:

- Overall posture score (with 7-day delta) and per-domain breakdown — identity, Azure exposure, device, threat exposure, M365 compliance.
- Top risks table (5 findings ranked by deterministic risk score).
- Threat exposure panel — 2 active campaigns (Akira ransomware via public RDP + Storm-1234 phishing), 1 KEV-flagged CVE, 11 MITRE techniques observed, 2 correlation hits.
- Compliance framework summary — CIS Azure / MCSB / NIST CSF / ISO 27001 / SOC 2 / GDPR with progress bars.
- Remediation roadmap — counters across all statuses + the next prioritized actions with approval requirement badges.
- Recent scan status — completed full scan with 12 findings produced.

If the API isn't reachable, the dashboard renders from an embedded static fallback dataset and shows a yellow banner with the diagnostic reason — see `apps/frontend/app/page.tsx` (Phase 8).

---

## Deploying to Azure

Two supported paths, both sharing the same shared platform resources (RG, managed identity, Key Vault, Storage, Log Analytics, Application Insights, VNet):

1. **Simple App Service path** — fastest to a public demo; two Linux Web Apps on a P1v3 plan.
2. **Azure Container Apps path** — the long-term Azure-native target; per-workload scaling, KEDA scalers, blue/green revisions.

Both paths are scaffolded as **production-oriented placeholders** in `infra/terraform/` (Phase 9). Real deploys land in Phase 1.

Full guide: **[`docs/AZURE_DEPLOYMENT_GUIDE.md`](docs/AZURE_DEPLOYMENT_GUIDE.md)**.

---

## Repository layout

```
azurelens/
├── apps/
│   ├── api/               FastAPI backend (Python 3.11)
│   │   ├── app/           code (routes, models, demo data, security primitives)
│   │   ├── Dockerfile     production-style multi-stage image
│   │   └── pyproject.toml
│   └── frontend/          Next.js 14 (App Router, TypeScript, server components)
│       ├── app/           pages + globals.css
│       ├── components/    dashboard primitives
│       ├── lib/           typed API client
│       ├── types/         shared domain types
│       └── Dockerfile     production-style Next.js standalone image
├── services/
│   ├── scanner/           scanner plugin contracts + 7 stub plugins
│   ├── threat-intel/      TI connector contracts + 11 stub connectors
│   ├── risk-engine/       deterministic scoring + 5 named policy profiles
│   └── ai-engine/         AI contracts + 6 prompt templates + safety + grounding + report gen
├── infra/
│   └── terraform/         providers, identity, KV, storage, monitoring, networking,
│                          App Service path, Container Apps path
├── docs/                  Architecture / Security / Threat model / Schema / Azure
│                          services / Roadmap / Scanner / Threat Intel / Correlation /
│                          Risk scoring / AI engine / Prompt safety / Demo mode /
│                          Local runbook / Azure deployment guide
├── ci/                    holding directory for `ci.yml` (see ci/README.md)
├── docker-compose.yml     local orchestration (API + frontend)
├── .env.example           safe placeholder env vars
└── README.md              this file
```

---

## Pre-production safety properties

Phase 9 keeps the demo strictly demo-safe:

- **No real secrets** in any file. Every secret reference is a Key Vault URI or a `kv://...` placeholder; runtime resolution happens via Managed Identity (Phase 1+).
- **No outbound calls** to Microsoft Graph / Azure Resource Graph / Defender / Sentinel / Intune / Purview / Azure OpenAI / external TI feeds. All demo data is deterministic constants.
- **CORS gated** on `AZURELENS_ENV=local`. Non-local environments bypass the permissive CORS block and are expected to sit behind APIM (Phase 1+).
- **Synthetic identifiers everywhere.** Tenant `00000000-…`, domains under `*.invalid` per RFC 6761, IPs from the `203.0.113.0/24` documentation range.
- **Terraform Phase 9 = scaffolding only.** Resources declare a production-grade posture (HSM-backed KV, public-denied storage, ZRS, NSGs, MI everywhere) but the Phase 1 dependencies — Front Door, APIM, SQL, Cosmos, Service Bus, OpenAI, ACR, Private Endpoints — are commented forward contracts.

---

## What's next (Phase 1 → 9 roadmap)

Detailed milestones in **[`docs/ROADMAP.md`](docs/ROADMAP.md)**. Key Phase 1 deliverables:

- Multi-tenant Entra ID authentication + tenant-context middleware.
- Real persistence in Azure SQL + Cosmos DB + ADLS Gen2 + AI Search.
- First real scanner integrations (Azure Resource Graph, Entra ID, Defender for Cloud).
- First real TI ingestions (CISA KEV, MITRE ATT&CK, Microsoft Defender TI).
- Service Bus eventing + Container Apps Jobs orchestration.
- GitHub Actions OIDC → Azure deployment pipeline.

Phase 5 lights up the AI engine against Azure OpenAI; Phase 8 takes the platform to a multi-region GA.

---

## Documentation index

| Document | Covers |
|---|---|
| `docs/ARCHITECTURE.md` | Full system design, monorepo decomposition, Azure-native patterns |
| `docs/ROADMAP.md` | Phased implementation plan with exit criteria |
| `docs/SECURITY_MODEL.md` | Identity, RBAC, secrets, network, data protection, audit |
| `docs/THREAT_MODEL.md` | STRIDE + OWASP LLM Top 10 with mitigations |
| `docs/SCHEMA_DESIGN.md` | Persistence-side data models for assets, findings, TI, mappings |
| `docs/AZURE_SERVICES.md` | Every Azure service used, SKUs, rationale, alternatives |
| `docs/API_CONTRACTS.md` | HTTP API surface (resources, endpoints, RBAC) |
| `docs/DATA_MODEL.md` | Entity model behind the API (five rings) |
| `docs/SCANNER_ARCHITECTURE.md` | Scanner plugin lifecycle + tenant isolation + output mapping |
| `docs/THREAT_INTEL_ARCHITECTURE.md` | TI ingestion + STIX/TAXII alignment + dedupe + trust + freshness |
| `docs/CORRELATION_ENGINE.md` | How TI maps to Azure / M365 / Entra / Intune / Defender / Sentinel posture |
| `docs/RISK_SCORING_MODEL.md` | Deterministic scoring formulas + 5 policy profiles + AI roadmap |
| `docs/AI_ANALYSIS_ENGINE.md` | AI orchestration, grounding, prompt templates, model routing |
| `docs/PROMPT_SAFETY_MODEL.md` | Prompt safety policy (rules, redaction, approval gates, audit) |
| `docs/DEMO_MODE.md` | What demo mode is + endpoint map + migration to Phase 1 |
| `docs/DEVELOPMENT_GUIDE.md` | Per-package setup, branching, code style, secrets, CI |
| `docs/LOCAL_RUNBOOK.md` | Three local-run paths + troubleshooting |
| `docs/AZURE_DEPLOYMENT_GUIDE.md` | App Service path + Container Apps path + cost notes |

---

## License

To be defined (target: commercial / proprietary with optional source-available components).
