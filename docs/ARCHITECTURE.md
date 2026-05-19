# AzureLens — Architecture

> Azure-native, event-driven, multi-tenant architecture for the Cloud Threat & Compliance Exposure Analyzer (CTCEA).

This document is the single source of truth for **system design**, **service decomposition**, **monorepo layout**, **Azure-native patterns**, **event-driven workflows**, **threat intelligence ingestion**, and **AI orchestration**. Detailed schemas live in `SCHEMA_DESIGN.md`; security controls in `SECURITY_MODEL.md`; threat model in `THREAT_MODEL.md`; Azure service rationale in `AZURE_SERVICES.md`.

---

## 1. Architectural Principles

1. **Azure-native first.** Prefer managed PaaS over self-hosted. Prefer Managed Identity over secrets. Prefer Private Link over public endpoints.
2. **Event-driven by default.** Long-running and high-fan-out work uses Event Grid / Service Bus / Event Hubs. Synchronous APIs only for user-facing reads.
3. **Stateless compute, stateful data.** All compute (Container Apps, Functions) is horizontally scalable and disposable; state lives in SQL / Cosmos / Storage.
4. **Multi-tenant by partition.** Tenant isolation enforced at every layer via `tenant_id` partitioning, RBAC scopes, and per-tenant encryption keys.
5. **Defense in depth.** WAF → Front Door → Private Link → Managed Identity → least-privilege RBAC → CMK → audit-everything.
6. **Reproducible infrastructure.** 100% IaC (Bicep primary, Terraform parity). No click-ops. Every environment is a deployment of the same template tree.
7. **Continuous delivery.** Trunk-based with feature branches, OIDC federation to Azure, environment gates, blue/green for the API tier.
8. **Observability is a feature.** OpenTelemetry traces end-to-end, structured logs, golden-signal dashboards, SLOs with error budgets.
9. **AI as a service, not a dependency.** AI is opt-in per tenant; the platform must produce correct findings without LLM availability.
10. **Customer-deployable.** The same Bicep tree must deploy either (a) the shared SaaS control plane or (b) a single-tenant ISV instance inside a customer's subscription.

---

## 2. Logical Architecture (C4 — Containers)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  USERS                                        │
│  CISO · SecAdmin · Compliance · Cloud Architect · SOC · IT · Auditor · Exec   │
└──────────────────────────────────────────────────────────────────────────────┘
                           │ HTTPS (Entra ID SSO + MFA + CA)
                           ▼
                ┌──────────────────────────┐
                │  Azure Front Door + WAF  │  (global, OWASP rules, bot mgmt)
                └──────────────┬───────────┘
                               │ Private Link
                               ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                    PRESENTATION TIER (per region)                     │
   │  ┌────────────────────────┐    ┌──────────────────────────────────┐   │
   │  │  Web (Static Web App   │    │  Power BI Embedded (dashboards)  │   │
   │  │  or Container Apps)    │    │  via service principal + RLS     │   │
   │  └──────────┬─────────────┘    └──────────────────────────────────┘   │
   └─────────────┼─────────────────────────────────────────────────────────┘
                 │ JWT (Entra ID, on-behalf-of)
                 ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                    APPLICATION TIER (per region)                      │
   │   ┌───────────────────────────────────────────────────────────────┐   │
   │   │  API Gateway (APIM)  ───►  Backend API (Container Apps)        │   │
   │   │     - tenant resolver    - REST + GraphQL                      │   │
   │   │     - quota / throttle   - OBO + RBAC                          │   │
   │   │     - schema validation  - findings/scores/reports/admin       │   │
   │   └───────────────────────────────────────────────────────────────┘   │
   └───────┬────────────────────────────────────────────┬─────────────────┘
           │                                             │
           ▼                                             ▼
   ┌──────────────────────────┐              ┌────────────────────────────┐
   │     ASYNC BACKBONE        │              │      DATA TIER              │
   │  ┌────────────────────┐   │              │  ┌──────────────────────┐   │
   │  │ Event Grid (system │   │              │  │ Azure SQL (txn /     │   │
   │  │  + custom topics)  │   │              │  │  findings / scores)  │   │
   │  └─────────┬──────────┘   │              │  └──────────────────────┘   │
   │  ┌─────────▼──────────┐   │              │  ┌──────────────────────┐   │
   │  │ Service Bus topics │   │              │  │ Cosmos DB (graph /   │   │
   │  │  (scan, ti, ai,    │   │              │  │  TI / mappings)      │   │
   │  │   reporting, notify│   │              │  └──────────────────────┘   │
   │  └─────────┬──────────┘   │              │  ┌──────────────────────┐   │
   │  ┌─────────▼──────────┐   │              │  │ ADLS Gen2 (raw scan  │   │
   │  │ Event Hubs         │   │              │  │  evidence, CMK)      │   │
   │  │  (telemetry / TI   │   │              │  └──────────────────────┘   │
   │  │   firehose)        │   │              │  ┌──────────────────────┐   │
   │  └────────────────────┘   │              │  │ Blob (reports / PDFs)│   │
   └──────────────────────────┘              │  └──────────────────────┘   │
                                              │  ┌──────────────────────┐   │
                                              │  │ Azure AI Search      │   │
                                              │  │  (RAG indexes)       │   │
                                              │  └──────────────────────┘   │
                                              │  ┌──────────────────────┐   │
                                              │  │ Key Vault (HSM)      │   │
                                              │  └──────────────────────┘   │
                                              └────────────────────────────┘
           │
           ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                       WORKER / ENGINE TIER                            │
   │  Scanner-Azure · Scanner-M365 · Scanner-Intune · Scanner-Purview      │
   │  Compliance Engine · Risk Engine · TI Ingestion · TI Correlation      │
   │  AI Engine · Remediation · Reporting · Notification                   │
   │   (Container Apps Jobs + Azure Functions + Durable Functions)         │
   └──────────────────────────────────────────────────────────────────────┘
           │
           ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                    EXTERNAL INTEGRATIONS                              │
   │  Microsoft Graph · Azure Resource Graph · Defender for Cloud API     │
   │  Microsoft Sentinel · Defender XDR · Intune · Purview · Azure Policy │
   │  Defender TI · Sentinel TI · CISA KEV · MITRE · MISP · OpenCTI       │
   │  OTX · abuse.ch · VirusTotal · GHSA · NVD                            │
   └──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Monorepo Layout

```
azurelens/
├── README.md
├── .gitignore
├── .editorconfig                          # (planned)
├── .github/
│   ├── workflows/                         # CI/CD (OIDC to Azure)        (planned)
│   ├── CODEOWNERS                         # (planned)
│   └── PULL_REQUEST_TEMPLATE.md           # (planned)
├── docs/
│   ├── ARCHITECTURE.md                    # this file
│   ├── ROADMAP.md
│   ├── SECURITY_MODEL.md
│   ├── THREAT_MODEL.md
│   ├── SCHEMA_DESIGN.md
│   └── AZURE_SERVICES.md
│
├── apps/                                   # User-facing applications
│   ├── web/                                # Next.js (React + TS) frontend
│   │   ├── app/                            # App router
│   │   ├── components/
│   │   ├── lib/                            # API client, auth (MSAL.js)
│   │   └── public/
│   └── api/                                # Backend API (ASP.NET Core or FastAPI)
│       ├── src/
│       │   ├── controllers/                # REST controllers
│       │   ├── graphql/                    # GraphQL resolvers (optional)
│       │   ├── auth/                       # Entra ID, OBO, RBAC
│       │   ├── tenants/                    # Tenant resolver / context
│       │   ├── findings/
│       │   ├── scores/
│       │   ├── reports/
│       │   └── admin/
│       └── tests/
│
├── services/                               # Backend microservices / workers
│   ├── scanner-azure/                      # ARG + ARM scanning
│   ├── scanner-m365/                       # Graph (Entra, EXO, SPO, Teams, OD)
│   ├── scanner-intune/                     # Intune devices, compliance, configs
│   ├── scanner-defender/                   # Defender XDR + Defender for Cloud
│   ├── scanner-purview/                    # Purview labels, DLP, retention
│   ├── compliance-engine/                  # Framework mapping & gap analysis
│   ├── risk-engine/                        # Risk scoring algorithm
│   ├── ti-ingestion/                       # TI feed ingestion workers
│   ├── ti-correlation/                     # Threat ↔ environment mapping
│   ├── ai-engine/                          # Azure OpenAI orchestration
│   ├── remediation/                        # Remediation Center (CLI/PS/Graph)
│   ├── reporting/                          # PDF/PPTX/CSV/JSON report rendering
│   └── notification/                       # Email, Teams, Webhook delivery
│
├── jobs/                                   # Scheduled / Durable orchestrations
│   ├── timer-scan-orchestrator/            # Hourly/daily scan triggers
│   ├── timer-ti-pull/                      # TI feed pull schedules
│   ├── timer-report-generator/             # Periodic report generation
│   └── durable-scan-orchestrator/          # Durable Functions for fan-out scans
│
├── packages/                               # Internal shared libraries
│   ├── shared-types/                       # OpenAPI + zod / pydantic models
│   ├── connectors/
│   │   ├── graph-client/                   # Graph SDK wrapper (Application + OBO)
│   │   ├── arg-client/                     # Resource Graph KQL helpers
│   │   ├── defender-client/                # Defender for Cloud + XDR
│   │   ├── sentinel-client/                # Sentinel TI / incidents
│   │   ├── intune-client/                  # Intune Graph endpoints
│   │   └── purview-client/                 # Purview APIs
│   ├── frameworks/                         # Reference data (versioned)
│   │   ├── mitre-attack/                   # STIX 2.1 → normalized JSON
│   │   ├── cis-azure/                      # CIS Azure benchmark control IDs
│   │   ├── nist-csf/
│   │   ├── iso-27001/
│   │   ├── soc2/
│   │   ├── gdpr/
│   │   ├── mcsb/                           # Microsoft Cloud Security Benchmark
│   │   ├── m365-baseline/
│   │   └── zero-trust/
│   ├── ti-normalizers/                     # STIX/TAXII, MISP, OTX, KEV, NVD
│   ├── ai-prompts/                         # Versioned prompt templates
│   ├── scoring/                            # Risk scoring formulas
│   └── telemetry/                          # OpenTelemetry helpers
│
├── infra/                                   # Infrastructure as Code
│   ├── bicep/
│   │   ├── main.bicep                       # Subscription-level entry
│   │   ├── modules/
│   │   │   ├── network/                     # Hub-spoke VNet, PE, NSG
│   │   │   ├── identity/                    # Managed identities, RBAC
│   │   │   ├── data/                        # SQL, Cosmos, ADLS, Blob, AI Search
│   │   │   ├── compute/                     # Container Apps, Functions
│   │   │   ├── eventing/                    # Event Grid, Service Bus, Event Hubs
│   │   │   ├── ai/                          # OpenAI, AI Search, Prompt Flow
│   │   │   ├── frontdoor/                   # Front Door + WAF
│   │   │   ├── apim/                        # API Management
│   │   │   ├── keyvault/                    # KV + HSM keys + access policies
│   │   │   ├── observability/               # LAW, App Insights, Workbooks
│   │   │   ├── powerbi/                     # Embedded workspace
│   │   │   └── security/                    # Defender plans, Sentinel, Policy
│   │   └── envs/
│   │       ├── dev.bicepparam
│   │       ├── staging.bicepparam
│   │       ├── prod.bicepparam
│   │       └── customer-hosted.bicepparam   # ISV/single-tenant mode
│   └── terraform/                           # Parity modules (optional path)
│
├── data/                                    # Reference / seed data
│   ├── frameworks-seed/                     # Initial framework reference packs
│   └── mappings-seed/                       # MITRE ↔ MCSB ↔ CIS crosswalks
│
├── scripts/                                 # Dev / ops scripts
│   ├── bootstrap/
│   ├── codegen/                             # OpenAPI → clients
│   ├── data-seed/
│   └── release/
│
└── tools/                                   # CLI utilities for operators
    ├── azurelens-cli/                       # Admin CLI (onboarding, exports)
    └── benchmark-runner/
```

> **Branch `feature/platform-foundation` includes only the documentation and `.gitignore`. All other paths above are referenced for design clarity and will be created in subsequent feature branches.**

---

## 4. Service Decomposition

### 4.1 Frontend (`apps/web`)

- **Stack**: Next.js (App Router), TypeScript, React, TanStack Query, Tailwind, MSAL.js for Entra ID auth, Power BI Embedded JS SDK.
- **Hosting**: Azure Static Web Apps (preferred for SPA/SSR hybrid) **or** Container Apps if SSR-heavy.
- **Auth**: PKCE + MSAL; tokens exchanged via API for OBO calls to Graph.
- **State**: Server state via API; minimal client state (Zustand).
- **Tenant context**: `tenant_id` carried in JWT claim and validated on every API call.
- **Role-aware UI**: navigation and widgets filtered by user role (see RBAC matrix in `SECURITY_MODEL.md`).

### 4.2 Backend API (`apps/api`)

- **Stack candidates**: ASP.NET Core 8 (primary recommendation — deep Azure SDK + Graph SDK story) **or** Python FastAPI (if AI/data team prefers Python).
- **Hosting**: Azure Container Apps, behind APIM, behind Front Door.
- **Surface**: REST (OpenAPI 3.1) + optional GraphQL for dashboard queries.
- **Auth**: Entra ID JWT validation; On-Behalf-Of (OBO) for delegated Graph calls; Managed Identity for service-to-service.
- **Concerns**:
  - Tenant resolution & isolation.
  - Read APIs for findings, scores, reports, mappings.
  - Write APIs for tenant onboarding, scan triggers, remediation acknowledgment.
  - Webhook receivers (Defender, Sentinel, Event Grid).
- **No long-running work** — anything > 5s is queued to Service Bus and handled by workers.

### 4.3 Scanning Engine (`services/scanner-*`)

Four scanner services, each independently scalable:

| Service | Inputs | Outputs |
|---|---|---|
| `scanner-azure` | ARG KQL, ARM REST, Defender for Cloud REST, Policy REST | Asset graph + posture findings |
| `scanner-m365` | Graph (Entra, EXO, SPO, Teams, OD), CA policies, OAuth grants | Identity & collaboration findings |
| `scanner-intune` | Graph Intune endpoints | Device & MDM findings |
| `scanner-defender` | Defender XDR API, Defender for Cloud, Sentinel | Alerts, incidents, secure-score deltas |
| `scanner-purview` | Purview REST, M365 DLP, sensitivity labels | Data-governance findings |

- **Pattern**: Container Apps Jobs (event-triggered) for full scans; Azure Functions (Durable) for fan-out parallelism over subscriptions / users / devices.
- **Throttling**: token-bucket per Graph endpoint; respect `Retry-After`; exponential backoff with jitter; circuit breakers via Polly / tenacity.
- **Output contract**: every scanner writes raw evidence to ADLS Gen2 and a normalized `RawFinding` envelope to a Service Bus topic. The Findings Processor (in `services/compliance-engine`) consumes, enriches, dedupes, and persists.

### 4.4 Compliance Engine (`services/compliance-engine`)

- Consumes `RawFinding` events.
- Applies framework mappings from `packages/frameworks` (versioned, signed).
- Produces normalized `Finding` records with multi-framework tags.
- Maintains per-tenant **compliance posture matrix** (framework × control × status × evidence_refs).

### 4.5 Risk Engine (`services/risk-engine`)

- Stateless scoring service.
- Inputs: `Finding`, `Asset`, optional `CampaignLink`, optional `CVEExploitStatus`.
- Formula (v1):
  ```
  risk = base_severity
       × exploitability_factor      # actively exploited (KEV) ⇒ ×1.5
       × exposure_factor             # public-facing ⇒ ×1.3
       × business_impact_factor      # tenant-defined asset criticality
       × compliance_weight           # max across mapped frameworks
       × campaign_proximity_factor   # live campaign hits this asset ⇒ ×1.4
  ```
- Aggregates: per-asset, per-control, per-framework, per-tenant **posture score (0–100)**.
- All weights are **policy objects** stored in Cosmos DB and tenant-overridable.

### 4.6 Threat Intelligence Engine (`services/ti-ingestion` + `services/ti-correlation`)

See § 7 below — TI gets its own deep-dive.

### 4.7 AI Engine (`services/ai-engine`)

See § 8 below.

### 4.8 Azure Integrations (`packages/connectors/*`)

Thin, typed, retrying, rate-limited SDK wrappers. **Every** call carries:
- a tenant context object,
- a correlation ID (W3C `traceparent`),
- a delegation mode (`Application` vs `Delegated/OBO`).

### 4.9 Background Jobs (`jobs/*`)

- **Timer Functions** for cadence (e.g., `0 */6 * * *` for posture re-scan, `0 */1 * * *` for TI pull).
- **Durable Functions** orchestrators for fan-out / fan-in scan patterns:
  - Fan-out per subscription → fan-in to compliance engine.
  - Fan-out per user batch (Graph 999/page) → fan-in to identity findings.
- **Logic Apps** for human-in-the-loop workflows (e.g., remediation approval, ticket creation in ServiceNow/Jira, Teams notifications).

### 4.10 Reporting (`services/reporting`)

- PDF (executive, technical, audit-evidence) — via Headless Chromium in Container Apps or Azure Functions Premium.
- PPTX — for board decks.
- CSV / JSON — for downstream BI / SIEM.
- Power BI Embedded — interactive dashboards with **Row-Level Security** mapped to `tenant_id` + role.
- Outputs land in Blob Storage with **immutable** retention policy for audit packs.

### 4.11 Remediation Center (`services/remediation`)

- Library of remediation templates keyed by `(finding_type, technique, framework_control)`.
- Renders Azure CLI / PowerShell / Microsoft Graph / Azure Policy JSON.
- Optional **one-click remediation** via a separate, opt-in, scoped service principal with **write** RBAC (off by default). Always behind an explicit user confirmation and a 4-eyes approval flow via Logic Apps.

### 4.12 RBAC (cross-cutting)

- **Authentication**: Entra ID (workforce or B2B; B2C deferred).
- **Authorization**: combination of (a) Entra ID app roles for coarse-grained role, (b) custom policy in API for fine-grained scope (subscription / report / framework).
- **Roles**: `GlobalAdmin`, `SecurityAdmin`, `Compliance`, `CloudArchitect`, `SOCAnalyst`, `ITManager`, `Auditor`, `ExecViewer`. Detailed matrix in `SECURITY_MODEL.md`.

---

## 5. Azure-Native Patterns

| Pattern | Where used | Why |
|---|---|---|
| **Managed Identity (System + User)** | Every compute resource | Eliminate secrets |
| **Workload Identity Federation** | GitHub Actions → Azure | No long-lived service-principal secrets |
| **Private Endpoints + Private DNS Zones** | All PaaS (SQL, Cosmos, Storage, KV, Service Bus, OpenAI) | No public data plane |
| **VNet Integration** | Container Apps + Functions | Egress through hub firewall, ingress via PE |
| **APIM (Internal)** | In front of API | Quota / throttling / schema / OAuth |
| **Front Door + WAF** | Public ingress | Global anycast, OWASP, DDoS |
| **Azure Policy + Defender for Cloud** | Platform subscription | Self-host the product on its own product principles |
| **Key Vault + CMK** | All data stores | Tenant-key separation; HSM-backed |
| **Event-driven (EG → SB → Workers)** | Scan + TI + AI pipelines | Decouple, scale, retry |
| **Durable Functions fan-out/fan-in** | Large tenant scans | Massive parallelism, checkpoints |
| **Outbox pattern** | API ↔ workers | Atomicity between DB write and event publish |
| **Saga (orchestration)** | Multi-step scan + score + report | Compensating actions on failure |
| **CQRS-light** | Reads (Cosmos read model) vs writes (SQL) | Read-optimized dashboards |
| **Idempotency keys** | All event consumers | At-least-once delivery safety |
| **Circuit breaker + retry with jitter** | All external API clients | Graceful degradation |
| **Feature flags** | Azure App Configuration | Progressive rollout, kill switches |
| **Blue/Green via Container Apps revisions** | API + workers | Zero-downtime deploys |
| **Multi-region active/active** | Enterprise tier | Front Door routing, geo-replicated SQL/Cosmos |

---

## 6. Event-Driven Workflows

### 6.1 Topics & Subscriptions

| Topic | Producers | Consumers | Notes |
|---|---|---|---|
| `tenant.lifecycle` | Onboarding API | Scanners (bootstrap), Compliance Engine, Reporting | Tenant created / updated / offboarded |
| `scan.requested` | API, Timer Functions | Durable Orchestrators | One per scan kind |
| `scan.partition` | Orchestrator | Scanner workers | Fan-out per subscription / page |
| `scan.partition.completed` | Scanner workers | Orchestrator | Fan-in checkpoints |
| `finding.raw` | All scanners | Compliance Engine | Normalize + map |
| `finding.normalized` | Compliance Engine | Risk Engine, AI Engine, Search Indexer | |
| `ti.feed.pulled` | TI Ingestion | TI Normalizer | New batch of indicators |
| `ti.indicator.normalized` | TI Normalizer | TI Correlation | Add to TI graph |
| `correlation.hit` | TI Correlation | Risk Engine, Notification | Threat ↔ asset match |
| `ai.summarize.requested` | API, Reporting | AI Engine | Generate narrative |
| `report.generate.requested` | API, Timer | Reporting | PDF/PPTX/CSV |
| `notification.dispatch` | Risk Engine, Reporting | Notification | Email/Teams/Webhook |

### 6.2 Delivery Semantics

- **At-least-once** everywhere; consumers are **idempotent** via `(event_id, tenant_id)` dedupe table in SQL.
- **Dead-letter queues** on every subscription with automated re-drive after fix.
- **Schema registry** in Azure Schema Registry (Event Hubs) or a versioned `packages/shared-types` published to internal feed; events carry `schema_version`.

### 6.3 Example: Full Tenant Scan Saga

```
1. user clicks "Run full scan"
2. API → publish scan.requested {tenant_id, kinds:[azure,m365,intune,defender,purview]}
3. Durable Orchestrator A starts
4. Orchestrator A enumerates subscriptions via ARG → publishes N × scan.partition for scanner-azure
5. Orchestrator A enumerates user batches via Graph → publishes M × scan.partition for scanner-m365
6. Each worker scans, writes raw evidence to ADLS, publishes finding.raw events
7. Compliance Engine normalizes + maps frameworks → publishes finding.normalized
8. Risk Engine scores → updates SQL aggregates + Cosmos read model
9. AI Engine generates per-section summaries (async)
10. Reporting generates PDF when all partitions complete
11. Notification dispatches "scan complete" via Teams + email
12. On any step failure, Orchestrator runs compensating actions (mark partial, alert ops)
```

---

## 7. Threat Intelligence Ingestion Architecture

### 7.1 Sources & Modalities

| Source | Protocol | Cadence | Auth |
|---|---|---|---|
| Microsoft Defender TI | Graph (`security/threatIntelligence`) | 1h | Graph App perm |
| Microsoft Sentinel TI | TAXII 2.1 (STIX 2.1) | 1h | Workspace key / OAuth |
| CISA KEV | HTTPS JSON | 6h | None |
| MITRE ATT&CK | GitHub raw STIX 2.1 | 24h | None |
| MISP | PyMISP / REST | 1h | API key in KV |
| OpenCTI | GraphQL | 1h | API key in KV |
| AlienVault OTX | REST | 1h | API key in KV |
| abuse.ch | REST (URLhaus, MalwareBazaar, ThreatFox) | 1h | API key in KV |
| VirusTotal (optional) | REST | on-demand only | API key in KV |
| GitHub Security Advisories | GraphQL | 6h | Fine-grained PAT in KV |
| CVE / NVD | JSON feed | 6h | None |

### 7.2 Pipeline

```
[Timer Function: ti-pull-{source}]
   └─► HTTP fetch (with ETag / cursor) ─► land raw to ADLS  (immutable, CMK)
         └─► emit ti.feed.pulled {source, batch_id, blob_uri}
              └─► [ti-normalizer worker]
                    - Parse STIX 2.1 / MISP / vendor JSON
                    - Map to internal TI model (Indicator, Campaign, Actor, Malware, Vulnerability, Tool, TTP)
                    - Deduplicate (sha256 over canonical form)
                    - Enrich (geo, ASN, MITRE technique back-references)
                    └─► persist to Cosmos DB (graph container)
                    └─► index searchable fields to Azure AI Search
                    └─► emit ti.indicator.normalized
                          └─► [ti-correlation worker]
                                - Query customer asset graph (Cosmos) for matches
                                - Match dimensions:
                                    · CVE ⨝ inventory (image, package, OS)
                                    · IP / domain / URL ⨝ NSG flow logs, App GW, FW logs (via LAW)
                                    · TTP ⨝ posture finding (control absent)
                                    · Campaign target sector ⨝ customer industry profile
                                    · Affected platform ⨝ customer tech stack
                                - Produce CorrelationHit {tenant_id, ti_id, asset_id, confidence}
                                └─► emit correlation.hit
                                      └─► Risk Engine boost + Notification
```

### 7.3 TI Data Model (high level)

- `Indicator` (IP, domain, URL, hash, email, regkey, etc.) → STIX `indicator`
- `Campaign` → STIX `campaign`
- `ThreatActor` → STIX `threat-actor`
- `Malware` → STIX `malware`
- `Tool` → STIX `tool`
- `Vulnerability` (CVE) → STIX `vulnerability` + KEV flag
- `AttackPattern` (TTP) → STIX `attack-pattern` (MITRE technique)
- `Mitigation` → STIX `course-of-action`
- Relationships → STIX `relationship` (uses, targets, mitigates, attributed-to)

Full schemas in `SCHEMA_DESIGN.md`.

### 7.4 Trust & Freshness

- Per-source **trust score** (0–1) configurable per tenant.
- Indicator **TTL** (e.g., commodity IOCs decay over 30/60/90 days; CVE/KEV permanent).
- **Confidence aggregation**: weighted average across sources reporting the same indicator.
- **Tenant-private TI** opt-in: customers can push their own indicators via API.

---

## 8. AI Orchestration Architecture

### 8.1 Goals

- Translate technical findings into **business-grade narrative**.
- Recommend **prioritized, actionable** remediations.
- Power a **conversational copilot** grounded in the tenant's own data (RAG).
- **Never** invent findings — AI summarizes structured inputs; it does not generate raw findings.

### 8.2 Components

```
┌──────────────────────────────────────────────────────────────────┐
│                     AI Engine (services/ai-engine)               │
│                                                                  │
│   ┌────────────────┐    ┌────────────────┐    ┌──────────────┐   │
│   │ Prompt Library │ ─► │ Prompt Router  │ ─► │ Azure OpenAI │   │
│   │  (versioned,   │    │ (selects model │    │ (GPT-4 class │   │
│   │   reviewed)    │    │  + template)   │    │  deployments)│   │
│   └────────────────┘    └───────┬────────┘    └──────┬───────┘   │
│                                 │                     │           │
│                                 ▼                     ▼           │
│                         ┌──────────────┐     ┌───────────────┐    │
│                         │   RAG via    │     │ Output Guard  │    │
│                         │  AI Search   │     │ (schema, PII, │    │
│                         │ (per-tenant  │     │ injection,    │    │
│                         │  index)      │     │ profanity)    │    │
│                         └──────────────┘     └───────┬───────┘    │
│                                                      │            │
│                                                      ▼            │
│                                              ┌──────────────┐     │
│                                              │  Audit Log   │     │
│                                              │ (prompt+resp)│     │
│                                              └──────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

### 8.3 Use Cases & Templates

| Use case | Template id | Inputs | Output schema |
|---|---|---|---|
| Executive summary | `exec.summary.v1` | tenant scores, top 10 findings, top campaigns | Markdown narrative |
| Finding explanation | `finding.explain.v1` | one `Finding` + framework tags | Plain-language paragraph |
| Remediation drafting | `finding.remediate.v1` | one `Finding` + asset metadata | Steps + CLI/PS snippets |
| Campaign briefing | `campaign.brief.v1` | one `Campaign` + correlation hits | Briefing with relevance |
| Compliance evidence | `compliance.evidence.v1` | framework + controls + findings | Auditor-style narrative |
| Copilot Q&A | `copilot.qa.v1` | user question + tenant context | Grounded answer with citations |

### 8.4 RAG Indexing

- **Per-tenant** AI Search index (logical isolation; physical separation in Enterprise tier).
- Sources indexed:
  - Normalized findings (last N scans).
  - Framework reference packs (read-only, shared across tenants but tagged).
  - TI normalized records relevant to tenant (post-correlation).
  - Remediation playbook library.
- Chunking strategy: structured-first (one chunk per finding/control/campaign) + supplementary prose chunks; embeddings via `text-embedding-3-large`.

### 8.5 Safety, Privacy, Cost

- **No training on customer data**; Azure OpenAI with data-residency commitments.
- **Prompt-injection mitigation**: input sanitization, system-prompt isolation, tool-use schema validation, citation requirement for copilot answers.
- **PII redaction** before logging prompts/responses.
- **Token budgets** per tenant per day; overage soft-blocks with notification.
- **Model routing**: cheap model (e.g., 4o-mini) for short summaries; capable model for executive narrative; embeddings model for RAG.
- **Determinism**: temperature ≤ 0.3 for findings; ≤ 0.5 for executive narrative; 0 for compliance evidence.

---

## 9. Multi-Tenant Considerations

| Concern | Approach |
|---|---|
| **Tenant identity** | Customer Entra ID `tenantId` (GUID) is the canonical key |
| **Data isolation** | Every table has `tenant_id` partition key; SQL row-level security; Cosmos partition key = `tenant_id` |
| **Storage isolation** | Per-tenant container in ADLS Gen2 with CMK from per-tenant key in Key Vault |
| **Index isolation** | AI Search: per-tenant index (Enterprise) or per-tenant filter (Pro) |
| **Compute isolation** | Shared compute by default; dedicated Container Apps environment in Enterprise tier |
| **Network isolation** | Optional dedicated Private Endpoint + dedicated APIM product per Enterprise customer |
| **Quotas & throttling** | Per-tenant token bucket at APIM; per-tenant Service Bus session keys |
| **Audit** | Every action logged with `tenant_id, user_id, action, resource, outcome`; immutable storage |
| **Offboarding** | Soft-delete with grace period → hard-delete that cascades to all stores + AI Search + Blob; verifiable certificate of deletion |
| **Customer-hosted mode** | Entire IaC tree can deploy single-tenant into customer subscription; updates delivered via signed Bicep releases |

---

## 10. Scanning Strategy

### 10.1 Strategies per source

| Source | Strategy |
|---|---|
| Azure Resource Graph | KQL queries, paged 1000/req, parallel per subscription, cached graph |
| ARM REST | Only for properties ARG doesn't expose; per-RP throttle aware |
| Microsoft Graph | Delta queries (`@odata.deltaLink`) for users/devices/groups; full sweep weekly |
| Defender for Cloud | Recommendations + Secure Score + Sub-assessments REST; incremental via timestamps |
| Defender XDR | Advanced Hunting KQL (limited per query); pull alerts/incidents via REST |
| Sentinel | Workspace KQL via LAW; TI via TAXII |
| Intune | Graph beta endpoints where required; per-device pull with batching (`$batch`) |
| Purview | REST with scope filters |

### 10.2 Scan kinds

- **Bootstrap** (full, on tenant onboarding).
- **Continuous incremental** (delta-based, every 15–60 min).
- **Scheduled full** (daily or weekly).
- **On-demand** (user-triggered).
- **Targeted** (single asset / single framework re-scan after remediation).

### 10.3 Performance budgets

- Bootstrap of a 10k-identity / 5k-resource tenant ≤ **30 minutes** wall-clock.
- Incremental scan ≤ **5 minutes** P95.
- API read endpoints ≤ **300 ms** P95 (cached read model).
- Dashboard initial load ≤ **2 s** P95.

---

## 11. Observability

- **Traces**: OpenTelemetry, sent to Application Insights; trace ID propagated through Service Bus / Event Grid via custom headers.
- **Logs**: structured JSON, shipped to Log Analytics Workspace; redaction middleware strips PII.
- **Metrics**: per-service RED metrics, per-pipeline lag metrics, per-tenant scan duration & cost.
- **Dashboards**: Azure Workbooks for ops; Grafana (optional) on top of LAW.
- **SLOs**:
  - Scan completeness 99.5% / 30d.
  - API availability 99.9% (Pro), 99.95% (Enterprise).
  - TI freshness P95 ≤ 90 min.
- **Alerting**: action groups → PagerDuty / Teams; runbooks linked from every alert.

---

## 12. CI/CD

| Pipeline | Trigger | Steps |
|---|---|---|
| `pr-validate` | PR open / push | lint, typecheck, unit tests, security scan, IaC plan |
| `build-and-publish` | merge to main | build container images, sign (Notary v2 / Cosign), push to ACR |
| `deploy-dev` | post-build | Bicep `what-if` + deploy to dev; smoke tests |
| `deploy-staging` | manual approval | deploy via Container Apps revision (blue/green) |
| `deploy-prod` | manual approval + change ticket | progressive rollout (10/50/100), automatic rollback on SLO burn |
| `release-customer-hosted` | tag `chx-*` | publish signed Bicep bundle to customer release feed |

- **Auth**: GitHub OIDC → Azure (no PATs). One federated credential per environment.
- **Secrets**: none in repo; Key Vault references via Container Apps and Functions.
- **Supply chain**: SBOM (SPDX) per image; container signing; dependency scanning (Dependabot + GHAS); SAST (CodeQL).
- **Quality gates**: ≥ 80% test coverage on engines; Bicep PSRule pass; Defender for DevOps clean.

---

## 13. Enterprise Scalability

| Axis | Approach |
|---|---|
| **Compute scale** | Container Apps KEDA scalers (Service Bus length, CPU); Functions Premium with elastic scale |
| **Data scale** | SQL Hyperscale; Cosmos autoscale RU; ADLS Gen2 unlimited; AI Search S2+ replicas |
| **Region scale** | Multi-region active/active for API + read replicas for SQL/Cosmos; Front Door priority/weighted routing |
| **Throughput** | Event Hubs partitions sized to per-tenant TI volume; Service Bus partitioned topics |
| **Tenant scale** | Sharding strategy: `tenant_id` → shard map; new shards added without downtime |
| **Cost** | FinOps tagging on all resources; per-tenant cost attribution; reservation/savings-plan modeling |
| **Compliance scale** | New framework added as a versioned reference pack + new mappings — no code change |

---

## 14. Open Design Decisions

These will be resolved during the MVP phase and tracked in `ROADMAP.md`:

1. **API language**: ASP.NET Core 8 (recommended) vs Python FastAPI.
2. **Findings store**: Azure SQL (recommended for relational + audit) vs Cosmos DB exclusively.
3. **Workflow engine**: Durable Functions vs Logic Apps Standard vs Dapr Workflows.
4. **Search**: Azure AI Search vs Cosmos DB full-text + vector.
5. **Customer-hosted update channel**: Marketplace SaaS offer vs ARM-template release feed.
6. **One-click remediation**: included in v1 (opt-in) vs deferred to v2.
7. **B2C / partner portal**: deferred; revisit post-GA.

---

## 15. References (informational)

- Azure Architecture Center — Reliable web app, Event-driven, Multi-tenant SaaS patterns.
- Microsoft Cloud Security Benchmark v1.x.
- MITRE ATT&CK Enterprise & Cloud matrices.
- STIX 2.1 / TAXII 2.1 specifications.
- Microsoft Graph & Azure Resource Graph documentation.
- Azure Well-Architected Framework pillars.
- Azure Zero Trust deployment guidance.

---

*This document is updated alongside every architectural change. Significant changes require an ADR (`docs/adr/NNNN-title.md`, to be introduced in the next milestone).*
