# AzureLens — Azure Services Catalog

Every Azure service the platform uses: **what it does**, **why it's chosen**, **SKU/tier**, **scaling profile**, **security posture**, and **alternatives considered**. Used as the design contract for the IaC modules that will be authored in later phases.

> The platform is "Azure-native first." If a capability can be delivered by a managed Azure service with comparable cost/feature parity to a self-hosted option, we choose the managed service.

---

## 1. Service Selection Principles

1. **Managed > self-hosted** unless cost or capability gap is unacceptable.
2. **PaaS with Private Endpoint** > anything with public data plane.
3. **Workload identity (MI / federated)** > keys or shared secrets.
4. **CMK-capable** services preferred for any data store.
5. **Multi-region capable** services preferred for anything in the request path.
6. **Cost transparency** — services that support per-tenant tag attribution for FinOps.
7. **Microsoft Cloud Security Benchmark coverage** — services with full MCSB controls preferred.

---

## 2. Compute

### 2.1 Azure Container Apps (primary compute)

- **Uses**: Backend API, scanner workers, TI workers, AI engine, reporting, notification.
- **Why**: Serverless-style scaling with KEDA, revisions for blue/green, VNet integration, Dapr-ready.
- **SKU**: Consumption + Dedicated workload profile for AI/heavy jobs.
- **Scaling**: KEDA scalers on Service Bus length, CPU, HTTP concurrency; min/max replicas per app.
- **Security**: System-assigned MI; internal ingress with Private Link; VNet integrated.
- **Alternatives considered**:
  - *AKS* — too operationally heavy for our service count and team size; revisit at scale.
  - *App Service* — solid for the API alone, weaker fit for many event-driven workers.
  - *Azure Functions* — used selectively for triggers and short orchestrations; not used as the primary HTTP API.

### 2.2 Azure Functions (Premium plan)

- **Uses**: Timer-triggered jobs (TI pull, posture re-scan cadence), Event-Grid-triggered short workers, Durable Functions orchestrators for fan-out/fan-in scans.
- **Why**: Built-in triggers + Durable Task Framework for sagas; VNet integration on Premium.
- **SKU**: EP1 baseline; scale to EP3 under load; pre-warmed instances to avoid cold starts.
- **Security**: System-assigned MI; VNet integration; Private Endpoints to dependencies.
- **Alternatives**: Container Apps Jobs for batch only — used in parallel for long-running scans, but Functions remain the better fit for triggers and Durable orchestrations.

### 2.3 Azure Static Web Apps (frontend)

- **Uses**: `apps/web` Next.js hosting.
- **Why**: Global edge, integrated auth (but we use MSAL directly), Linked Backends for the API.
- **SKU**: Standard (for SLA + custom auth + Private Endpoint on backend).
- **Alternatives**: Container Apps for the web app — chosen only if heavy SSR/streaming is required.

---

## 3. Networking

### 3.1 Azure Front Door (Premium)

- **Uses**: Global ingress for `apps/web` and APIM.
- **Why**: WAF Premium (Bot Manager, managed rule sets), Private Link origin, anycast, DDoS L7, custom domains/cert mgmt.
- **SKU**: Premium.
- **Alternatives**: Application Gateway — regional only; chosen as a fallback for single-region deployments.

### 3.2 Azure API Management (Internal)

- **Uses**: API gateway in front of `apps/api`.
- **Why**: Quota, throttling, OAuth validation, schema validation, transformation, developer portal (for partners later).
- **SKU**: Premium (multi-region, VNet integration, AZ redundancy).
- **Alternatives**: Front Door alone — lacks fine-grained API policy.

### 3.3 Virtual Network + Subnets (hub-spoke)

- **Hub**: Azure Firewall, Bastion, Private DNS Resolver, shared Private DNS zones.
- **Spokes**: per-environment subnets for compute, data, eventing, observability.
- **Security**: NSGs deny-by-default, ASGs for workload grouping, UDRs forcing egress through Azure Firewall.

### 3.4 Azure Firewall (Premium)

- **Uses**: All outbound traffic from compute subnets.
- **Why**: FQDN tags (Microsoft Graph, ARM), TLS inspection, IDPS, threat-intel-based filtering.
- **SKU**: Premium.

### 3.5 Azure DDoS Protection Standard

- **Uses**: Subscription-wide protection for VNets and public IPs.

### 3.6 Azure Bastion (Standard)

- **Uses**: Operator access to any temporary jump host; primary admin is browser/CLI via portal + PIM.

### 3.7 Private Endpoints + Private DNS Zones

- **For**: SQL, Cosmos, Storage, Key Vault, Service Bus, Event Hubs, AI Search, OpenAI, ACR, App Configuration, APIM (internal).

---

## 4. Data

### 4.1 Azure SQL Database (Business Critical / Hyperscale)

- **Uses**: Tenants, users, findings (current + history), scores, remediation actions, reports metadata, audit dedupe.
- **Why**: Relational integrity, RLS for tenant isolation, point-in-time restore 35d, geo-replication, transparent CMK.
- **SKU**: Business Critical (Pro) → Hyperscale (Enterprise) with read replicas.
- **Security**: Microsoft Entra-only authentication, Private Endpoint only, TDE with CMK, Advanced Threat Protection (Defender for SQL).
- **Alternatives**: Postgres Flexible Server — strong alternative if team prefers; SQL chosen for RLS maturity and Defender depth.

### 4.2 Azure Cosmos DB (NoSQL API)

- **Uses**: Asset graph + edges, TI corpus (STIX), TI correlations, AI prompt log, reference mappings cache.
- **Why**: Single-digit-ms latency, partition-key isolation per tenant, autoscale RU, change feed for downstream processing, multi-region writes in Enterprise.
- **SKU**: Autoscale; serverless for low-traffic preview.
- **Security**: RBAC data plane, Private Endpoint, CMK, total request rate caps per tenant.
- **Alternatives**: Cosmos DB for PostgreSQL (Citus) — chosen for graph workload only if relational semantics dominate. Neo4j Aura — out-of-platform dependency, avoided.

### 4.3 Azure Storage — ADLS Gen2 + Blob

- **Uses**: Raw scan evidence (ADLS), reports & exports (Blob).
- **Why**: Cheap, immutable retention (WORM), CMK, lifecycle policies (cool → archive).
- **SKU**: Standard ZRS minimum; GRS for audit-evidence containers.
- **Security**: Defender for Storage, Private Endpoint only, network rules deny-public, OAuth (no SAS keys except short-lived user-delegation SAS).

### 4.4 Azure AI Search

- **Uses**: TI lexical + vector search; RAG corpus for AI Engine.
- **Why**: Hybrid (BM25 + vector) ranking, semantic ranker, per-tenant indexes possible.
- **SKU**: S1 baseline; S2/S3 with replicas for Enterprise.
- **Security**: MI auth, Private Endpoint, CMK.

### 4.5 Azure Key Vault (Premium / HSM)

- **Uses**: Customer connector secrets (MISP/OTX/VT), platform secrets, CMKs for all data stores, certificates.
- **Why**: HSM-backed keys, soft-delete + purge protection, RBAC mode, audit to LAW.
- **SKU**: Premium with HSM-backed keys for production. Managed HSM for Enterprise per-tenant CMK in regulated tiers.
- **Security**: RBAC, Private Endpoint, deny-by-default, alerting on any unauthorized `getSecret`.

### 4.6 Azure App Configuration

- **Uses**: Feature flags, non-secret config (model deployment names, framework pack versions).
- **Why**: Hot-reload, labels per env, Key Vault references for secrets.
- **SKU**: Standard with geo-replication.

### 4.7 Azure Backup + Recovery Services Vault

- **Uses**: Backups for SQL (managed); for any IaaS introduced later.
- **Why**: CMK, immutable vaults, soft-delete, cross-region restore.

---

## 5. Eventing & Messaging

### 5.1 Azure Service Bus (Premium)

- **Uses**: Topics/queues for scan, TI, AI, reporting, notification pipelines.
- **Why**: Sessions (per-tenant ordering), dead-letter, scheduled messages, MI auth, geo-DR.
- **SKU**: Premium (4 MU baseline; scale per region load).
- **Security**: MI auth (no SAS), Private Endpoint, CMK.
- **Alternatives**: Storage Queues — too limited; Kafka via Event Hubs — used for high-volume telemetry, not transactional events.

### 5.2 Azure Event Grid

- **Uses**: System events (Blob created → trigger TI normalizer; Cosmos change feed → indexer); custom topics for cross-service fan-out.
- **Why**: Push delivery, schemas, dead-lettering, advanced filters.
- **SKU**: Basic for system topics; Premium namespace if MQTT/Domain features needed.

### 5.3 Azure Event Hubs (Standard)

- **Uses**: High-volume firehose ingestion (TI normalized stream, telemetry shipping).
- **Why**: Partition scale, Kafka surface for downstream Spark/Synapse if added later.
- **SKU**: Standard with auto-inflate; Dedicated only at extreme scale.

### 5.4 Azure Logic Apps (Standard)

- **Uses**: Human-in-the-loop workflows (remediation approvals, ServiceNow/Jira tickets, Teams notifications, partner connectors).
- **Why**: Hundreds of pre-built connectors; designer-friendly for ops.
- **SKU**: Standard (single-tenant) with VNet integration.
- **Alternatives**: Power Automate — preferred when end-user-built; Logic Apps for platform workflows.

---

## 6. AI

### 6.1 Azure OpenAI Service

- **Uses**: Executive narrative, finding explanation, remediation drafting, copilot Q&A, embeddings.
- **Why**: Azure data residency, no training on customer data, regional deployments, content filters, MI auth.
- **Models**: GPT-4 class for narrative & copilot; smaller GPT-class for short summaries; `text-embedding-3-large` for embeddings.
- **SKU**: Pay-as-you-go (PTU for predictable Enterprise tier).
- **Security**: Private Endpoint, MI auth, per-deployment RBAC, content filtering, abuse monitoring opt-out evaluated per tier.
- **Alternatives**: Azure AI Foundry hosted models (Phi/Mistral) — evaluated for cheap routes; OpenAI fallback only via Azure OpenAI for compliance reasons.

### 6.2 Azure AI Search (RAG)

- See § 4.4.

### 6.3 Azure AI Content Safety (optional)

- **Uses**: Output filtering for AI engine (in addition to OpenAI content filters); detect prompt-injection patterns.
- **SKU**: Standard.

### 6.4 Azure Machine Learning (future)

- **Uses**: Optional later — anomaly detection on posture drift, predictive risk modeling.
- Not in MVP scope.

---

## 7. Observability

### 7.1 Azure Monitor + Log Analytics Workspace

- **Uses**: Logs, metrics, KQL queries, workbooks; LAW-backed Sentinel.
- **Why**: Native to every Azure service; cheap retention tiers; integrated with Application Insights.
- **SKU**: Pay-as-you-go with commitment tiers as volume grows.

### 7.2 Application Insights

- **Uses**: APM for API + workers (OpenTelemetry).
- **Why**: Distributed tracing, live metrics, dependency mapping.

### 7.3 Microsoft Sentinel

- **Uses**: SIEM on the *platform's own* telemetry (control-plane logs, Defender alerts, custom analytics rules for cross-tenant access attempts, mass-export, KV anomalies).
- **Why**: Native integration; analytics rules for our own threat model.
- **SKU**: LAW commitment tier.

### 7.4 Azure Monitor Workbooks / Managed Grafana (optional)

- **Uses**: Operator dashboards; Grafana only if visualization needs exceed Workbooks.

### 7.5 Azure Chaos Studio

- **Uses**: Quarterly chaos drills (region loss, dependency unavailability).

---

## 8. Security & Governance

### 8.1 Microsoft Defender for Cloud (all plans relevant)

- **Plans enabled**: Servers P2, App Service, Storage, SQL, Open-source DB (when applicable), Containers, Key Vault, Resource Manager, DNS, AI services (Defender for AI), APIs.
- **Why**: Continuous posture management for our own subscription + threat protection for runtime.
- **Self-eating-dogfood**: AzureLens uses Defender for Cloud findings as one input to its own posture; the same posture we recommend to customers.

### 8.2 Microsoft Defender for DevOps

- **Uses**: Security findings in GitHub repos; secret scanning, IaC scanning, code scanning.

### 8.3 Azure Policy + Initiative

- **Uses**: Enforce platform standards (no public IPs, Private Endpoints mandatory, CMK mandatory, mandatory tags, locations allowlist).
- **Why**: Continuous compliance; prevents drift.

### 8.4 Microsoft Entra ID (PIM, Conditional Access)

- **Uses**: All platform identity; PIM for operator JIT; CA for phishing-resistant MFA enforcement.

### 8.5 Microsoft Purview

- **Uses (future)**: Data classification across the platform's own data estate; not in MVP.

---

## 9. CI/CD & DevEx

### 9.1 GitHub Actions

- **Uses**: All CI/CD; OIDC federation to Azure (no PATs).
- **Why**: Native to our repo host; first-class OIDC.
- **Alternatives**: Azure DevOps Pipelines — equivalent; not chosen because the repo is on GitHub.

### 9.2 Azure Container Registry (Premium)

- **Uses**: Container images for API + workers.
- **Why**: Geo-replication, content trust (Cosign / Notary v2), Defender for Containers integration, MI access.
- **SKU**: Premium with geo-replication.

### 9.3 Azure Deployment Environments (optional)

- **Uses**: Ephemeral developer environments based on Bicep templates.

### 9.4 Azure Load Testing

- **Uses**: Pre-release performance gates on API and scan throughput.

---

## 10. Reporting & BI

### 10.1 Power BI Embedded

- **Uses**: Interactive dashboards inside the web app (Executive, Compliance, Identity, Device, Threat).
- **Why**: Enterprise-grade visualization; RLS bound to `tenant_id` + role; export to PPTX/PDF.
- **SKU**: A1 baseline (per-region capacity); scale to A4/F-series with growth.
- **Security**: Embedded via service principal; RLS enforced at dataset level.

### 10.2 Headless Chromium (in Container Apps Jobs)

- **Uses**: Render PDF / PPTX reports from web templates.
- **Alternatives**: Power BI export, Azure Functions with native libs — chosen Headless Chromium for layout control.

---

## 11. Microsoft APIs Consumed (not deployed, but central to the platform)

| API | Purpose |
|---|---|
| Microsoft Graph (v1.0 + beta) | Identity, devices, mail/teams/SPO, Intune, security, reports |
| Azure Resource Graph | Cross-subscription resource inventory at KQL speed |
| Azure ARM REST | Properties not exposed via ARG |
| Microsoft Defender for Cloud REST | Recommendations, sub-assessments, Secure Score |
| Microsoft Sentinel REST + Log Analytics KQL | Analytics rules, incidents, TI |
| Microsoft Defender XDR (Security API) | Alerts, incidents, Advanced Hunting |
| Microsoft Intune Graph endpoints | Devices, compliance, configuration |
| Microsoft Purview REST | Data governance, sensitivity labels, DLP |
| Azure Policy REST | Definitions, assignments, compliance state |
| Azure Key Vault REST | Customer KV reads (if customer authorizes) |

---

## 12. SKU & Cost Profile (illustrative)

| Service | Dev | Pro tenant baseline | Enterprise tenant baseline |
|---|---|---|---|
| Container Apps | Consumption | Consumption + dedicated for AI | Dedicated env per Enterprise customer |
| Functions | EP1 | EP1 | EP3 |
| SQL DB | S2 / Basic | Business Critical Gen5 8vCore | Hyperscale 16+ vCore with replicas |
| Cosmos DB | Serverless | Autoscale 4k RU starting | Autoscale 40k+ RU, multi-region writes |
| Storage | Standard LRS | Standard ZRS | GRS for evidence, ZRS for working |
| KV | Standard | Premium HSM | Premium HSM + Managed HSM optional |
| AI Search | Basic | S1 | S2/S3 with replicas; per-tenant index |
| OpenAI | PAYG | PAYG with quotas | PTU committed |
| Service Bus | Standard | Premium 1 MU | Premium 4+ MU |
| Event Hubs | Standard 1 TU | Standard 2 TU | Dedicated cluster (only at extreme scale) |
| APIM | Developer | Premium 1 unit | Premium multi-region |
| Front Door | Standard | Premium | Premium with multiple endpoints |
| Power BI Embedded | A1 | A2 | F-series capacity |

Cost tagging convention: every resource tagged with `env`, `service`, `tier`, `tenant_id` (where applicable), `owner`.

---

## 13. Region Strategy

- **Pro**: single primary region with paired-region geo-replication for SQL + Cosmos + Storage. Active-passive failover.
- **Enterprise**: active-active across two paired regions for API + read replicas. Front Door priority routing with health probes.
- **Sovereign**: Azure Government and Azure China deployments are scoped separately (Phase 10+).

---

## 14. Out of Scope / Explicitly Rejected

- **AKS** as primary compute — too much operational surface for current team size; revisit if we add streaming / Spark / heavy ML.
- **Synapse / Fabric** in MVP — Cosmos + SQL + AI Search cover analytical needs through Phase 7. Consider Fabric for cross-tenant analytics later.
- **Service Fabric** — superseded by Container Apps + AKS for our needs.
- **Azure Spring Apps** — irrelevant to our stack.
- **Self-managed Postgres/Mongo/Elasticsearch** — managed equivalents exist.

---

## 15. Mapping back to Architecture

Every Azure service above appears in `docs/ARCHITECTURE.md` § 2 (logical architecture) and the IaC plan in `docs/ROADMAP.md`. Changes to this catalog require a corresponding update to both — enforced via PR checklist.
