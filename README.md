# AzureLens — Cloud Threat & Compliance Exposure Analyzer (CTCEA)

> **Azure-native, AI-augmented Cloud Security Posture, Compliance, and Live Threat Exposure platform for Azure and Microsoft 365 tenants.**

AzureLens is an enterprise-grade, multi-tenant SaaS (also deployable as a dedicated single-tenant ISV solution inside the customer's Azure subscription) that continuously scans an organization's Azure tenant, Microsoft 365 environment, identities, devices, resources, policies, and configurations, then maps the findings against **live threat intelligence**, **MITRE ATT&CK**, and **major compliance frameworks** (CIS, NIST CSF, ISO 27001, SOC 2, GDPR, Microsoft Cloud Security Benchmark, Azure Well-Architected, Zero Trust, M365 baselines).

It behaves like a unified combination of **Defender for Cloud CSPM + Secure Score + Sentinel TI + Purview compliance + MITRE ATT&CK exposure + AI security advisor**, but presented through a **single executive-friendly and technically rigorous experience**.

---

## 1. Product Name Ideas

| Name | Positioning |
|---|---|
| **AzureLens** (working name) | "See your Azure clearly" — posture + exposure clarity |
| **CloudThreatLens** | Threat-intel-led CSPM |
| **TenantPulse** | Continuous tenant heartbeat |
| **PostureIQ for Azure** | AI-driven posture intelligence |
| **SentinelGrade** | Sentinel-aligned grading platform |
| **M365 GuardScore** | M365-centric scoring brand |
| **NorthStar Cloud Security** | Executive narrative brand |

The repository name `azurelens` is used throughout this design.

---

## 2. Problem Statement

Modern enterprises operate sprawling Azure and Microsoft 365 estates with thousands of identities, devices, resources, and policies. Existing native tooling is powerful but **fragmented**:

- Defender for Cloud covers Azure resource posture, but not M365 / Entra deeply.
- Secure Score covers M365, but is identity- and license-centric.
- Sentinel surfaces TI and incidents, but does not perform tenant-wide static posture analysis.
- Purview covers data compliance, but not infrastructure exposure.
- None of them answer the executive question: **"Which active, real-world attack campaigns can hit *us* today, and what is the single prioritized list of things we must fix?"**

AzureLens unifies posture, compliance, identity, device, and **live threat-to-environment mapping** into one continuously-updated, AI-summarized, evidence-backed view.

---

## 3. Target Users

| Persona | Primary Outcome |
|---|---|
| **CISO / Security Executive** | Board-grade posture & exposure narrative |
| **Security Administrator** | Prioritized remediation backlog |
| **Compliance Officer** | Framework-mapped evidence for audits |
| **Cloud Architect** | Well-Architected & Zero Trust gap analysis |
| **SOC Analyst** | Threat-campaign-to-asset correlation |
| **IT Manager** | Device, Intune, and identity hygiene |
| **Auditor (external/internal)** | Read-only evidence-based audit reports |
| **Executive Viewer** | High-level dashboards only |

---

## 4. Main Features

1. Continuous **Azure Tenant Scanner** (subscriptions, RGs, IaaS, PaaS, networking, IAM, policy, Defender).
2. **Microsoft 365 Security Scanner** (Entra ID, Conditional Access, MFA, OAuth consent, EXO/SPO/Teams/OD).
3. **Device & Intune Scanner** (compliance, configuration, endpoint security, Defender onboarding).
4. **Compliance Gap Analyzer** (CIS, NIST, ISO, SOC 2, GDPR, MCSB, M365 baseline).
5. **Live Threat Intelligence Engine** (Defender TI, Sentinel TI, CISA KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch, VT, GHSA, CVE/NVD).
6. **Threat-to-Environment Mapping Engine** (correlates live campaigns and TTPs to the customer's actual posture).
7. **Risk Scoring Engine** (severity × exploitability × exposure × business impact × compliance impact × active-exploitation flag).
8. **AI Analysis Engine** (Azure OpenAI summarization, executive narrative, remediation drafting, Q&A copilot).
9. **Remediation Center** (Azure CLI / PowerShell / Graph snippets, policy templates, doc links).
10. **Reporting & Dashboards** (Power BI Embedded, role-aware views, exportable executive/technical/audit reports).

See `docs/ARCHITECTURE.md` for the full module decomposition.

---

## 5. Azure-Native Architecture (Summary)

- **Frontend**: Azure Static Web Apps or Container Apps (React/Next.js + TypeScript).
- **Backend API**: Azure Container Apps (ASP.NET Core / Python FastAPI) behind Azure Front Door + WAF + Private Link.
- **Scanning Engine**: Azure Container Apps Jobs + Azure Functions (Durable Functions for long-running scans).
- **Threat Intelligence Engine**: Azure Functions (timer + event) + Service Bus + Cosmos DB (TI graph) + Azure AI Search.
- **AI Engine**: Azure OpenAI (GPT-4 class) + Azure AI Search (RAG) + Prompt Flow.
- **Data**: Azure SQL (transactional) + Cosmos DB (graph / TI / findings) + ADLS Gen2 (raw scan evidence) + Blob (reports).
- **Eventing**: Event Grid + Service Bus (topics/queues) + Event Hubs (high-volume telemetry).
- **Secrets / Identity**: Azure Key Vault + Managed Identity + Entra ID Workload Identity Federation.
- **Observability**: Azure Monitor + Application Insights + Log Analytics + Workbooks.
- **Governance**: Azure Policy, Defender for Cloud, Microsoft Sentinel hooked into the platform's own subscription.
- **Networking**: Hub-spoke VNets, Private Endpoints for every PaaS, no public data plane.
- **IaC**: Bicep (primary) + Terraform parity modules for ISV/customer-deployed mode.
- **CI/CD**: GitHub Actions with OIDC federation to Azure (no long-lived secrets) + environment gates.

Full diagrams and decomposition in `docs/ARCHITECTURE.md` and Azure-service rationale in `docs/AZURE_SERVICES.md`.

---

## 6. Required Microsoft Permissions (High Level)

Application uses **Managed Identity** (for in-Azure resources it owns) and a **multi-tenant Entra ID application** with admin-consented permissions for customer tenants. Least-privilege, read-only where possible.

**Microsoft Graph (Application permissions):**
`Directory.Read.All`, `Policy.Read.All`, `Policy.Read.ConditionalAccess`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `SecurityEvents.Read.All`, `ThreatIndicators.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `Application.Read.All`, `Group.Read.All`, `User.Read.All`, `Reports.Read.All`, `SecurityActions.Read.All`, `SecurityAlert.Read.All`, `InformationProtectionPolicy.Read.All`.

**Azure ARM / Resource Graph (RBAC):**
`Reader` at root management group, `Security Reader`, `Reader and Data Access` (Storage), optional `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Microsoft Defender for Cloud Reader`.

**Defender XDR / Microsoft 365 Defender APIs:**
`SecurityIncident.Read.All`, `SecurityAlert.Read.All`, `Machine.Read.All`, `AdvancedHunting.Read.All`.

**Purview:**
`InformationProtectionPolicy.Read.All`, Purview RBAC `Data Reader` role.

A full, normative matrix lives in `docs/SECURITY_MODEL.md`.

---

## 7. Security Model (Summary)

- Multi-tenant SaaS isolation at data layer (tenant_id partitioning) **or** dedicated single-tenant deployment ("Customer-Hosted Mode") via Bicep into the customer's subscription.
- All customer credentials and certificates in **Azure Key Vault** with HSM-backed keys; **no plaintext secrets** anywhere.
- **Customer-Managed Keys (CMK)** support for all data stores.
- Entra ID **Workload Identity Federation** for CI/CD (no PATs / no client secrets).
- **Just-In-Time** and **PIM**-style elevated access for platform operators.
- Full audit logging to immutable storage; integrated with Microsoft Sentinel.
- Zero Trust internal: every service-to-service hop authenticated via Managed Identity + Entra ID tokens.
- Threat model in `docs/THREAT_MODEL.md`; security controls in `docs/SECURITY_MODEL.md`.

---

## 8. Data Flow (Summary)

```
Customer Tenant (Azure + M365)
  └─► [Connectors via Graph / ARG / Defender / Sentinel / Intune / Purview]
        └─► Scanning Engine (Container Apps Jobs + Durable Functions)
              └─► Raw evidence  ─► ADLS Gen2 (immutable, CMK)
              └─► Normalized findings ─► Service Bus ─► Findings Processor
                    └─► Azure SQL (transactional findings + scores)
                    └─► Cosmos DB (graph: assets ↔ findings ↔ TTPs ↔ campaigns)
Threat Intel Sources (Defender TI, Sentinel TI, CISA KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch, VT, GHSA, NVD)
  └─► TI Ingestion Functions ─► Normalizer ─► Cosmos DB (TI graph) + AI Search index
        └─► Correlation Engine ─► joins TI graph ⨝ Customer asset graph
              └─► Threat-to-Environment mappings ─► Risk Scoring Engine
                    └─► AI Engine (Azure OpenAI + RAG over AI Search)
                          └─► Reports (Blob) + Power BI dataset + API
                                └─► Frontend (role-aware UI)
```

Detail in `docs/ARCHITECTURE.md` and `docs/SCHEMA_DESIGN.md`.

---

## 9. Threat Intelligence Sources

Microsoft Defender TI, Microsoft Sentinel TI (TAXII/STIX), CISA KEV catalog, MITRE ATT&CK (STIX 2.1), MISP, OpenCTI, AlienVault OTX, abuse.ch (URLhaus, MalwareBazaar, ThreatFox), VirusTotal (optional, paid), GitHub Security Advisories (GHSA), CVE/NVD JSON feeds.

Ingestion strategy in `docs/ARCHITECTURE.md` § Threat Intelligence Engine.

---

## 10. Compliance Framework Mapping

Each finding is tagged with a multi-framework control mapping:

`MITRE ATT&CK technique(s)` → `MCSB control` → `CIS Azure Benchmark control` → `NIST CSF subcategory` → `ISO 27001 Annex A control` → `SOC 2 TSC criterion` → `GDPR article(s)` → `Zero Trust pillar` → `Azure WAF pillar` → `M365 baseline control`.

Reference data is stored in versioned reference packs in Cosmos DB and rebuilt monthly. Schema in `docs/SCHEMA_DESIGN.md`.

---

## 11. MITRE ATT&CK Mapping Approach

- Maintain a normalized internal model of Tactics → Techniques → Sub-techniques → Procedures.
- Map **detective** signals (configuration weakness ↔ technique) and **preventive** signals (control presence ↔ mitigation).
- Cloud-specific: weight Azure / M365 / Entra-relevant techniques higher (T1078 Valid Accounts, T1556 Modify Authentication Process, T1098 Account Manipulation, T1199 Trusted Relationship, T1190 Exploit Public-Facing Application, T1133 External Remote Services, T1567 Exfiltration over Web Service, etc.).
- Each finding carries `technique_ids[]`; aggregate to compute **per-tactic exposure heatmap** per tenant.

---

## 12. AI Capabilities

- **Executive narrative generation** (Azure OpenAI + structured prompt templates).
- **Finding explanation** in plain language with business impact.
- **Remediation drafting** (Azure CLI / PowerShell / Graph snippets).
- **Compliance evidence drafting** for auditors.
- **Conversational copilot** ("Why is our identity score 62?") backed by RAG over the tenant's own findings + reference frameworks (Azure AI Search).
- **Anomaly summarization** of scan-over-scan deltas.
- **Guardrails**: prompt-injection defenses, content filters, customer-data isolation per tenant index, no training on customer data, full prompt/response audit log.

---

## 13. Example Dashboard Screens

1. **Executive Overview** — overall posture score, top 5 risks, live campaigns affecting you, trend.
2. **Identity Risk** — PIM coverage, MFA %, risky users, OAuth consent surface, CA policy heatmap.
3. **Azure Exposure** — public IPs, open ports, missing private endpoints, unencrypted resources, NSG anomalies.
4. **Device Posture** — compliant vs non-compliant, Defender onboarding %, BitLocker, patch level.
5. **Compliance Center** — per-framework heatmaps with drill-down to evidence.
6. **Threat Exposure** — campaigns ⨯ your assets, MITRE heatmap, KEV CVEs you're exposed to.
7. **Remediation Backlog** — Kanban-style prioritized actions with owners and SLAs.
8. **Audit Mode** — read-only evidence pack export.

---

## 14. Example Executive Report (Excerpt)

> Your Azure tenant currently scores **68/100** (Moderate). The single highest-leverage action is enforcing **MFA for all privileged roles** — this closes exposure to **3 active phishing campaigns** tracked by Microsoft Defender TI in the last 14 days and improves your CIS Azure Benchmark 1.x and NIST CSF PR.AC scores. Remediation effort: ~2 hours. Estimated risk reduction: **-18 points**.

---

## 15. Example Technical Finding

```yaml
finding_id: F-2026-0001
title: "RDP exposed to the public internet on 3 VMs"
severity: high
exploitability: active
techniques: [T1133, T1078, T1190]
frameworks:
  cis_azure: ["6.1", "6.2"]
  mcsb: ["NS-1", "NS-2"]
  nist_csf: ["PR.AC-3", "PR.AC-5"]
  iso_27001: ["A.13.1.1"]
campaign_links:
  - name: "Akira ransomware – RDP brute force wave"
    source: "Microsoft Defender TI"
    confidence: high
affected_assets:
  - subscription: "sub-prod"
    resource: "vm-bastion-eu-01"
    public_ip: "x.x.x.x"
remediation:
  azure_cli: |
    az network nsg rule update -g rg-prod --nsg-name nsg-vm --name allow-rdp \
      --source-address-prefixes "10.0.0.0/8" --access Deny
  policy: "Deploy 'Allow only Azure Bastion for RDP' built-in policy."
```

---

## 16. MVP Version (v0.1)

- Single-tenant deploy via Bicep.
- Azure Tenant Scanner (subset: subscriptions, VMs, storage, networking, RBAC).
- M365 Scanner (Entra ID, CA policies, MFA, risky users).
- Compliance mapping: CIS Azure + MCSB only.
- TI: CISA KEV + MITRE ATT&CK + Defender TI.
- Static dashboards + PDF executive report.
- Azure OpenAI summarization (single prompt template).

---

## 17. Advanced Enterprise Version (v1.0+)

- Multi-tenant SaaS with full data isolation and CMK per tenant.
- All scanners (Azure, M365, Intune, Purview, Defender XDR).
- Full TI mesh (Defender TI + Sentinel TI + MISP + OpenCTI + OTX + abuse.ch + VT + GHSA + NVD + KEV).
- Live campaign-to-asset mapping with continuous re-scoring.
- AI copilot with RAG.
- Power BI Embedded dashboards.
- API + Webhooks + Logic Apps connector + Teams app.
- Customer-managed keys, Private Link, Confidential Computing for AI inference (optional).
- Multi-region active-active with paired Azure regions.

---

## 18. Implementation Roadmap

See `docs/ROADMAP.md` for the milestone-by-milestone plan (Foundation → MVP → GA → Enterprise → Marketplace).

---

## 19. Monetization Model

| Tier | Audience | Notes |
|---|---|---|
| **Free / Assessment** | SMB, evaluation | 1 tenant, weekly scan, executive PDF only |
| **Pro** | Mid-market | Continuous scans, all frameworks, AI summaries |
| **Enterprise** | Large enterprise | SSO, RBAC, Power BI, CMK, API, SLAs |
| **ISV / Customer-Hosted** | Regulated / sovereign | Deployed into customer subscription via Bicep; per-tenant license |
| **Azure Marketplace SaaS Offer** | All | Transactable via Microsoft commerce |

Pricing axes: number of tenants, number of identities, scan frequency, retention period, AI tokens.

---

## 20. Example End-to-End Customer Use Case

A 5,000-employee financial services firm onboards their Azure tenant via the AzureLens onboarding wizard (admin consent for the multi-tenant app). Within 30 minutes, AzureLens has scanned 14 subscriptions, 9,200 identities, 6,800 Intune-enrolled devices, and produced a posture score of **61/100**. The CISO opens the **Executive Overview** and sees that:

1. An **active Akira ransomware campaign** maps to **3 RDP-exposed VMs** in their non-prod subscription.
2. **42 privileged users lack PIM**, mapping to **MITRE T1078** and **CIS 1.x**.
3. Their **DLP coverage gap for financial data** triggers **GDPR Art. 32** and **SOC 2 CC6** findings.

They click **"Generate Remediation Plan"**. The AI engine produces a 2-week prioritized backlog, with Azure CLI / Graph commands and Azure Policy templates. The compliance officer exports the **Audit Evidence Pack** (ZIP of JSON evidence + signed PDF). Two weeks later, after applying the remediations, the score moves to **84/100** and the campaign exposure drops to zero — visible as a clear trend on the executive dashboard.

---

## Repository Layout (Planned)

```
azurelens/
├── README.md
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── SECURITY_MODEL.md
│   ├── THREAT_MODEL.md
│   ├── SCHEMA_DESIGN.md
│   └── AZURE_SERVICES.md
├── apps/
│   ├── web/                  # Next.js frontend (planned)
│   └── api/                  # Backend API (planned)
├── services/
│   ├── scanner-azure/        # Azure Tenant Scanner (planned)
│   ├── scanner-m365/         # Microsoft 365 Scanner (planned)
│   ├── scanner-intune/       # Device & Intune Scanner (planned)
│   ├── compliance-engine/    # Compliance Gap Analyzer (planned)
│   ├── ti-ingestion/         # Live TI ingestion workers (planned)
│   ├── ti-correlation/       # Threat-to-Environment mapping (planned)
│   ├── risk-engine/          # Risk scoring (planned)
│   ├── ai-engine/            # Azure OpenAI orchestration (planned)
│   ├── remediation/          # Remediation Center (planned)
│   └── reporting/            # Report generation (planned)
├── packages/
│   ├── shared-types/         # Shared TS/Python types (planned)
│   ├── connectors/           # Graph / ARG / Defender / Sentinel clients (planned)
│   └── frameworks/           # Reference data (MITRE, CIS, NIST, ISO, ...) (planned)
├── infra/
│   ├── bicep/                # Bicep IaC modules (planned)
│   └── terraform/            # Terraform parity modules (planned)
├── jobs/                     # Scheduled / Durable Functions jobs (planned)
└── .github/
    └── workflows/            # CI/CD with OIDC to Azure (planned)
```

> **This branch (`feature/platform-foundation`) intentionally contains only design and documentation. No code, no infrastructure, no application files are committed yet.**

---

## License

To be defined (target: commercial / proprietary with optional source-available components).

## Status

`feature/platform-foundation` — design phase. See `docs/ROADMAP.md` for next steps.
