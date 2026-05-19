# Cloud Threat & Compliance Exposure Analyzer — Design Document

> Azure-native, AI-powered security posture, compliance, and live threat exposure platform for Azure + Microsoft 365 tenants.

---

## 1. Product Name Ideas

| Tier | Name | Tagline |
|------|------|---------|
| **Primary** | **AzureLens** | *See your tenant the way attackers do.* |
| Alt 1 | **SentinelPath** | Threat-aware posture management for Azure & M365. |
| Alt 2 | **CloudGuard 360** | Unified posture, compliance, and live threat exposure. |
| Alt 3 | **Aegis Cloud Posture (ACP)** | Continuous defense across identity, device, and cloud. |
| Alt 4 | **ThreatScope for Azure** | Live attacker techniques mapped to your real environment. |
| Alt 5 | **Posturely** | Executive-friendly cloud security scoring. |
| Alt 6 | **NorthStar Security Compass** | Audit-grade evidence and remediation guidance. |

Recommended: **AzureLens** (matches the repo name).

---

## 2. Problem Statement

Enterprises running Azure and Microsoft 365 must satisfy a growing list of regulatory regimes (ISO 27001, SOC 2, GDPR, NIST CSF, CIS) while defending against attacker techniques that evolve faster than control frameworks. Today, security leaders rely on a patchwork of tools — Defender for Cloud for posture, Secure Score for M365, Sentinel for SIEM, Purview for compliance, Intune for devices — each with its own dashboard, scoring model, and remediation language. None of them answer the executive's actual question:

> *"Given what attackers are doing **this week**, am I exposed, and what should I fix first?"*

**AzureLens** unifies posture, identity, device, and compliance signals across the Microsoft cloud, correlates them against live threat intelligence (active campaigns, KEV CVEs, MITRE techniques, IOCs), and produces a single prioritized, evidence-backed remediation roadmap — explained in both executive and engineer language.

---

## 3. Target Users

| Persona | Primary Need | Primary View |
|---------|--------------|--------------|
| **CISO / Security Executive** | One score, board-ready narrative, peer benchmark | Executive Dashboard |
| **Security Administrator** | Day-to-day posture drift, MFA/CA gaps | Identity & Posture |
| **Compliance Officer / Auditor** | Mapped evidence for ISO/SOC 2/GDPR/CIS | Compliance Center |
| **Cloud Architect** | Resource-level exposure, IaC remediation | Azure Exposure View |
| **SOC Analyst** | Active campaigns → my tenant → IOCs | Live Threat Map |
| **IT / Endpoint Manager** | Device compliance, Intune drift | Device Posture |
| **Read-only Executive Viewer** | Trend lines, top 5 risks | Executive Report PDF |

---

## 4. Main Features

1. **Tenant Security Posture Score** — single 0–100 weighted score with sub-scores for Identity, Device, Resource, Data, Threat Exposure.
2. **Unified Azure + M365 Scanner** — single sweep across Graph, ARG, Defender, Intune, Purview, Sentinel.
3. **Compliance Mapping Engine** — every finding mapped to ISO 27001, SOC 2, CIS, NIST CSF, GDPR, MCSB, CIS Azure, Zero Trust.
4. **Live Threat-to-Environment Correlation** — *"these 3 of your assets are vulnerable to this week's ransomware campaign."*
5. **MITRE ATT&CK Exposure Heatmap** — which techniques your tenant is currently weak against.
6. **AI Security Advisor (Azure OpenAI)** — natural-language explanations, exec summaries, remediation drafts.
7. **Prioritized Remediation Roadmap** — sequenced by exploitability × business impact × compliance weight.
8. **One-click Remediation Artifacts** — generated Azure CLI / PowerShell / Bicep / Graph snippets.
9. **Evidence-Grade Audit Reports** — PDF / DOCX with timestamps, raw evidence, control mappings.
10. **Continuous Drift Detection** — scheduled deltas with Event Grid alerts when posture degrades.

---

## 5. Azure-Native Architecture

### 5.1 Component Diagram (logical)

```
                        ┌──────────────────────────────────────┐
                        │           Microsoft Entra ID         │
                        │   (AuthN/AuthZ, RBAC, App Roles)     │
                        └──────────────────┬───────────────────┘
                                           │ OIDC
            ┌──────────────────────────────▼──────────────────────────────┐
            │              Azure Front Door + WAF                         │
            └──────────────┬─────────────────────────────┬────────────────┘
                           │                             │
                ┌──────────▼─────────┐         ┌─────────▼──────────┐
                │  Container Apps    │         │  Power BI Embedded │
                │  (React SPA UI)    │         │   (Dashboards)     │
                └──────────┬─────────┘         └─────────┬──────────┘
                           │ REST / GraphQL              │
                ┌──────────▼──────────────────────────────────────────┐
                │      API Layer — Container Apps (.NET / Python)     │
                │  Auth middleware │ RBAC │ Rate limit │ OpenAPI      │
                └─────┬─────────┬──────────────┬──────────────┬───────┘
                      │         │              │              │
        ┌─────────────▼──┐ ┌────▼──────┐ ┌─────▼─────┐ ┌──────▼────────┐
        │ Scanner Workers│ │ AI Engine │ │ Risk/Score│ │ Remediation   │
        │ (Functions)    │ │ (AOAI)    │ │ Engine    │ │ Generator     │
        │  • Azure       │ └─────┬─────┘ └─────┬─────┘ └──────┬────────┘
        │  • M365/Graph  │       │             │              │
        │  • Intune      │       └─────────────┼──────────────┘
        │  • Defender    │                     │
        │  • Sentinel    │           ┌─────────▼──────────┐
        │  • Purview     │           │  Service Bus /     │
        └────┬───────────┘           │  Event Grid        │
             │                       └─────────┬──────────┘
             │                                 │
   ┌─────────▼─────────────────────────────────▼─────────────┐
   │                    Data Plane                            │
   │  Cosmos DB (findings)  │  Azure SQL (compliance state)   │
   │  Blob Storage (reports/evidence)  │  Log Analytics       │
   │  Key Vault (secrets)   │  AI Search (semantic findings)  │
   └──────────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────┐
   │              Threat Intelligence Ingestion                │
   │  Logic Apps + Functions pull: MDTI, Sentinel TI, CISA KEV,│
   │  MITRE, MISP, OpenCTI, OTX, abuse.ch, NVD, GHSA, VT       │
   └──────────────────────────────────────────────────────────┘
```

### 5.2 Service Choices & Rationale

| Concern | Service | Why |
|---------|---------|-----|
| Frontend SPA hosting | **Azure Container Apps** | Scale-to-zero, revisions, ingress, Dapr-ready |
| API tier | **Container Apps** (.NET 8 or FastAPI) | Same runtime as frontend; KEDA-driven scaling |
| Scheduled scans | **Azure Functions** (Timer + Durable) | Long-running orchestrations for fan-out per subscription |
| Workflow / TI ingestion | **Logic Apps Standard** | Connector-rich, low-code feed pulls |
| Findings store | **Cosmos DB** (NoSQL, multi-region) | Schema-flexible findings, low-latency queries |
| Compliance state | **Azure SQL** | Relational mapping of controls ↔ findings ↔ evidence |
| Reports & evidence | **Blob Storage** (immutable + WORM) | Audit-grade chain of custody |
| Secrets | **Key Vault** (HSM-backed) | All TI API keys, signing certs |
| Identity | **Managed Identity** end-to-end | No secrets between Azure services |
| AI | **Azure OpenAI** (GPT-4-class + embeddings) | Data residency, private endpoint, content safety |
| Search | **Azure AI Search** | Semantic + vector queries over findings/TI |
| Dashboards | **Power BI Embedded** + native React | Mix exec PBI tiles with engineer drill-down |
| Eventing | **Event Grid + Service Bus** | Posture drift events, scan-completed events |
| Observability | **Azure Monitor + App Insights + Log Analytics** | Single workspace, audit retention |
| Edge | **Front Door + WAF** | DDoS, geo, OWASP rules |

### 5.3 Deployment Topology
- Per-tenant **dedicated resource group** (`rg-azurelens-<tenantId>`) deployed via Bicep / Terraform.
- VNet-integrated Container Apps + private endpoints for Cosmos / SQL / Storage / Key Vault / AOAI.
- Multi-region active/passive (paired regions) with Cosmos multi-write for findings.

---

## 6. Required Microsoft Permissions

The app uses **two app registrations**: a *Read-Scan* app (high privilege, app-only, read-only) and a *UI* app (delegated, user-context).

### 6.1 Microsoft Graph — Application permissions (admin consent)

| Permission | Purpose |
|------------|---------|
| `Directory.Read.All` | Users, groups, roles |
| `RoleManagement.Read.Directory` | Privileged role assignments |
| `Policy.Read.All` | Conditional Access, authorization policies |
| `Policy.Read.ConditionalAccess` | CA detail |
| `IdentityRiskyUser.Read.All` | Risky users |
| `IdentityRiskEvent.Read.All` | Risk detections |
| `AuditLog.Read.All` | Sign-in & audit logs |
| `Application.Read.All` | App registrations & enterprise apps |
| `DelegatedPermissionGrant.Read.All` | OAuth consent grants |
| `SecurityEvents.Read.All` | Defender XDR alerts |
| `SecurityActions.Read.All` | XDR actions |
| `ThreatIndicators.Read.All` | TI indicators |
| `ThreatIntelligence.Read.All` | TI articles |
| `DeviceManagementConfiguration.Read.All` | Intune config |
| `DeviceManagementManagedDevices.Read.All` | Intune devices |
| `DeviceManagementServiceConfig.Read.All` | Intune service config |
| `InformationProtectionPolicy.Read.All` | Sensitivity labels |
| `Reports.Read.All` | Secure Score, usage |
| `SecureScores.Read.All` | Secure Score sub-controls |

### 6.2 Azure ARM / Resource Manager (Subscription-scoped)

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Management Group / Subscription | Resource enumeration |
| **Security Reader** | Subscription | Defender for Cloud findings |
| **Resource Graph Reader** | Tenant root group | Cross-sub ARG queries |
| **Log Analytics Reader** | Sentinel workspace | KQL over alerts/logs |
| **Sentinel Reader** | Sentinel workspace | Incidents, analytics rules |
| **Reader** on Key Vaults | RG-scoped | Vault config (not secrets) |

### 6.3 Purview / Compliance Center

- `ComplianceManager.Read.All` (Graph beta)
- `InformationProtectionPolicy.Read.All`
- Compliance Administrator (Entra role) for content scanning APIs

### 6.4 What the app does **not** require
- No write permissions in the default profile.
- Optional *"Remediation"* role pack (separately consented) grants `Policy.ReadWrite.ConditionalAccess`, `DeviceManagementConfiguration.ReadWrite.All`, ARM `Contributor` on a tagged scope.

---

## 7. Security Model

### 7.1 Identity & Access
- **Entra ID** for human auth (OIDC + PKCE).
- **Managed Identity** for service-to-service (no client secrets in code).
- **App roles**: `Admin`, `SecurityAdmin`, `ComplianceOfficer`, `CloudArchitect`, `SOCAnalyst`, `ITManager`, `Auditor`, `Viewer`.
- **RBAC matrix** enforced server-side; UI hides unauthorized actions.

### 7.2 Data Protection
- All data **encrypted at rest** with customer-managed keys (CMK) in Key Vault.
- TLS 1.3 in transit; mTLS between internal services via Dapr.
- **Tenant isolation**: each customer = isolated subscription + resource group + Cosmos partition key + dedicated CMK.
- **Immutable evidence**: Blob legal hold + WORM for audit reports.

### 7.3 Network
- Private Endpoints for all PaaS data services.
- Egress restricted via Azure Firewall; TI feed FQDNs allow-listed.
- WAF (OWASP 3.2 + custom rules) on Front Door.

### 7.4 Auditing
- Every API call → App Insights + Log Analytics with user, role, action, resource, correlation ID.
- Diagnostic settings on every Azure resource → central workspace, 7-year retention for audit logs.

### 7.5 Secrets & Keys
- Key Vault with HSM-backed keys, soft-delete + purge protection.
- Auto-rotation for TI API keys via Logic Apps + Key Vault events.

### 7.6 Supply Chain
- Container images signed (Notation / cosign), scanned by Defender for Containers.
- Dependency SBOM generated per build, stored in Blob.

---

## 8. Data Flow

```
[1] User signs in via Entra ID → SPA receives ID/Access token
[2] SPA calls API (bearer token) → API validates audience/issuer
[3] API enqueues scan job → Service Bus topic 'scan-requests'
[4] Durable Function orchestrator fans out per data source:
       ├─ Azure Resource Graph query  ──► raw resources
       ├─ Graph API paged calls       ──► users, roles, CA, apps
       ├─ Defender for Cloud REST     ──► assessments, recommendations
       ├─ Intune via Graph beta       ──► devices, profiles
       ├─ Sentinel KQL                ──► incidents, analytics rules
       └─ Purview API                 ──► labels, DLP
[5] Raw payloads → Blob (raw zone, partitioned by date/tenant)
[6] Normalizer Functions → canonical Finding schema → Cosmos DB
[7] Risk Engine joins findings with TI index (AI Search vector store)
       → enriched finding with: CVE refs, MITRE techniques, active campaigns
[8] AI Engine (Azure OpenAI) generates: exec narrative, remediation steps
       using RAG over compliance corpus + Microsoft docs (indexed)
[9] Scoring Engine computes scores → writes to Cosmos + SQL
[10] Event Grid emits 'scan.completed' → Logic App generates PDF/DOCX
        reports → Blob (evidence container, immutable)
[11] SPA polls / SignalR pushes results to dashboard
[12] Alerts: posture drift → Event Grid → Teams / Email / ServiceNow
```

---

## 9. Threat Intelligence Sources

| Source | Method | Refresh | Use |
|--------|--------|---------|-----|
| **Microsoft Defender Threat Intelligence (MDTI)** | Graph `/security/threatIntelligence` | 15 min | Articles, indicators, attribution |
| **Microsoft Sentinel TI** | Log Analytics `ThreatIntelligenceIndicator` | streaming | Tenant-attached IOCs |
| **CISA KEV** | JSON pull from cisa.gov | hourly | Actively-exploited CVEs |
| **MITRE ATT&CK** | STIX 2.1 from attack.mitre.org | weekly | Tactic/technique taxonomy |
| **MISP** | REST API (customer-provided instance) | hourly | Community IOCs |
| **OpenCTI** | GraphQL | hourly | Curated TI graph |
| **AlienVault OTX** | REST | hourly | Pulses |
| **abuse.ch** (URLhaus, ThreatFox, MalwareBazaar) | REST/CSV | hourly | Malware URLs, samples, IOCs |
| **VirusTotal** *(opt-in, paid key)* | REST | on-demand | File/URL reputation enrichment |
| **GitHub Security Advisories** | GraphQL | hourly | Package CVEs |
| **NVD / CVE** | REST 2.0 | daily | CVSS, CPE |

Indicators normalized to **STIX 2.1** internally; stored in Cosmos with vector embeddings in AI Search for semantic correlation.

---

## 10. Compliance Framework Mapping

Each finding carries a `controlMappings[]` array. The mapping engine ingests official control catalogs and maintains a versioned crosswalk.

| Framework | Source Catalog | Example Control → Finding |
|-----------|----------------|---------------------------|
| **ISO 27001:2022** | Annex A controls | A.5.17 (Authentication info) ← *MFA disabled for admin* |
| **SOC 2** | TSC 2017 | CC6.1 (Logical access) ← *No CA policy on privileged users* |
| **CIS Microsoft Azure 2.1** | CIS hardening guide | 1.1.1 (MFA for Global Admins) ← *3 GAs without MFA* |
| **NIST CSF 2.0** | Functions / Categories | PR.AA-01 ← *Permanent GA assignments* |
| **GDPR** | Articles | Art. 32 ← *No DLP for PII* |
| **MCSB v3** | Microsoft Cloud Security Benchmark | IM-1 ← *Legacy auth enabled* |
| **Microsoft 365 baseline** | M365 secure config baseline | Baseline 5.1.1 ← *Anonymous sharing in SPO* |
| **Zero Trust** | Microsoft maturity model | Identity Pillar L2 ← *No risk-based CA* |
| **Azure Well-Architected** | Security pillar | SE:05 ← *No private endpoints on storage* |

Crosswalk format (excerpt):
```json
{
  "findingType": "mfa.disabled.privileged",
  "mappings": [
    { "framework": "ISO27001:2022", "control": "A.5.17" },
    { "framework": "SOC2", "control": "CC6.1" },
    { "framework": "CIS-Azure-2.1", "control": "1.1.1" },
    { "framework": "NIST-CSF-2.0", "control": "PR.AA-01" },
    { "framework": "MCSB-v3", "control": "IM-1" }
  ]
}
```

---

## 11. MITRE ATT&CK Mapping Approach

1. **Catalog ingestion**: ATT&CK Enterprise STIX bundle pulled weekly → loaded into Cosmos `attack_techniques` container.
2. **Finding → Technique linkage**: each finding-type has a curated `techniqueIds[]` list (e.g., `mfa.disabled.privileged` → `T1078`, `T1110`).
3. **TI → Technique linkage**: TI articles (MDTI, MISP) already carry `kill_chain_phases` and `mitre_attack_techniques`.
4. **Exposure scoring per technique**:
   ```
   exposure(T) = Σ(weight(finding) × severity(finding) × activeCampaignBoost(T))
   ```
   where `activeCampaignBoost(T) = 1 + (campaigns_using_T_last_30_days × 0.1)`.
5. **Visualization**: ATT&CK Navigator-style heatmap (12 tactics × techniques), color = exposure score.
6. **Detection coverage overlay**: Sentinel analytics rules tagged with `relevantTechniques` → overlay shows *"you are exposed to T1566 and have no detection rule for it."*

---

## 12. AI Capabilities (Azure OpenAI)

| Capability | Pattern | Model |
|------------|---------|-------|
| **Executive narrative** | RAG over findings + scores | GPT-4-class |
| **Finding explanation (plain English)** | Prompt with finding JSON | GPT-4-class |
| **Remediation generation** | RAG over Microsoft docs + CLI/PS reference | GPT-4-class + tools |
| **Compliance evidence drafting** | Template + findings → control narrative | GPT-4-class |
| **Semantic finding search** | Embeddings (text-embedding-3-large) → AI Search | embeddings |
| **Threat-to-tenant correlation rationale** | Few-shot with TI article + tenant context | GPT-4-class |
| **Q&A copilot ("Why did my score drop?")** | Agentic with function-calling over findings API | GPT-4-class |
| **Anomaly summarization** | Compare scan deltas, narrate top changes | GPT-4-class |
| **Translation** | Reports in customer's language | GPT-4-class |
| **Safety** | Azure Content Safety on all inputs/outputs; PII scrubber pre-prompt | — |

All prompts use a strict system prompt that **forbids fabricating CVEs, controls, or commands** and requires citation-style references to source IDs.

---

## 13. Example Dashboard Screens

### 13.1 Executive Dashboard (CISO view)
```
┌────────────────────────────────────────────────────────────────┐
│  AzureLens — Contoso Ltd                  As of 19 May 2026    │
├────────────────────────────────────────────────────────────────┤
│  TENANT SECURITY POSTURE             72 / 100   ▼ 4 (7 days)   │
│  ──────────────────────                                         │
│  Identity 68  │ Device 81 │ Resource 70 │ Data 65 │ Threat 74  │
├────────────────────────────────────────────────────────────────┤
│  ACTIVE CAMPAIGN EXPOSURE                                       │
│  ⚠ Midnight Blizzard OAuth phishing — 4 exposed app consents    │
│  ⚠ Akira ransomware (T1133) — 2 VMs with public RDP             │
│  ✓ Cl0p MOVEit — not applicable                                 │
├────────────────────────────────────────────────────────────────┤
│  TOP 5 PRIORITIZED ACTIONS                                      │
│  1. Disable legacy auth (impacts 38 users)          [Fix It]    │
│  2. Convert 3 permanent GAs to PIM-eligible          [Fix It]   │
│  3. Block public RDP on 2 VMs (NSG)                  [Fix It]   │
│  4. Enable DLP for financial data (GDPR/ISO gap)     [Fix It]   │
│  5. Onboard 14 devices to Defender for Endpoint      [Fix It]   │
└────────────────────────────────────────────────────────────────┘
```

### 13.2 MITRE ATT&CK Heatmap
12-column matrix (Reconnaissance → Impact). Cells colored red/amber/green by tenant exposure; overlay toggles: *Active Campaigns / Detection Coverage / Compliance Impact*.

### 13.3 Compliance Center
Tabbed view per framework. Each control: status (pass/fail/N/A), evidence link, last-checked timestamp, mapped findings, auditor notes.

### 13.4 Identity Risk
Sankey: Users → Roles → Conditional Access coverage → Risk state. Drill-down opens user card with sign-ins, risky events, and recommended CA changes.

### 13.5 Azure Exposure Map
Geographic + resource-graph hybrid. Public IPs, exposed storage, weak NSGs flagged; click → Bicep/CLI remediation panel.

### 13.6 Live Threat Feed
Streaming list of TI articles. Each card: *"Relevant to you because…"* with linked tenant findings.

---

## 14. Example Executive Report

> **Contoso Ltd — Cloud Security Executive Summary**
> *Period: 12–19 May 2026*
>
> **Headline.** Contoso's tenant security posture is **72/100**, down 4 points week-over-week. The decline is driven by three newly exposed surfaces that align with active attacker campaigns observed in the wild over the past 14 days.
>
> **What changed this week.**
> - Two virtual machines in `rg-prod-eu` had their NSGs modified to permit inbound RDP from any source. The Akira ransomware group has been observed exploiting exposed RDP throughout April–May 2026 (CISA Alert AA26-127A).
> - Four enterprise applications were granted user-consent to read mailbox content. This pattern is being abused by Midnight Blizzard in an ongoing OAuth phishing campaign (MDTI article *Storm-0539, May 2026*).
> - One Global Administrator account was created without MFA enforcement.
>
> **Compliance impact.** The above findings produce **11 control failures** across ISO 27001 (A.5.17, A.8.5), SOC 2 (CC6.1, CC6.6), and CIS Microsoft Azure 2.1 (1.1.1, 6.2). GDPR Art. 32 exposure unchanged.
>
> **Recommended 7-day action plan.**
> 1. Remove public RDP on the two affected VMs (15 min).
> 2. Revoke the four risky OAuth consents and disable user consent for unverified publishers (30 min).
> 3. Move the new GA account to PIM-eligible with MFA + CA policy (1 hour).
> 4. Schedule policy review of CA "Block legacy auth" (in progress).
>
> **Outlook.** Implementing items 1–3 returns the posture score to an estimated **78/100** and closes 9 of the 11 control failures.

---

## 15. Example Technical Finding

```json
{
  "findingId": "f-2026-05-19-0a14",
  "tenantId": "contoso.onmicrosoft.com",
  "type": "network.rdp.public",
  "title": "Public RDP exposure on production VM",
  "severity": "High",
  "exploitability": "Active in the wild",
  "asset": {
    "kind": "Microsoft.Compute/virtualMachines",
    "id": "/subscriptions/.../resourceGroups/rg-prod-eu/providers/Microsoft.Compute/virtualMachines/vm-app-03",
    "location": "westeurope",
    "publicIp": "20.74.12.88"
  },
  "evidence": {
    "nsgRule": {
      "name": "AllowAnyRDPInbound",
      "priority": 100,
      "direction": "Inbound",
      "access": "Allow",
      "protocol": "Tcp",
      "destinationPortRange": "3389",
      "sourceAddressPrefix": "*"
    },
    "collectedAt": "2026-05-19T14:02:11Z",
    "rawBlob": "raw/contoso/2026-05-19/arg-nsg-rules.json#L412"
  },
  "threatContext": {
    "activeCampaigns": [
      { "name": "Akira ransomware May-2026 wave", "source": "MDTI", "id": "ti-art-9182" }
    ],
    "kev": [],
    "techniques": ["T1133", "T1021.001"]
  },
  "controlMappings": [
    { "framework": "CIS-Azure-2.1", "control": "6.2" },
    { "framework": "ISO27001:2022", "control": "A.8.20" },
    { "framework": "NIST-CSF-2.0", "control": "PR.AC-05" },
    { "framework": "MCSB-v3", "control": "NS-1" }
  ],
  "riskScore": 87,
  "remediation": {
    "summary": "Restrict NSG rule to corporate IP ranges or replace with Azure Bastion + JIT.",
    "azureCli": [
      "az network nsg rule update -g rg-prod-eu --nsg-name nsg-app-03 -n AllowAnyRDPInbound --source-address-prefixes 198.51.100.0/24",
      "az security jit-policy create ..."
    ],
    "powershell": [
      "Set-AzNetworkSecurityRuleConfig -Name AllowAnyRDPInbound -SourceAddressPrefix 198.51.100.0/24 ..."
    ],
    "bicep": "azurelens-snippets/nsg-restrict-rdp.bicep",
    "docs": ["https://learn.microsoft.com/azure/bastion/", "https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview"]
  },
  "firstSeen": "2026-05-19T14:02:11Z",
  "status": "open"
}
```

---

## 16. MVP Version (~ 12 weeks, 1 team)

**Goal:** prove the unified posture + live-TI correlation value in a single tenant.

| Area | In-scope for MVP |
|------|------------------|
| Scanners | Azure Resource Graph, Graph (users/CA/roles/apps), Defender for Cloud |
| TI feeds | CISA KEV, MITRE ATT&CK, Microsoft Sentinel TI |
| Frameworks | CIS Azure, ISO 27001, MCSB |
| AI | Finding explanation + executive summary (no agentic copilot) |
| Reports | Executive PDF, technical CSV |
| Architecture | Container Apps + Functions + Cosmos + Blob + Key Vault + Front Door |
| Auth | Entra ID with 3 roles (Admin, Analyst, Viewer) |
| Out of scope | Intune deep scan, Purview, Power BI Embedded, write-back remediation, multi-tenant SaaS |

**Success criteria.** Single tenant scan in <15 min, 200+ finding types, exec PDF generation, 5 design partners onboarded.

---

## 17. Advanced Enterprise Version

| Capability | Detail |
|------------|--------|
| **Multi-tenant SaaS** | MSP / MSSP mode with per-tenant isolation, cross-tenant rollup |
| **Full Intune + Purview + Sentinel** scanners | Device drift, sensitivity labels, analytics rule coverage |
| **All 11 TI sources** including MISP/OpenCTI/OTX/abuse.ch/VT | STIX normalization, vector store |
| **Agentic AI Copilot** | Function-calling Q&A over findings + scans + TI |
| **Write-back remediation** | Optional Contributor scope to apply fixes with approval workflow |
| **Power BI Embedded** | Customer-branded dashboards |
| **SOAR integration** | ServiceNow, Jira, Teams, Slack, Logic Apps playbooks |
| **GitHub / Azure DevOps integration** | PRs generated for Bicep/Terraform remediations |
| **Continuous Compliance Evidence Locker** | WORM blob + signed PDFs + audit trail export |
| **Custom frameworks** | Customer policy → control crosswalk authoring UI |
| **Benchmarking** | Anonymized industry peer comparison |
| **Air-gapped / sovereign cloud** | Azure Government, Azure China deployment manifests |

---

## 18. Implementation Roadmap

| Phase | Weeks | Milestones |
|-------|-------|-----------|
| **0 — Foundations** | 1–2 | Bicep landing zone, app registrations, CI/CD (GitHub Actions + OIDC to Azure), telemetry baseline |
| **1 — Core scanners** | 3–6 | ARG, Graph, Defender for Cloud scanners; canonical Finding schema; Cosmos data model |
| **2 — Compliance & scoring** | 5–8 | CIS/ISO/MCSB crosswalks; scoring engine; first dashboards |
| **3 — TI integration** | 7–10 | CISA KEV, MITRE, Sentinel TI; threat-to-env correlation engine; ATT&CK heatmap |
| **4 — AI layer** | 9–11 | AOAI integration; exec narrative; finding explanations; PDF reports |
| **5 — MVP GA** | 12 | 5 design-partner onboarding, security review, pen-test |
| **6 — Intune + Purview** | 13–16 | Device & data scanners; M365 baseline mappings |
| **7 — Multi-tenant SaaS** | 17–22 | Tenant isolation, billing, MSP console, Power BI embed |
| **8 — Copilot + Remediation write-back** | 23–28 | Agentic Q&A, approval workflow, SOAR connectors |
| **9 — Sovereign cloud + enterprise** | 29–36 | Azure Gov, custom frameworks, GitHub PR remediation |

---

## 19. Monetization Model

| Tier | Price (indicative) | Target | Includes |
|------|--------------------|--------|----------|
| **Free / Community** | $0 | Single subscription, ≤ 25 users | CIS Azure check + Secure Score mirror, weekly scan |
| **Pro** | $1,500 / month flat | SMB / single tenant | All scanners, all TI feeds, AI summaries, daily scan |
| **Enterprise** | $0.30 per Azure resource + $4 per active M365 user / month | Mid-large enterprise | Custom frameworks, write-back, Power BI, SLA |
| **MSP / MSSP** | Volume-tiered per managed tenant | Partners | Multi-tenant console, white-label, cross-customer rollup |
| **Sovereign / Regulated** | Custom | Gov / finance / healthcare | Azure Gov / China deployment, FedRAMP-aligned, dedicated support |

**Add-ons.** Audit-evidence Locker ($500/mo), Custom Framework Authoring ($2k/mo), Quarterly Security Review (services).

**Distribution.** Azure Marketplace (transactable SaaS), Microsoft AppSource, partner co-sell (MACC eligible).

**Unit economics.** Cosmos + AOAI dominate variable cost; target gross margin >= 70% by caching TI normalization and batching AOAI completions.

---

## 20. Example End-to-End Customer Use Case

**Customer.** *Contoso Bank* — 4,200 employees, regulated under ISO 27001, SOC 2 Type II, GDPR, and DORA. Uses Azure (3 subscriptions, ~2,800 resources) and Microsoft 365 E5.

**Day 0 — Onboarding (35 minutes).**
The CISO opens the Azure Marketplace, deploys AzureLens into a new resource group via Bicep. The deployment script creates the app registration and prompts a Global Admin to consent the read-only Graph + Azure scopes. A first scan kicks off automatically.

**Day 0 + 15 minutes — First scan completes.**
Tenant Posture: **64/100**.
- 7 Global Admins, 5 of them permanent.
- Legacy authentication enabled.
- 11 storage accounts allow public blob access.
- 23 devices not onboarded to Defender for Endpoint.
- DLP policies present but missing financial-data classifier.

Live Threat Engine flags: *"The Akira ransomware campaign currently active in EU finance sector exploits exposed RDP. You have 2 VMs with public RDP."*

**Week 1 — Executive review.**
The CISO downloads the executive PDF, presents to the board. AzureLens has rephrased technical findings into business risk: "Our exposure to active ransomware campaigns is rated High due to two production VMs accepting RDP from the public internet."

**Week 1–2 — Remediation sprint.**
The security team uses the prioritized roadmap. For each item, AzureLens provides the exact Azure CLI / PowerShell / Bicep snippet. The Cloud Architect adopts the Bicep snippets directly into their IaC repo. Eight items closed in week 1; AzureLens detects the changes on the next scan and lifts the score to **74/100**.

**Week 4 — Compliance officer prepares for SOC 2 audit.**
She opens the Compliance Center, filters by SOC 2 TSC. Each control shows current status, mapped findings, and timestamped evidence in the immutable evidence Locker. She exports a control-by-control evidence pack to PDF and shares it with the external auditor.

**Week 6 — New campaign detected.**
MDTI publishes an article on a new OAuth phishing campaign abusing user consent. AzureLens correlates: Contoso permits user consent to verified publishers, and 14 enterprise apps were consented in the last 30 days. The SOC analyst gets a Teams notification with the affected app IDs and a one-click revoke playbook.

**Month 3 — Posture stabilized at 86/100.**
The board adopts AzureLens's score as a quarterly KPI. The CISO benchmarks against the anonymized industry peer median (78/100) and reports Contoso is now in the top quartile for financial-services Azure tenants.

**Outcome.**
- SOC 2 audit passed with no security-control findings (evidence pack accepted).
- Two avoided incidents traced to early remediation triggered by TI correlation.
- Mean time to remediate critical posture findings dropped from 21 days to 4 days.
- AzureLens renewed; expanded to MSSP partner for 24×7 monitoring.

---

*End of design document.*
