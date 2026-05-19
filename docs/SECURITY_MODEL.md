# AzureLens — Security Model

End-to-end security model for the Cloud Threat & Compliance Exposure Analyzer. This document defines **identity & access**, **authentication & RBAC**, **secrets**, **network**, **data protection**, **multi-tenant isolation**, **Microsoft permission scopes**, **audit & compliance**, and **operational security**.

> The platform analyzes customers' security posture; therefore the platform itself must exemplify the controls it recommends. Every recommendation it makes to customers, it implements on its own infrastructure.

---

## 1. Security Principles

1. **Zero Trust.** No implicit trust, ever — every request authenticated, authorized, and logged.
2. **Least privilege.** Every identity (human or workload) gets the minimum permission to do its job, scoped as narrowly as possible.
3. **No secrets in code.** All secrets in Key Vault; all service-to-service auth via Managed Identity or workload identity federation.
4. **Encrypt everywhere.** TLS 1.2+ in transit; AES-256 + CMK at rest for every data store.
5. **Tenant isolation by design.** Cross-tenant data access is impossible at the storage layer, not just the application layer.
6. **Auditable by default.** Every read of customer data, every privileged action, every AI prompt — logged, immutable, exportable.
7. **Assume breach.** Network micro-segmentation, just-in-time access, fast credential revocation, blast-radius minimization.
8. **Defense in depth.** Multiple independent controls per risk; no single control is load-bearing.

---

## 2. Identity Model

### 2.1 Customer-facing identities

| Identity type | Used by | Auth method |
|---|---|---|
| **Customer workforce user** | CISO, SecAdmin, Compliance, etc. | Entra ID SSO (customer tenant via federation/B2B) |
| **Customer guest user** | External auditor brought in by customer | B2B guest in customer tenant |
| **MSSP user** | Partner managing multiple customers | Lighthouse-style delegation (Phase 9) |
| **API client** | Customer automation | Entra ID app registration in customer tenant + client credentials in customer KV |

### 2.2 Platform internal identities

| Identity | Purpose | Permissions |
|---|---|---|
| **System-assigned Managed Identity** per service | Service-to-service auth within Azure | Scoped RBAC on KV / SQL / Cosmos / Storage / Service Bus / OpenAI |
| **User-assigned Managed Identity** for shared roles | E.g., scanners that need the same RBAC | Same as above, reusable |
| **Platform Entra ID multi-tenant app** | App used by customer tenants for delegated/app-perm Graph calls | Pre-consented set of Graph / Azure / Defender permissions (see § 6) |
| **GitHub Actions OIDC federated identity** | CI/CD deploys | Contributor (dev), limited (staging), tightly scoped (prod) |
| **Break-glass account** | Emergency human admin | Stored sealed; alerted on every use |

### 2.3 No standing privileged access

- Platform operators use **PIM-eligible** assignments only; activation requires MFA + justification + max 8h.
- All elevations are logged to immutable audit storage and alerted to the security on-call.

---

## 3. Authentication

### 3.1 Frontend (`apps/web`)

- **Auth library**: MSAL.js v3.
- **Flow**: Authorization Code with PKCE; no implicit grant.
- **MFA**: required (enforced by Conditional Access on the platform tenant or by the customer's CA policies for their users).
- **Token storage**: in-memory by default; refresh via silent SSO; no `localStorage` tokens.
- **Session**: short-lived ID/access tokens (1h), refresh tokens (configurable, default 24h with sliding window).
- **CSRF**: same-site=strict cookies; double-submit token where state-changing endpoints accept cookies.
- **CSP**: strict CSP, no inline scripts, no eval, allowlisted origins for Power BI Embedded.

### 3.2 Backend API (`apps/api`)

- **Token validation**: signature, issuer, audience, expiry, signing-key rotation; supports v2.0 tokens.
- **OBO (On-Behalf-Of)**: for delegated Graph calls when the user must be the actor.
- **Managed Identity**: for service-to-service calls (Key Vault, SQL, Cosmos, Storage, Service Bus, OpenAI).
- **Tenant resolution**: `tenant_id` claim → tenant context object → enforced as filter on every query.

### 3.3 Service-to-service

- All internal HTTP hops use **Managed Identity** + Entra ID tokens (audience = target service).
- Service Bus / Event Grid use Managed Identity (no SAS keys).
- Database access via Managed Identity (Azure AD authentication for SQL; RBAC data plane for Cosmos).

---

## 4. RBAC — Application Role Matrix

Roles are assigned via **Entra ID app roles** + fine-grained per-resource scopes enforced in the API.

| Capability | GlobalAdmin | SecurityAdmin | Compliance | CloudArchitect | SOCAnalyst | ITManager | Auditor | ExecViewer |
|---|---|---|---|---|---|---|---|---|
| View executive dashboards | ● | ● | ● | ● | ● | ● | ● | ● |
| View technical findings | ● | ● | ● | ● | ● | ● | ● | — |
| View compliance frameworks | ● | ● | ● | ● | — | — | ● | view-only |
| View identity findings | ● | ● | ● | — | ● | ● | ● | — |
| View device findings | ● | ● | — | ● | ● | ● | ● | — |
| View threat campaigns | ● | ● | — | ● | ● | — | ● | — |
| Trigger scans | ● | ● | — | ● | ● | — | — | — |
| Acknowledge / suppress findings | ● | ● | ● (compliance only) | ● | ● | ● | — | — |
| Run AI copilot | ● | ● | ● | ● | ● | ● | ● | — |
| Export reports | ● | ● | ● | ● | ● | ● | ● | exec PDF only |
| Configure connectors | ● | ● | — | ● | — | — | — | — |
| Manage users & roles | ● | — | — | — | — | — | — | — |
| One-click remediation (opt-in) | ● | ● | — | — | — | — | — | — |
| Manage CMK / encryption | ● | — | — | — | — | — | — | — |
| Manage subscriptions / billing | ● | — | — | — | — | — | — | — |

Notes:
- **GlobalAdmin** is a platform tenant admin per customer organization, not the Entra ID "Global Administrator" role.
- Auditor is **read-only with evidence export**; cannot suppress findings or alter state.
- ExecViewer sees only dashboards and the executive PDF — no raw findings.
- Custom roles supported in Enterprise tier (Phase 8).

---

## 5. Secrets & Key Management

- **Azure Key Vault** (Premium / HSM-backed) per environment; soft-delete + purge protection enabled.
- **All secrets**: customer connector keys (MISP, OTX, etc.), webhook signing keys, encryption keys.
- **No secrets in app settings**; only **Key Vault references** in Container Apps / Functions.
- **Customer-Managed Keys (CMK)** for SQL, Cosmos, Storage, Backup, Service Bus, AI Search where supported.
- **Per-tenant CMK** in Enterprise tier: each tenant's CMK lives in a dedicated Key Vault (optionally in customer-owned KV via cross-tenant key access).
- **Rotation**:
  - Platform secrets: automatic 90 days.
  - CMKs: annual rotation with key versioning; old versions retained for legal hold.
  - Webhook signing keys: 30-day overlap window.
- **Access policies**: RBAC mode (not legacy access policies); deny-by-default; alerting on every `getSecret` outside expected callers.

---

## 6. Microsoft Permissions Catalog (Customer Tenant)

The platform's multi-tenant Entra ID app requests the **minimum** permissions necessary. Application permissions require **admin consent**; delegated permissions are scoped per-feature.

### 6.1 Microsoft Graph — Application permissions (read-only)

| Permission | Why |
|---|---|
| `Directory.Read.All` | Users, groups, org structure |
| `User.Read.All` | User properties, sign-in risk |
| `Group.Read.All` | Group memberships |
| `Application.Read.All` | App registrations, enterprise apps |
| `Policy.Read.All` | Tenant policies |
| `Policy.Read.ConditionalAccess` | CA policy posture |
| `RoleManagement.Read.Directory` | Directory role assignments + PIM eligibility |
| `RoleManagement.Read.All` | All RBAC |
| `AuditLog.Read.All` | Sign-ins, audit events for risk analysis |
| `IdentityRiskyUser.Read.All` | Risky users |
| `IdentityRiskEvent.Read.All` | Risk events |
| `SecurityEvents.Read.All` | Alerts |
| `SecurityAlert.Read.All` | Defender alerts |
| `SecurityIncident.Read.All` | Defender incidents |
| `ThreatIndicators.Read.All` | TI indicators |
| `SecurityActions.Read.All` | Security actions |
| `DeviceManagementConfiguration.Read.All` | Intune config profiles |
| `DeviceManagementManagedDevices.Read.All` | Intune devices |
| `DeviceManagementServiceConfig.Read.All` | Intune service config |
| `Reports.Read.All` | M365 reports & Secure Score |
| `InformationProtectionPolicy.Read.All` | Sensitivity labels |
| `Files.Read.All` (optional) | Sample SPO/OneDrive sharing analysis (off by default) |
| `Mail.ReadBasic.All` (optional) | Phishing/DLP heuristic checks (off by default) |

### 6.2 Defender XDR (Microsoft 365 Defender) — Application permissions

| Permission | Why |
|---|---|
| `AdvancedHunting.Read.All` | KQL hunting queries |
| `Machine.Read.All` | Device inventory in Defender for Endpoint |
| `Alert.Read.All` | Defender alerts |
| `Incident.Read.All` | Defender incidents |
| `Score.Read.All` | Secure Score for Devices |

### 6.3 Azure ARM / Resource Graph (RBAC)

Granted on the **Root Management Group** (or a chosen scope):

- `Reader`
- `Security Reader`
- `Microsoft Sentinel Reader` (per workspace)
- `Log Analytics Reader` (per workspace)
- `Reader and Data Access` on Storage accounts (for blob inventory metadata only; no data plane read by default)
- `Key Vault Reader` (metadata; no secret read)

### 6.4 Purview

- Purview RBAC `Data Reader` on the Purview account
- Graph `InformationProtectionPolicy.Read.All`

### 6.5 Optional / opt-in Write Permissions (Remediation Service Principal)

A **separate** app registration, off by default, with **narrowly scoped write** roles:
- `Contributor` constrained by Azure Policy to specific resource types and actions.
- Graph `Policy.ReadWrite.ConditionalAccess`, `DeviceManagementConfiguration.ReadWrite.All` — only when the customer enables a specific remediation flow.

### 6.6 Consent UX

- Admin-consent flow on first onboarding shows a clear permission list grouped by purpose.
- Each scanner module's permissions are listed independently; customers can disable any module and revoke its scopes.

---

## 7. Network Security

### 7.1 Ingress

- **Azure Front Door** with WAF (OWASP Core Rule Set + bot manager) is the only public entry point.
- **Front Door → APIM via Private Link** (origin restriction by Front Door ID header verified at APIM).
- **APIM** (Internal mode) → Container Apps (internal ingress) via VNet.

### 7.2 Egress

- All outbound traffic via **Azure Firewall** in the hub VNet.
- **FQDN allowlist** for: Microsoft Graph, ARM, Defender, Sentinel, Purview, TI feed endpoints, Azure OpenAI, package registries.
- **No direct internet** from compute subnets.

### 7.3 East-West

- **Private Endpoints** for: SQL, Cosmos, Storage, Key Vault, Service Bus, Event Hubs, AI Search, OpenAI, ACR, App Configuration.
- **Private DNS zones** in the hub.
- **NSGs** per subnet with deny-by-default; **Application Security Groups** for workload grouping.

### 7.4 Customer-tenant connectivity

- All API calls **outbound** from the platform to Microsoft endpoints (Graph, ARM, Defender, etc.).
- **No inbound** requirement to customer tenants.
- Optionally, customers can pin platform egress IPs (Standard SKU public IP) for their conditional access / firewall allow-lists.

### 7.5 DDoS

- Front Door provides L7 protection; subscription-level **Azure DDoS Protection Standard** on hub VNets.

---

## 8. Data Protection

### 8.1 At rest

- AES-256 with **CMK** for SQL, Cosmos, Storage, Service Bus, AI Search, Backup, Recovery Services.
- **Per-tenant CMK** in Enterprise tier.
- ADLS Gen2: per-tenant container, immutable retention for audit-evidence blobs (WORM via legal hold + time-based retention).

### 8.2 In transit

- TLS 1.2+ enforced everywhere; HSTS on web; mTLS optional for service-to-service in Enterprise mode.
- No legacy ciphers; quarterly TLS configuration audit.

### 8.3 In use

- Optional **Azure Confidential Computing** (DCsv3 / Confidential Containers) for AI inference in Enterprise tier.
- Memory secrets zeroized after use in custom code; standard for managed services.

### 8.4 PII & sensitive data

- Customer data classification:
  - **Tenant metadata** (tenant id, name, domains) — low sensitivity.
  - **User identifiers** (UPN, object id) — moderate.
  - **Findings & posture data** — moderate.
  - **Audit logs from customer tenant** — high.
  - **Raw scan evidence** — high; retained per tenant policy (default 90 days).
- **PII redaction** in:
  - All log entries.
  - All AI prompts (UPNs hashed unless explicitly authorized).
  - All telemetry exports.
- **Data residency**: customer chooses region at onboarding; data never leaves the chosen geo.
- **Data minimization**: scanners pull only required fields; raw bodies discarded after normalization (unless evidence retention is enabled).

### 8.5 Backup & DR

- SQL: geo-redundant backups, PITR 35 days.
- Cosmos: continuous backup, PITR 30 days, multi-region writes in Enterprise.
- Storage: ZRS minimum, GRS for audit-evidence containers.
- KV: soft-delete + purge protection.
- DR runbooks: RPO 15 min, RTO 1 hour (Pro); RPO 5 min, RTO 15 min (Enterprise).
- Backups encrypted with separate CMK from primary store.

---

## 9. Multi-Tenant Isolation

| Layer | Mechanism |
|---|---|
| **API** | Tenant context middleware injects `tenant_id`; every query is filter-mandatory; cross-tenant access throws `403` and alerts. |
| **SQL** | Single DB with `tenant_id` column on every row; **row-level security** policies; periodic isolation test in CI. |
| **Cosmos** | `tenant_id` as partition key; RBAC data-plane roles scoped per container. |
| **Storage** | Per-tenant container path; per-tenant SAS only via Managed Identity-signed user delegation keys; CMK per tenant in Enterprise. |
| **AI Search** | Per-tenant filter (Pro) or per-tenant index (Enterprise). |
| **Service Bus** | Per-tenant session id for ordered processing; subscription filters by `tenant_id`. |
| **AI** | Per-tenant RAG corpus; prompt templates load only the requesting tenant's documents. |
| **Audit** | Audit pipeline emits per-tenant streams; cross-tenant aggregation only in platform-admin views with extra approvals. |
| **Deletion** | Offboarding cascades across SQL, Cosmos, Storage, AI Search, Backup, Logs; certificate of deletion issued. |

**Automated isolation tests** run in CI: a synthetic Tenant B token attempting to read Tenant A data must always fail.

---

## 10. Audit & Compliance

### 10.1 Audit log content

Every audit event includes: `event_id`, `timestamp`, `tenant_id`, `actor_id`, `actor_type`, `action`, `resource_type`, `resource_id`, `outcome`, `source_ip`, `correlation_id`, `additional_context`.

Captured for:
- Authentications & token issuance.
- All read/write API calls touching customer data.
- Scan triggers, suppression actions, remediation actions.
- AI prompts and responses (with PII redaction).
- Connector configuration changes.
- Role assignments / changes.
- KV access events (mirrored from Azure diagnostic logs).

### 10.2 Storage

- Immutable Blob Storage container (time-based retention, legal hold) per tenant.
- Default retention: 1 year (Pro), 7 years (Enterprise / regulated).
- Optional **export to customer-supplied Sentinel workspace** (Enterprise).

### 10.3 Frameworks the platform itself targets

- **SOC 2 Type II** (after GA).
- **ISO 27001:2022**.
- **GDPR** (DPA, DPIA, sub-processor list, EU Standard Contractual Clauses where applicable).
- **Microsoft Cloud Security Benchmark** (continuously enforced via Defender for Cloud on platform subscription).
- **CIS Azure Benchmark** (gated via Azure Policy).
- **Zero Trust** maturity model — self-assessed quarterly.

### 10.4 Vulnerability management

- **Defender for DevOps** + **GHAS** on every repo.
- **Container image scanning** in ACR + Defender for Containers in runtime.
- **Dependency scanning**: Dependabot + Renovate; critical CVEs patched in ≤ 7 days.
- **External pen-test**: annual + before each major release.
- **Bug bounty**: opens at GA.

---

## 11. AI Security (additional controls)

- **Tenant-scoped RAG**: prompts only retrieve from the requesting tenant's index.
- **System prompt isolation**: system prompt is immutable per template; user content sandboxed.
- **Tool-use schema validation**: any function-calling output is JSON-schema-validated before execution.
- **Prompt-injection defenses**: input filtering, instruction hierarchies, output classifiers, citation enforcement, refusal patterns reviewed against OWASP Top 10 for LLMs.
- **PII redaction** before logging or telemetry.
- **No training on customer data** — contractual + technical (Azure OpenAI data privacy).
- **Cost & quota**: per-tenant token quotas to prevent budget abuse.
- **Auditability**: full prompt + response audit log (with PII redacted) retained per audit retention policy.

---

## 12. Incident Response

- 24×7 on-call (Pro) / dedicated (Enterprise).
- Severity matrix tied to SLO burn.
- **15-minute** initial response, **1-hour** customer-facing incident note (Pro); tighter for Enterprise.
- Incident channels: status page, email, Teams, optional webhook to customer SIEM.
- Post-incident reviews public for Sev1; private with the customer for Sev2.

---

## 13. Customer-Hosted Mode — Additional Controls

When the platform is deployed inside the customer's subscription via Bicep:

- Platform vendor has **no access** to customer data plane.
- Updates delivered via **signed Bicep release feed**; customer applies on their schedule.
- Telemetry to vendor is **opt-in** and contains only platform health (no customer findings).
- All identities are owned by the customer; no platform-side service principals in the customer tenant.

---

## 14. References & Mappings

This security model is mapped to: NIST CSF 2.0, ISO 27001:2022 Annex A, CIS Azure Benchmark, MCSB v1.x, SOC 2 Trust Services Criteria, GDPR Articles 5/25/28/32, Microsoft Zero Trust maturity model. Reference mappings are stored in `packages/frameworks/` and rebuilt monthly.
