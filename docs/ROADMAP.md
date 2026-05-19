# AzureLens — Implementation Roadmap

A milestone-driven plan from **design foundation → MVP → GA → enterprise → marketplace**. Each phase has clear exit criteria, target personas, and design artifacts that must exist before code is written.

> Branch convention: `feature/<phase>-<topic>`. The current branch is `feature/platform-foundation` and contains only design docs.

---

## Phase 0 — Platform Foundation  *(current — this branch)*

**Goal:** lock the architecture, contracts, security posture, and repository conventions before any code lands.

**Deliverables (this branch only):**
- `README.md` — product framing (problem, users, features, summary architecture, roadmap pointer).
- `docs/ARCHITECTURE.md` — full Azure-native architecture, monorepo layout, service decomposition.
- `docs/ROADMAP.md` — this document.
- `docs/SECURITY_MODEL.md` — RBAC, identities, secrets, network, data protection.
- `docs/THREAT_MODEL.md` — STRIDE per component, trust boundaries, mitigations.
- `docs/SCHEMA_DESIGN.md` — canonical data models for findings, assets, TI, mappings.
- `docs/AZURE_SERVICES.md` — every Azure service used, why, SKU choices, alternatives.
- `.gitignore` — polyglot.

**Exit criteria:**
- Architecture peer-reviewed by at least one security architect and one cloud architect.
- Threat model reviewed; high-risk mitigations agreed.
- Schemas reviewed for multi-tenant safety and PII handling.
- Repository conventions agreed (branching, ADRs, commit style).

**Out of scope (do not start yet):**
- Any application code, infrastructure code, CI/CD pipelines, tests, or sample data files.

---

## Phase 1 — Tenant Onboarding & Bootstrap MVP  *(v0.1)*

**Target persona:** internal pilot tenants + design partners.

**Scope:**
- Bicep IaC for a single-region deployment (network, identity, KV, SQL, Cosmos, ADLS, Blob, Container Apps env, APIM, Front Door, App Insights, LAW, OpenAI, AI Search).
- Multi-tenant Entra ID app registration (admin-consent flow).
- Backend API skeleton (`apps/api`) with auth + tenant resolver + `/health` + `/tenants/onboard`.
- Frontend shell (`apps/web`) with MSAL.js login + tenant selector + placeholder dashboards.
- `scanner-azure` MVP: subscriptions, resource groups, VMs, storage accounts, NSGs, public IPs, RBAC assignments. ARG-based.
- `scanner-m365` MVP: users, groups, admin roles, MFA state, Conditional Access policies, risky users.
- `compliance-engine` MVP: framework packs for **CIS Azure** and **MCSB** only.
- `risk-engine` MVP: base scoring (no campaign factor yet).
- `reporting` MVP: executive PDF only (Headless Chromium).
- CI/CD: PR validate + build + deploy-dev pipelines via GitHub OIDC.

**Exit criteria:**
- Onboard a real Azure tenant, run a full bootstrap scan, produce an executive PDF, in ≤ 30 minutes.
- All Phase 0 security controls live (no public data plane, Managed Identity, KV-only secrets, CMK for SQL/Storage).
- ≥ 70% unit-test coverage on engines.
- Defender for Cloud on the platform subscription = Secure score ≥ 90%.

---

## Phase 2 — Threat Intelligence Engine  *(v0.2)*

**Scope:**
- `ti-ingestion` workers for: CISA KEV, MITRE ATT&CK, Microsoft Defender TI, Microsoft Sentinel TI (TAXII).
- Normalized TI graph in Cosmos DB + AI Search index.
- `ti-correlation` worker: CVE↔inventory, technique↔posture, campaign↔asset (basic).
- Risk engine: add `campaign_proximity_factor` and `exploitability_factor` (KEV).
- Dashboard: "Threat Exposure" page + MITRE heatmap.
- API: `/threats`, `/threats/{id}`, `/threats/correlations`.

**Exit criteria:**
- TI freshness ≤ 90 min P95 for all configured sources.
- At least one real campaign correlation visible in a pilot tenant.
- TI ingestion is idempotent and survives source outage gracefully.

---

## Phase 3 — Compliance & Reporting Expansion  *(v0.3)*

**Scope:**
- Framework packs added: **NIST CSF**, **ISO 27001**, **SOC 2**, **GDPR**, **Zero Trust**, **Azure WAF**, **M365 baseline**.
- Mapping crosswalks (MITRE ↔ MCSB ↔ CIS ↔ NIST ↔ ISO ↔ SOC2).
- `reporting`: PPTX board deck, technical PDF, audit-evidence ZIP (signed).
- Power BI Embedded workspace + first 3 reports (Executive, Compliance, Identity).
- API: framework filters and evidence endpoints.

**Exit criteria:**
- Two design-partner CISOs sign off the executive narrative quality.
- One auditor signs off the audit-evidence pack format.

---

## Phase 4 — Device, Defender, Purview & Remediation  *(v0.4 → MVP-complete)*

**Scope:**
- `scanner-intune`: enrolled devices, compliance/config profiles, endpoint security, Defender onboarding, BitLocker, AV.
- `scanner-defender`: Defender XDR alerts/incidents, Defender for Cloud recommendations & sub-assessments, Secure Score deltas.
- `scanner-purview`: sensitivity labels, DLP policies, retention, eDiscovery readiness.
- `remediation` Center: templates with Azure CLI / PowerShell / Graph snippets + Azure Policy JSON.
- Optional one-click remediation (opt-in, scoped write SP, 4-eyes via Logic Apps).
- Dashboard: Device Posture, Compliance Center deep-dive, Remediation Backlog (Kanban).

**Exit criteria:**
- All ten scanner-led modules functional in pilot.
- At least 50 remediation templates curated and reviewed.

---

## Phase 5 — AI Engine & Copilot  *(v0.5)*

**Scope:**
- Prompt library for: executive narrative, finding explanation, remediation drafting, campaign briefing, compliance evidence drafting.
- RAG: per-tenant AI Search index (findings + relevant TI + reference packs + remediation library).
- Copilot conversational endpoint with citation enforcement.
- Output guards (schema, PII redaction, prompt-injection mitigations).
- Per-tenant token budgets + cost telemetry.

**Exit criteria:**
- Blind evaluation: ≥ 80% of AI-generated executive paragraphs preferred over template baseline by 3 reviewers.
- Zero prompt-injection escapes in red-team test suite.
- All AI outputs auditable end-to-end.

---

## Phase 6 — RBAC, Audit, Multi-Tenant Hardening  *(v0.6)*

**Scope:**
- Full role matrix: `GlobalAdmin`, `SecurityAdmin`, `Compliance`, `CloudArchitect`, `SOCAnalyst`, `ITManager`, `Auditor`, `ExecViewer`.
- Fine-grained scopes (subscription / framework / report).
- Per-tenant CMK with key rotation drills.
- Tenant offboarding with verifiable deletion certificate.
- Immutable audit log shipped to customer-supplied Sentinel workspace (optional).
- DPIA + DPA templates for GDPR.

**Exit criteria:**
- Pen-test (external) passed with no high/critical findings unmitigated.
- Tenant-isolation tests automated in CI (cross-tenant access must be impossible).

---

## Phase 7 — GA: SaaS Launch  *(v1.0)*

**Scope:**
- Multi-region active/active (primary + paired).
- SLOs published; status page; incident management runbooks.
- Pricing tiers + billing integration.
- Self-service onboarding from a public landing site.
- Documentation portal (customer-facing).
- Support: in-app tickets, knowledge base, SLA matrix.

**Exit criteria:**
- 99.9% availability over preceding 30 days (Pro tier).
- All Phase 0–6 docs current and externally publishable.

---

## Phase 8 — Enterprise & ISV / Customer-Hosted  *(v1.1)*

**Scope:**
- Dedicated Container Apps environments per Enterprise tenant.
- Per-tenant Private Endpoint and APIM product.
- Confidential Computing inference option for AI engine.
- Customer-hosted mode (signed Bicep release feed) — runs the entire product inside the customer's subscription.
- Custom roles + SSO with customer Entra ID (workforce) + B2B guest support.
- Premium support SLAs and dedicated TAM motion.

**Exit criteria:**
- One enterprise customer running in dedicated mode in production.
- One regulated customer running in customer-hosted mode.

---

## Phase 9 — Azure Marketplace & Integrations  *(v1.2)*

**Scope:**
- Azure Marketplace **Transactable SaaS Offer** + private offers.
- Microsoft AppSource listing.
- ServiceNow / Jira / GitHub Issues integration for remediation tickets.
- Teams app (in-product notifications + ask-copilot in chat).
- Webhooks + Logic Apps connector.
- Public REST API + SDK clients (TypeScript, Python, C#).
- Partner program for MSSPs (multi-customer console).

**Exit criteria:**
- First marketplace transaction.
- First MSSP partner onboarded with ≥ 3 downstream customers.

---

## Phase 10 — Continuous Innovation  *(v2.x)*

Optional / future:

- Attack-path graph (BloodHound-style for Entra + Azure RBAC).
- Predictive risk modeling (which control will degrade next).
- Auto-generated Azure Policy + DeployIfNotExists fixes.
- Tabletop-exercise generator from current tenant posture + active campaigns.
- Cyber-insurance evidence pack (mapped to common underwriter questionnaires).
- Native integration with Microsoft Security Copilot.
- Sovereign-cloud variants (Azure Gov, Azure China — separate compliance work).

---

## Cross-Phase Workstreams (always-on)

- **Security**: monthly threat model review; quarterly external pen-test; continuous Defender for DevOps.
- **Compliance**: SOC 2 Type I (after Phase 7), SOC 2 Type II (after Phase 8), ISO 27001 (after Phase 8), GDPR DPIA per release.
- **FinOps**: per-tenant cost attribution; reservation/savings-plan reviews quarterly.
- **Reliability**: error-budget reviews monthly; chaos engineering exercises quarterly (Azure Chaos Studio).
- **Reference data**: monthly refresh of framework packs and MITRE; weekly refresh of TI source connectors.

---

## Acceptance Definition

A phase is **complete** when:
1. All scoped capabilities are demonstrated end-to-end in staging by a non-author.
2. All new components have updated entries in `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `THREAT_MODEL.md`, `SCHEMA_DESIGN.md`, `AZURE_SERVICES.md`.
3. ADR is recorded for any deviation from the foundation design.
4. SLOs and dashboards exist for any new pipeline.
5. Cost impact estimated and approved.
6. Security and privacy reviews signed off.
