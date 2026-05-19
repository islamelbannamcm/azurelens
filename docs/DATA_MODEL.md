# AzureLens — Data Model (entity view)

A business-friendly walkthrough of the AzureLens domain. Where this document and `docs/SCHEMA_DESIGN.md` diverge in detail, **`SCHEMA_DESIGN.md` is authoritative** for persistence and `apps/api/app/models/` is authoritative for wire/runtime shapes.

---

## 1. The five rings

```
                          ┌──────────────────────────┐
                          │        Tenant            │
                          │  (one per customer org)  │
                          └────────────┬─────────────┘
                                       │ owns
       ┌───────────────────────────────┴───────────────────────────────┐
       │                                                                 │
       ▼                                                                 ▼
 ┌─────────────┐    discovers     ┌─────────────┐   produces    ┌─────────────┐
 │  Connector  │ ───────────────► │   Asset     │ ────────────► │  Finding    │
 │  (Graph,    │                  │  (VM, user, │               │  (gap,      │
 │   ARG, ...)│                   │   device,   │               │   posture,  │
 │             │                  │   policy)   │               │   compliance│
 └─────────────┘                  └──────┬──────┘               └──────┬──────┘
                                          │                              │ scored
                                          │ correlates                   ▼
                                          │ with                  ┌─────────────┐
                                          │                       │   Score     │
                                          │                       │ (per kind)  │
                                          │                       └─────────────┘
                                          ▼
                                   ┌─────────────┐
                                   │ TI object   │       relates to
                                   │ (campaign,  │ ◄────────────────┐
                                   │  indicator, │                  │
                                   │  CVE, TTP)  │                  │
                                   └──────┬──────┘                  │
                                          │                          │
                                          ▼                          │
                                   ┌─────────────────────────────────┴─┐
                                   │       CorrelationHit              │
                                   │  (TI ⨝ asset / finding per tenant)│
                                   └─────────────────────────────────┬─┘
                                                                     │
                                                                     ▼
                                                              ┌─────────────┐
                                                              │   Report    │
                                                              │ (exec, tech,│
                                                              │  audit, BI) │
                                                              └─────────────┘
```

---

## 2. Tenant

The **root of everything**. Every persisted record carries `tenant_id` (our internal UUID). The customer's Microsoft Entra ID GUID is `azure_tenant_id` — a separate identifier.

Key fields:
- `id` — internal UUID, partition key everywhere.
- `azure_tenant_id` — customer Entra ID tenant GUID.
- `tier` — `free | pro | enterprise | customer_hosted`.
- `status` — `provisioning | active | suspended | offboarding`.
- `data_residency` — `eu | uk | us | ...`.
- `cmk_key_uri` — per-tenant Customer-Managed Key (Enterprise).

Sub-objects: `TenantConnector` (per integration), `TenantContact` (admin contact).

Lifecycle: admin-consent → provisioning → bootstrap scan → active.

---

## 3. Asset

Anything we discover. We keep a single, unified asset graph spanning Azure, Entra ID/M365, Intune, Defender, and Purview.

Key fields:
- `id` — sha256 of canonical `asset_uri`.
- `asset_uri` — canonical identifier (e.g. `azure://subscriptions/.../vm-x`, `m365://users/<oid>`).
- `asset_kind` — taxonomy enum (`azure.vm`, `m365.user`, `intune.device`, ...).
- `provider` — `azure | m365 | entra_id | intune | defender_xdr | purview | aws | gcp`.
- `properties` — kind-specific shape (open ports for a VM, MFA state for a user, ...).
- `relationships` — edges in the asset graph (`located_in`, `uses_identity`, `has_role`, `exposes`, `depends_on`, ...).
- `criticality` — tenant-set business criticality.
- `exposure` — `internal | partner | public | unknown`.

Edges live in a separate Cosmos container (`asset_edges`) with their own model.

---

## 4. Finding

The **central security artifact**. Every dashboard, score, report, and remediation traces back to findings.

Key fields:
- `id` — internal UUID.
- `finding_type` — stable dotted id (`identity.mfa.privileged.missing`, `azure.network.rdp_public_exposed`).
- `severity` — `info | low | medium | high | critical`.
- `status` — `open | acknowledged | suppressed | remediated | false_positive`.
- `exploitability` — `none | theoretical | poc | active`.
- `mitre_tactics` (TA0001..TA0040) and `mitre_techniques` (`T1078`, `T1556.001`, ...).
- `framework_mappings` — multi-framework crosswalk (see § 6).
- `risk_score` — 0–100, computed by the risk engine (see § 7).
- `campaign_links` — pointers into TI correlations (see § 8).
- `asset_id` — the asset this finding hangs off.
- `evidence_blob_uri` — ADLS Gen2 location of the raw scan evidence.
- `remediation` — pointer to a remediation template + estimated effort.

A finding's *history* is preserved append-only in `findings_history` for trend analysis.

A separate envelope, `RawFinding`, is what scanners emit to Service Bus before the compliance engine normalizes it into the persisted `Finding`.

---

## 5. Connector & Scan

Connectors describe the *integration* between AzureLens and a customer's external system. Each tenant has zero or one `TenantConnector` per `ConnectorType`.

Connector types span:
- **Microsoft platforms** — Graph, ARM, Resource Graph, Defender for Cloud, Defender XDR, Sentinel, Intune, Purview, Policy.
- **Threat intelligence** — Defender TI, Sentinel TI, CISA KEV, MITRE ATT&CK, MISP, OpenCTI, OTX, abuse.ch, VirusTotal, GHSA, NVD.

Each connector has a `status` (`connected | degraded | error | disabled | not_configured`), a list of `consented_scopes`, and a Key Vault `secret_ref` (never an inline secret).

A `Scan` is the *act* of running one or more scanners against a tenant. Kinds: `azure | m365 | intune | defender | purview | full`. Statuses: `requested → queued → running → completed | partial | failed | cancelled`. Trigger types: `bootstrap | scheduled | incremental | on_demand | targeted`. A `ScanSummary` row tracks progress (partitions completed/total, findings produced).

---

## 6. Compliance Framework & Mapping

A framework is a versioned reference pack consisting of `FrameworkControl` entries; each control optionally crosswalks to other frameworks.

Supported frameworks (extensible):

| Enum | Notes |
|---|---|
| `cis_azure` | CIS Microsoft Azure Foundations Benchmark |
| `mcsb` | Microsoft Cloud Security Benchmark |
| `nist_csf` | NIST CSF 2.0 |
| `nist_800_53` | (Phase 3) |
| `iso_27001` | Annex A (2022) |
| `soc2` | Trust Services Criteria |
| `gdpr` | Articles |
| `zero_trust` | Pillars |
| `azure_waf` | Security pillar |
| `m365_baseline` | Microsoft 365 baseline |
| `cis_m365` | CIS Microsoft 365 Benchmark |
| `hipaa`, `pci_dss` | (Future) |

`FrameworkMappings` is the **strict shape** of the multi-framework tag carried on every Finding. The per-tenant projection is `ComplianceFrameworkPosture` (rollup) + `ComplianceControlState` (per-control).

---

## 7. Score

Numbers that summarize the tenant's posture. All scores are 0–100 with banded labels (`critical | weak | moderate | strong | excellent`).

Kinds:
- `overall`
- `identity`
- `azure_exposure`
- `device`
- `threat_exposure`
- `m365_compliance`

`Score` rows live in `scores_current` (one per tenant per kind); daily snapshots go to `scores_history` (driving trend dashboards). Every score carries a `ScoringPolicyRef` so audits can reproduce the calculation against the exact policy version used.

Per-finding risk score formula (v1):

```
risk = base_severity
     × exploitability_factor
     × exposure_factor
     × business_impact_factor
     × compliance_weight
     × campaign_proximity_factor
```

The breakdown is preserved (`ScoreBreakdown`) for explainability.

---

## 8. Threat Intelligence (TI)

STIX 2.1-aligned shapes. Shared corpus uses `tenant_id = "shared"`; tenant-private indicators use the customer tenant UUID.

Objects:
- `Indicator` (IOC: IP, domain, URL, hash, email, regkey, filename, mutex, user_agent, JA3).
- `Campaign` (named campaign with target sectors/geographies, techniques, attributions).
- `Vulnerability` (CVE, with CVSS, EPSS, CISA KEV flag).
- `ThreatActor`, `Malware`, `Tool`.
- `AttackPattern` (MITRE technique).
- `TIRelationship` (edges: `uses`, `targets`, `mitigates`, `indicates`, `exploits`, `attributed-to`).

Each TI object carries `sources[]` (list of `TISource` enum values), `confidence (0..100)`, and `trust_score (0..1)`.

`CorrelationHit` is the **per-tenant** join row: which TI object touches which asset/finding, along what `match_dimension`:

- `cve_in_inventory`
- `ip_in_nsg`
- `domain_in_traffic`
- `url_in_traffic`
- `technique_to_finding`
- `sector_alignment`
- `platform_match`

`CampaignExposureSummary` is the dashboard-ready rollup per tenant per campaign.

---

## 9. Report

An immutable artifact produced by `services/reporting`. Types:

| Type | Audience |
|---|---|
| `executive_pdf` | CISO, executives |
| `technical_pdf` | Security engineers, cloud architects |
| `audit_evidence_zip` | External / internal auditors |
| `board_pptx` | Board of directors |
| `csv_export`, `json_export` | Downstream BI / SIEM |

Status: `requested → queued → rendering → ready | failed | expired`.

Every report is signed (SHA-256 + Key Vault key id) and stored in immutable Blob containers per tenant.

---

## 10. Remediation

A `RemediationTemplate` is a reusable, version-pinned playbook keyed by `(finding_type, framework_control, technique)`. It contains `RemediationStep`s of kinds: `azure_cli | powershell | ms_graph | azure_policy | doc_link | manual`.

A `RemediationAction` is an **audit-grade record** of a remediation being executed (manual or, when enabled, one-click). Status: `not_started | suggested | requested | approved | executing | succeeded | failed | rolled_back`. The pre/post diff is captured for audit.

One-click remediation is opt-in, off by default, and requires a separate **scoped write** service principal plus a 4-eyes approval flow.

---

## 11. AI artifacts

Not exposed directly via this API surface in Phase 0/1, but referenced for completeness:

- `AIPromptLog` — per-call audit (template id, model deployment, redacted prompt + response, tokens, latency, correlation id).
- AI Search index — per-tenant RAG corpus (findings + relevant TI + framework reference + remediation playbooks).

See `docs/ARCHITECTURE.md` § 8 and `docs/SECURITY_MODEL.md` § 11.

---

## 12. Audit

Every read of customer data, every privileged action, every AI prompt is captured as an `AuditEvent` and streamed to an immutable Blob container plus Log Analytics. The shape includes `event_id`, `tenant_id`, `actor_id`, `actor_type`, `action`, `resource_type`, `resource_id`, `outcome`, `source_ip`, `correlation_id`, `context`.

Audit shape is intentionally not yet exposed via the public API (planned for Phase 6 `/admin/audit/*`).

---

## 13. Multi-tenant invariants (recap)

Every model in this document carries (or transitively reaches) a `tenant_id`. These invariants are enforced at multiple layers (see `docs/SCHEMA_DESIGN.md` § 12):

1. Every Cosmos query uses `tenant_id` as the partition key.
2. Every SQL query is filtered by `tenant_id` (Row-Level Security enforces this).
3. Every Service Bus / Event Grid message carries `tenant_id` in application properties.
4. Every AI Search query carries `filter=tenant_id eq '<id>'`.
5. Every Blob path begins with `tenants/{tenant_id}/`.
6. Cross-tenant attempts produce `404 Not Found` (never `403`) to avoid information disclosure.

---

## 14. Where to find the wire shapes

| Concern | File |
|---|---|
| Tenant, Connector, Role | `apps/api/app/models/tenant.py` |
| Asset graph + edges | `apps/api/app/models/asset.py` |
| Finding, MITRE tactic, severity | `apps/api/app/models/finding.py` |
| Threat intelligence (STIX) | `apps/api/app/models/threat_intel.py` |
| Compliance framework + mapping | `apps/api/app/models/compliance.py` |
| Score + Scan | `apps/api/app/models/scoring.py` |
| Report + Remediation | `apps/api/app/models/report.py` |
| Cross-cutting (TenantScoped, pagination, audit metadata) | `apps/api/app/models/common.py` |
| Re-exports | `apps/api/app/models/__init__.py` |

---

## 15. Next steps

These models intentionally cover the **full target product** so backward-compatibility commitments can start now. Phase 1 wires real persistence and tenant isolation. Phase 2 implements TI ingestion and correlation. Phase 3 expands framework reference packs. Phase 5 wires the AI engine. See `docs/ROADMAP.md`.
