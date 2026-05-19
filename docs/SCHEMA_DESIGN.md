# AzureLens — Schema Design

Canonical data models for **assets**, **findings**, **scores**, **threat intelligence**, **mappings**, **AI artifacts**, and **audit**. Defines storage choices (Azure SQL vs Cosmos DB vs ADLS vs AI Search), partitioning, and multi-tenant invariants.

> Schemas are illustrative — they intentionally focus on shape and relationships, not on physical column types or DDL, which will be defined in a follow-up phase alongside the code.

---

## 1. Storage allocation

| Domain | Store | Why |
|---|---|---|
| Tenants, users, roles, configuration | **Azure SQL** | Strong relational + transactional + auditable |
| Findings (current state) | **Azure SQL** | Relational joins (frameworks, assets, evidence refs); row-level security |
| Findings (history / time-series) | **Azure SQL Hyperscale** + partitioning by month | Long retention, analytical scan |
| Asset graph + relationships | **Cosmos DB (NoSQL API)** with graph-style adjacency lists | Flexible, per-tenant partitioning |
| Threat intelligence corpus (STIX) | **Cosmos DB (NoSQL API)** | Flexible STIX shape, fast partition reads |
| TI search / RAG | **Azure AI Search** | Vector + lexical search |
| Raw scan evidence | **ADLS Gen2** | Cheap, immutable, append-only, CMK |
| Reports (PDF, PPTX) | **Blob Storage** | Static artifacts, signed URLs |
| Audit log | **Blob Storage (immutable)** + Log Analytics mirror | Tamper-evident, queryable |
| Telemetry / traces | **Application Insights + Log Analytics** | Operational |
| AI prompts/responses | **Cosmos DB (NoSQL API)** with TTL + sensitive-data redaction | Per-tenant, queryable |
| Feature flags / config | **Azure App Configuration** | Hot-reloadable, environment-scoped |

**Common invariants:**

- Every record has `tenant_id` (GUID). Cosmos partition key = `tenant_id`. SQL row-level security keyed on `tenant_id`.
- Every record has `created_at`, `updated_at`, `source` (`scanner-azure`, `scanner-m365`, …), `schema_version`.
- Soft-delete via `deleted_at`; hard-delete cascades only at tenant offboarding.
- Money-or-secret fields are referenced (never inlined): `key_vault_ref`, `evidence_blob_uri`.

---

## 2. Tenant & User Models (Azure SQL)

### 2.1 `tenants`

```
tenant_id              UUID PK
azure_tenant_id        UUID UNIQUE     -- customer Entra ID tenant
display_name           STRING
primary_domain         STRING
data_residency         ENUM(eu, us, uk, ...)
tier                   ENUM(free, pro, enterprise, customer_hosted)
status                 ENUM(provisioning, active, suspended, offboarding)
cmk_key_uri            STRING NULL     -- per-tenant KV key (Enterprise+)
created_at, updated_at TIMESTAMP
```

### 2.2 `tenant_users`

```
tenant_id              UUID FK -> tenants
user_oid               UUID            -- Entra ID object id
upn_hash               STRING          -- hashed UPN for audit (no plaintext UPN stored)
display_name           STRING
roles                  ARRAY<ENUM>     -- GlobalAdmin, SecurityAdmin, ...
is_active              BOOL
last_login_at          TIMESTAMP
PK (tenant_id, user_oid)
```

### 2.3 `tenant_connectors`

```
tenant_id              UUID FK
connector_type         ENUM(graph, arm, defender_xdr, sentinel, intune, purview, misp, otx, vt, opencti)
status                 ENUM(connected, degraded, error, disabled)
consented_scopes       ARRAY<STRING>
last_success_at        TIMESTAMP
last_error             JSON NULL
secret_ref             STRING NULL     -- KV reference, never plaintext
PK (tenant_id, connector_type)
```

---

## 3. Asset Model

Assets are the things in the customer environment we scan and reason about.

### 3.1 Common shape (Cosmos DB container `assets`, partition key = `tenant_id`)

```
{
  "id": "<asset_uri_sha256>",                  // stable, computed
  "tenant_id": "<uuid>",
  "asset_uri": "azure://subscriptions/.../resourceGroups/.../providers/...",
  "asset_kind": "azure.vm | azure.storage | azure.keyvault | m365.user | m365.group | intune.device | azure.subscription | ...",
  "platform": "azure | m365 | intune",
  "subscription_id": "<uuid|null>",
  "resource_group": "<string|null>",
  "location": "<azure region|null>",
  "tags": { "<k>": "<v>" },
  "criticality": "low | moderate | high | critical",  // tenant-set
  "owners": ["<upn_hash>"],
  "properties": { /* asset-kind-specific shape, see below */ },
  "relationships": [
    { "type": "located_in", "to": "<asset_id>" },
    { "type": "uses_identity", "to": "<asset_id>" },
    { "type": "exposes", "to": "<asset_id>" }
  ],
  "discovered_at": "<ts>",
  "last_seen_at": "<ts>",
  "source": "scanner-azure",
  "schema_version": 1
}
```

### 3.2 Asset-kind property excerpts

`azure.vm`:
```
{ "vm_size": "...", "os": "Linux|Windows", "image_publisher": "...", "image_offer": "...",
  "image_sku": "...", "public_ip": "<ip|null>", "managed_disks": [...], "nics": [...],
  "open_ports": [22, 3389], "patch_state": "...", "defender_for_servers": "on|off" }
```

`azure.storage`:
```
{ "kind": "StorageV2", "tls_min": "TLS1_2", "allow_blob_public_access": false,
  "network_default_action": "Deny", "private_endpoints": [...], "cmk_uri": "<kv-key-uri|null>",
  "secure_transfer_required": true }
```

`m365.user`:
```
{ "account_enabled": true, "mfa_strength": "phishing_resistant | software_oath | sms | none",
  "is_privileged": true, "pim_eligible": true, "risk_level": "low|medium|high|none",
  "risky_sign_ins_30d": 0, "licenses": [...], "directory_roles": [...] }
```

`intune.device`:
```
{ "os": "Windows|macOS|iOS|Android", "compliance_state": "compliant|noncompliant|unknown",
  "is_encrypted": true, "defender_onboarded": true, "last_check_in": "<ts>",
  "owner_oid": "<uuid>", "configuration_profiles": [...] }
```

### 3.3 Asset graph (Cosmos container `asset_edges`)

```
{
  "id": "<from>__<type>__<to>",
  "tenant_id": "<uuid>",
  "from_id": "<asset_id>",
  "to_id": "<asset_id>",
  "edge_type": "located_in | uses_identity | exposes | depends_on | governed_by",
  "properties": { ... },
  "discovered_at": "<ts>"
}
```

---

## 4. Finding Model

### 4.1 `findings` (Azure SQL — current state)

```
finding_id             UUID PK
tenant_id              UUID FK            -- RLS keyed on this
title                  STRING
description            TEXT
finding_type           STRING             -- e.g., "identity.mfa.missing", "azure.storage.public_access"
severity               ENUM(info, low, medium, high, critical)
status                 ENUM(open, acknowledged, suppressed, remediated, false_positive)
first_seen_at          TIMESTAMP
last_seen_at           TIMESTAMP
last_evaluated_at      TIMESTAMP
asset_id               STRING FK -> assets
source_scanner         STRING             -- scanner-azure, scanner-m365, ...
evidence_blob_uri      STRING             -- ADLS Gen2 uri
mitre_techniques       JSON               -- ["T1078", "T1556.001"]
framework_mappings     JSON               -- see § 6
exploitability         ENUM(none, theoretical, poc, active)
risk_score             DECIMAL            -- 0-100
campaign_links         JSON               -- summary array; full join via Cosmos
remediation_template_id STRING NULL
acknowledged_by        UUID NULL
acknowledged_at        TIMESTAMP NULL
suppression_reason     STRING NULL
schema_version         INT
```

Row-level security: `USING (tenant_id = SESSION_CONTEXT('tenant_id'))`.

### 4.2 `findings_history` (Azure SQL — append-only, monthly partition)

Same shape as `findings` + `recorded_at`. Enables trend analysis and audit.

### 4.3 `finding_evidence` (ADLS Gen2)

- One blob per finding evaluation: `tenants/{tenant_id}/findings/{finding_id}/{eval_ts}.json`.
- Contents: raw API responses (sanitized), query used, scanner version, processor version.
- Immutable retention (90d default; configurable).

---

## 5. Threat Intelligence Model (STIX-aligned, Cosmos DB)

Containers (partition key = `tenant_id` for tenant-private TI; `"shared"` for global TI corpus shared across tenants but tagged):

### 5.1 `ti_indicators`

```
{
  "id": "<source>::<external_id>",
  "tenant_id": "shared | <uuid>",
  "stix_type": "indicator",
  "indicator_type": "ipv4 | ipv6 | domain | url | sha256 | md5 | email | regkey | filename | mutex",
  "pattern": "<STIX pattern>",
  "value": "<raw>",
  "labels": ["malicious-activity", "phishing", ...],
  "kill_chain_phases": [...],
  "valid_from": "<ts>",
  "valid_until": "<ts|null>",
  "confidence": 0-100,
  "trust_score": 0-1,                        // per-source × per-tenant
  "sources": ["defender_ti", "misp", ...],
  "external_references": [...],
  "schema_version": 1
}
```

### 5.2 `ti_campaigns`

```
{
  "id": "campaign::<uuid>",
  "stix_type": "campaign",
  "name": "Akira ransomware – RDP brute-force wave",
  "description": "...",
  "aliases": [...],
  "first_seen": "<ts>",
  "last_seen": "<ts>",
  "objective": "ransomware | espionage | hacktivism | data-theft",
  "target_sectors": ["financial", "healthcare"],
  "target_geographies": ["EU", "US"],
  "attributed_to": ["threat_actor::<id>"],
  "techniques": ["T1133", "T1078"],
  "indicators": ["indicator::<id>", ...],
  "vulnerabilities": ["CVE-2024-XXXXX"],
  "sources": [...]
}
```

### 5.3 `ti_vulnerabilities` (CVE)

```
{
  "id": "CVE-YYYY-NNNNN",
  "cvss_v3": 9.8,
  "cvss_v4": 9.4,
  "is_kev": true,
  "kev_added_date": "<ts>",
  "epss_score": 0.97,
  "affected_cpes": [...],
  "affected_products": [...],
  "references": [...],
  "techniques": ["T1190"]
}
```

### 5.4 `ti_threat_actors`, `ti_malware`, `ti_tools`, `ti_attack_patterns`

STIX 2.1 SDOs, normalized to the same envelope.

### 5.5 `ti_relationships`

```
{
  "id": "<from>__<rel>__<to>",
  "source_ref": "<sdo_id>",
  "relationship_type": "uses | targets | mitigates | attributed-to | indicates | exploits",
  "target_ref": "<sdo_id>",
  "confidence": 0-100,
  "sources": [...]
}
```

### 5.6 `ti_correlations` (per-tenant)

```
{
  "id": "<uuid>",
  "tenant_id": "<uuid>",
  "ti_id": "<indicator|campaign|vuln id>",
  "asset_id": "<asset id>",
  "match_dimension": "cve_in_inventory | ip_in_nsg | domain_in_traffic | technique_to_finding | sector_alignment | platform_match",
  "confidence": 0-100,
  "evidence": { /* small structured evidence object */ },
  "first_observed_at": "<ts>",
  "last_observed_at": "<ts>"
}
```

---

## 6. Framework & Mapping Model

### 6.1 Framework reference packs (versioned, signed; in `packages/frameworks`)

```
{
  "framework_id": "cis_azure",
  "version": "2.1.0",
  "title": "CIS Microsoft Azure Foundations Benchmark",
  "controls": [
    {
      "control_id": "1.1.1",
      "title": "Ensure that multi-factor authentication is enabled for all privileged users",
      "category": "Identity and Access Management",
      "severity_hint": "high",
      "mappings": {
        "mcsb": ["IM-7"],
        "nist_csf": ["PR.AC-1"],
        "iso_27001": ["A.9.4.2"],
        "soc2": ["CC6.1"],
        "mitre_techniques": ["T1078", "T1110"]
      }
    },
    ...
  ]
}
```

### 6.2 Mapping crosswalks

A separate Cosmos container `framework_crosswalks` indexed for fast lookup `(from_framework, from_control) → (to_framework, to_control)`.

### 6.3 Finding ↔ framework join (embedded in `finding.framework_mappings`)

```
{
  "cis_azure": [{ "version": "2.1.0", "controls": ["1.1.1"] }],
  "mcsb":      [{ "version": "1.0",   "controls": ["IM-7"] }],
  "nist_csf":  [{ "version": "2.0",   "subcategories": ["PR.AC-1"] }],
  "iso_27001": [{ "version": "2022",  "annex_a": ["A.5.17"] }],
  "soc2":      [{ "version": "2017",  "criteria": ["CC6.1"] }],
  "gdpr":      [{ "articles": [32] }],
  "zero_trust":[{ "pillar": "identity" }],
  "azure_waf": [{ "pillar": "security" }],
  "m365_baseline":[{ "control": "PRIV-1" }]
}
```

---

## 7. Scoring Model

### 7.1 `scores_current` (SQL — one row per tenant + score kind)

```
tenant_id              UUID
score_kind             ENUM(overall, identity, azure_exposure, device, threat_exposure, m365_compliance)
value                  INT 0-100
band                   ENUM(critical, weak, moderate, strong, excellent)
contributing_findings  JSON (top-N finding ids)
calculated_at          TIMESTAMP
PK (tenant_id, score_kind)
```

### 7.2 `scores_history` (SQL — daily snapshot)

Same shape + `recorded_date`.

### 7.3 Risk score per finding

Stored on `findings.risk_score`. Computation parameters live in a versioned policy doc (Cosmos `scoring_policies`), tenant-overridable:

```
{
  "tenant_id": "<uuid>",
  "policy_version": 3,
  "weights": {
    "severity": { "critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5 },
    "exploitability_multiplier": { "active": 1.5, "poc": 1.2, "theoretical": 1.0, "none": 0.9 },
    "exposure_multiplier":       { "public": 1.3, "partner": 1.1, "internal": 1.0 },
    "campaign_proximity_multiplier": { "direct": 1.4, "sector": 1.15, "none": 1.0 },
    "compliance_weight_max": true,
    "business_impact_multiplier_default": 1.0
  }
}
```

---

## 8. Remediation Model

### 8.1 `remediation_templates` (SQL or Cosmos `remediation_templates`)

```
{
  "template_id": "rt.identity.enforce_mfa_privileged.v2",
  "title": "Enforce phishing-resistant MFA for all privileged roles",
  "applies_to": {
    "finding_types": ["identity.mfa.privileged.missing"],
    "platforms": ["m365", "azure"]
  },
  "controls": { /* same shape as framework_mappings */ },
  "steps": [
    { "kind": "azure_cli", "code": "az ad ..." },
    { "kind": "powershell", "code": "..." },
    { "kind": "graph", "method": "POST", "url": "...", "body": { ... } },
    { "kind": "azure_policy", "definition": { ... } },
    { "kind": "doc", "url": "https://learn.microsoft.com/..." }
  ],
  "estimated_minutes": 30,
  "rollback_steps": [ ... ],
  "risk_reduction_estimate": 10,
  "author": "platform",
  "version": 2
}
```

### 8.2 `remediation_actions` (SQL — audit of any remediation executed)

```
action_id              UUID PK
tenant_id              UUID
finding_id             UUID
template_id            STRING
requested_by           UUID
approved_by            UUID NULL          -- 4-eyes requirement
status                 ENUM(requested, approved, executing, succeeded, failed, rolled_back)
target_asset_id        STRING
diff_before            JSON
diff_after             JSON
started_at, ended_at   TIMESTAMP
```

---

## 9. AI Artifacts (Cosmos DB)

### 9.1 `ai_prompts`

```
{
  "id": "<uuid>",
  "tenant_id": "<uuid>",
  "template_id": "exec.summary.v1",
  "model_deployment": "gpt-4o-2024-xx",
  "input_refs": ["finding::<id>", "score::overall"],
  "prompt_redacted": "...",     // PII-redacted
  "response_redacted": "...",   // PII-redacted
  "tokens_in": 1234,
  "tokens_out": 567,
  "latency_ms": 920,
  "user_oid": "<uuid|null>",    // null for system-triggered
  "correlation_id": "<traceparent>",
  "created_at": "<ts>",
  "ttl_days": 365
}
```

### 9.2 `ai_rag_index` (Azure AI Search — per-tenant index in Enterprise)

Fields:
- `id` (string, key)
- `tenant_id` (filterable)
- `doc_type` (filterable: `finding | framework_control | ti_campaign | remediation | playbook`)
- `title` (searchable)
- `content` (searchable, retrievable)
- `embedding` (vector, e.g. 3072-dim for text-embedding-3-large)
- `tags` (collection, filterable)
- `last_indexed_at` (date)

---

## 10. Audit Model

### 10.1 `audit_events` (Blob — immutable, JSONL per day per tenant)

```
{
  "event_id": "<uuid>",
  "timestamp": "<iso>",
  "tenant_id": "<uuid>",
  "actor_id": "<uuid>",
  "actor_type": "user | system | service_principal",
  "action": "finding.read | finding.suppress | scan.trigger | ai.prompt | connector.update | ...",
  "resource_type": "finding | report | tenant | connector | ...",
  "resource_id": "<id>",
  "outcome": "success | failure | denied",
  "source_ip": "<ip>",
  "correlation_id": "<traceparent>",
  "context": { /* additional structured context */ }
}
```

Also mirrored to Log Analytics for queryability and to a customer-supplied Sentinel workspace (Enterprise opt-in).

---

## 11. Reporting Model

### 11.1 `reports`

```
report_id              UUID PK
tenant_id              UUID
kind                   ENUM(executive_pdf, technical_pdf, audit_evidence_zip, board_pptx, csv_export, json_export)
parameters             JSON
generated_at           TIMESTAMP
blob_uri               STRING
sha256                 STRING                -- integrity
signed_by              STRING                -- signing key id
expires_at             TIMESTAMP NULL
generated_by           UUID                  -- user or system
schema_version         INT
```

---

## 12. Multi-Tenant Invariants (enforced everywhere)

1. **Mandatory partition**: every Cosmos query specifies `tenant_id` as partition key. Queries without it are rejected at the SDK middleware.
2. **Mandatory filter**: every SQL query is enforced by RLS on `tenant_id`; RLS is also asserted in CI tests.
3. **Mandatory scope on Blob**: every read/write path begins with `tenants/{tenant_id}/`. SAS tokens are user-delegation tokens scoped to that prefix.
4. **Mandatory filter on AI Search**: queries always include `filter=tenant_id eq '<id>'`.
5. **Mandatory header on events**: every event in Service Bus / Event Grid carries `tenant_id` in application properties; consumers reject events where the `tenant_id` does not match the context they are operating under.
6. **Cross-tenant deny tests**: synthetic tests run nightly attempting to read tenant B data with tenant A credentials. Failure of any test = automatic rollback of the affected release.

---

## 13. Retention & Lifecycle

| Data | Default retention | Configurable per tenant |
|---|---|---|
| Findings (current) | indefinite (while tenant active) | — |
| Findings history | 2 years | 1–7 years |
| Raw scan evidence | 90 days | 30–365 days |
| Reports | 1 year | 30 days – 7 years |
| Audit logs | 1 year (Pro) / 7 years (Enterprise) | matches tier minimum |
| AI prompts/responses | 365 days | 30 days – tier-max |
| TI shared corpus | rolling (per-source TTL) | — |
| Backups | 35d PITR (SQL) / 30d (Cosmos) | tier-dependent |

Tenant offboarding triggers a cascade deletion job with verifiable certificate of deletion (hashes of deleted blobs, row counts, container deletions).

---

## 14. Versioning & Migration

- Every schema document carries `schema_version`.
- Migrations are forward-only; readers must tolerate old versions for at least one minor release.
- Cosmos changes via background **change-feed processors**; SQL changes via versioned DACPAC / EF migrations.
- Reference framework packs are immutable per version; new versions added side-by-side.
