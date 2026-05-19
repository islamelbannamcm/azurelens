# AzureLens — API Contracts

The HTTP surface of the AzureLens platform: what each resource is, what every endpoint does, who can call it, what it returns, and how it evolves.

> Canonical implementation: Pydantic v2 models in `apps/api/app/models/` + FastAPI routers in `apps/api/app/api/v1/`.
> Cross-language consumers: `packages/contracts/` (see `packages/contracts/README.md` and `packages/contracts/openapi-contract-notes.md`).

---

## 1. Surface Overview

Base URL: `https://{host}/api/v1`.

| Resource | Endpoints | Purpose |
|---|---|---|
| `meta`        | `GET /health`                                    | Liveness / readiness probes |
| `tenants`     | `GET /tenants`, `GET /tenants/{id}`, `POST /tenants/onboard` | Tenant lifecycle |
| `assets`      | `GET /assets`, `GET /assets/{id}`                | Discovered assets in the customer environment |
| `findings`    | `GET /findings`, `GET /findings/{id}`, `POST /findings/{id}/acknowledge` | Posture & compliance findings |
| `threat-intel`| `GET /threat-intel/campaigns(/{id})`, `/indicators`, `/vulnerabilities`, `/correlations`, `/exposure/campaigns` | TI corpus + tenant correlations |
| `compliance`  | `GET /compliance/frameworks(/{f}/posture|controls(/{cid}))` | Per-framework posture & control state |
| `reports`     | `GET /reports(/{id})`, `POST /reports`           | Report artifacts |

All listing endpoints are paginated with opaque cursors. All write endpoints accept `Idempotency-Key`. All endpoints are tenant-scoped via the JWT `tid` claim.

Phase 1 adds: `/scores`, `/scans`, `/copilot/messages`, `/admin/*`, `/webhooks/*`.

---

## 2. Resources

### 2.1 Tenant

Represents an onboarded customer Entra ID tenant. One AzureLens `tenant_id` (our own UUID) per customer.

Lifecycle: `provisioning → active → suspended → offboarding`.

Key fields: `id`, `azure_tenant_id`, `display_name`, `primary_domain`, `tier`, `status`, `data_residency`, `cmk_key_uri`.

Endpoints:

- `GET /tenants` — visible to the caller. Phase 1: filtered by RBAC.
- `GET /tenants/{id}` — single tenant; cross-tenant returns `404`.
- `POST /tenants/onboard` — admin-consent callback handler; `202 Accepted` with a `provisioning` tenant.

Required permissions: `GlobalAdmin`.

### 2.2 Asset

Anything discovered: Azure subscriptions, VMs, storage, networking, Entra ID users, devices, M365 policies, Purview labels, etc. Backed by Cosmos DB asset graph with relationships.

Key fields: `id`, `tenant_id`, `asset_uri`, `asset_kind`, `provider`, `criticality`, `exposure`, `properties`, `relationships`.

Endpoints:

- `GET /assets?provider=...&asset_kind=...&exposure=...&criticality=...` — paginated, tenant-scoped.
- `GET /assets/{id}` — full asset including properties and immediate relationships.

Required permissions: any tenant role except `ExecViewer`.

### 2.3 Finding

The platform's central artifact: a normalized, framework-mapped security/compliance gap on an asset.

Key fields: `id`, `tenant_id`, `finding_type`, `severity`, `status`, `risk_score`, `mitre_tactics`, `mitre_techniques`, `framework_mappings`, `campaign_links`, `remediation`, `asset_id`, `evidence_blob_uri`.

Status lifecycle: `open → acknowledged | suppressed | remediated | false_positive`.

Endpoints:

- `GET /findings?severity=...&status=...&asset_id=...&mitre_technique=...&framework=...` — paginated, tenant-scoped.
- `GET /findings/{id}` — full finding with embedded mappings + remediation reference.
- `POST /findings/{id}/acknowledge` — RBAC-gated; transitions to `acknowledged` or `suppressed` (when `suppress_until` is set). Audit-logged.

Required permissions:
- list/get: `SecurityAdmin`, `Compliance`, `CloudArchitect`, `SOCAnalyst`, `ITManager`, `Auditor`, `GlobalAdmin`.
- acknowledge/suppress: `SecurityAdmin` or `GlobalAdmin` (Compliance can suppress only compliance-typed findings).

### 2.4 Threat Intel (Campaigns, Indicators, Vulnerabilities, Correlations)

STIX-aligned shapes for ingested TI plus per-tenant correlation results.

Endpoints:

- `GET /threat-intel/campaigns` — campaigns; `?relevant_only=true` restricts to those correlated to the caller's tenant.
- `GET /threat-intel/campaigns/{id}` — full campaign.
- `GET /threat-intel/indicators?indicator_type=...&source=...` — IOCs.
- `GET /threat-intel/vulnerabilities?kev_only=true` — CVEs, optionally restricted to CISA KEV.
- `GET /threat-intel/correlations?asset_id=...` — tenant-scoped correlation hits.
- `GET /threat-intel/exposure/campaigns` — per-tenant campaign exposure summary (Threat Exposure dashboard).

Required permissions: `SecurityAdmin`, `SOCAnalyst`, `CloudArchitect`, `Auditor`, `GlobalAdmin`.

### 2.5 Compliance

Per-tenant posture rollups for one framework + per-control drill-down.

Endpoints:

- `GET /compliance/frameworks` — list supported frameworks.
- `GET /compliance/frameworks/{f}/posture?version=latest` — overall posture summary for one framework.
- `GET /compliance/frameworks/{f}/controls?status=...` — per-control state list.
- `GET /compliance/frameworks/{f}/controls/{cid}` — single control state with evidence finding ids.

Required permissions: `Compliance`, `SecurityAdmin`, `Auditor`, `CloudArchitect`, `GlobalAdmin`.

### 2.6 Report

Artifacts produced by `services/reporting`: executive PDF, technical PDF, audit-evidence ZIP, board PPTX, CSV, JSON.

Status lifecycle: `requested → queued → rendering → ready | failed | expired`.

Endpoints:

- `GET /reports?type=...` — list reports.
- `GET /reports/{id}` — single report; `blob_uri` is a signed SAS URL when `status == ready`.
- `POST /reports` — request a new report; `202 Accepted` with a `queued` report.

Required permissions vary by report type; auditors can request `audit_evidence_zip` only, executives can request `executive_pdf` only.

---

## 3. Auth & RBAC

- All `/api/v1/*` (except `/health`) requires a bearer JWT issued by Entra ID for the audience `api://azurelens-api`.
- The token's `tid` claim selects the AzureLens tenant scope.
- App roles ⇒ AzureLens roles (`GlobalAdmin`, `SecurityAdmin`, `Compliance`, `CloudArchitect`, `SOCAnalyst`, `ITManager`, `Auditor`, `ExecViewer`).
- Fine-grained scopes (per-framework, per-subscription) layered on top in Phase 6.

Full matrix: `docs/SECURITY_MODEL.md` § 4.

---

## 4. Cross-Cutting Conventions

- **Pagination**: `?cursor=&limit=` ; response `page.next_cursor`, optional `page.total_estimate`.
- **Errors**: RFC 7807 *Problem Details* envelope with stable `code`, `correlation_id`. No internal detail leakage.
- **Idempotency**: `Idempotency-Key` header on write endpoints.
- **Tracing**: W3C `traceparent` propagated end-to-end.
- **Tenant scope**: enforced at every layer; cross-tenant requests return `404`, not `403`.
- **Reference data versions**: optional `?version=` parameter; resolved to "latest" when omitted, returned in body.

See `packages/contracts/openapi-contract-notes.md` for the normative rules.

---

## 5. Stability & Versioning

- **Path versioning** (`/api/v1`).
- Models carry `schema_version`.
- Additive changes within a major; breaking changes require `/api/v2`.
- Generated OpenAPI snapshot committed under `packages/contracts/openapi/` in Phase 1; breaking-change detection runs in CI.

---

## 6. Mock Responses (current state)

This branch ships placeholder routers that return deterministic mocks:

- One tenant: `00000000-0000-0000-0000-000000000001`, "Contoso Demo".
- One asset: `sha256:placeholder-asset-1`, an Azure VM with public RDP.
- One finding: `aaaaaaaa-...`, "RDP exposed to the public internet", severity `high`, MITRE `T1133`+`T1078`.
- One campaign: "Akira ransomware — RDP brute-force wave".
- One CVE: `CVE-2024-00000` (KEV-flagged placeholder).
- One correlation: links the campaign to the finding via `technique_to_finding`.
- One report: an executive PDF marked `ready`.

These exist so the frontend, partner integrators, and contract test suites can integrate against a stable shape today.

---

## 7. Roadmap of API Expansion

| Phase | Adds |
|---|---|
| 1 | Real persistence, auth, OBO, tenant resolution, `/scans`, `/scores`, `/admin/*`, `/webhooks/*` |
| 2 | TI correlation depth, `/threat-intel/exposure/*` real data, campaign briefings |
| 3 | Framework expansion (NIST 800-53, ISO, SOC 2, GDPR, ZT, WAF, M365 baseline) |
| 4 | Device/Defender/Purview endpoints; Remediation Center |
| 5 | `/copilot/messages` streaming + RAG citations |
| 6 | Fine-grained RBAC, tenant offboarding evidence |
| 7 | GA: stable v1, snapshot publishing, SDK generation |
| 8+ | Enterprise: custom roles, multi-region routing, sovereign variants |

---

## 8. Related Docs

- `docs/DATA_MODEL.md` — entity model behind the API.
- `docs/SCHEMA_DESIGN.md` — persistence-side data model.
- `docs/ARCHITECTURE.md` — system architecture.
- `docs/SECURITY_MODEL.md` — identity, RBAC, secrets, data protection.
- `packages/contracts/` — cross-language contract artifacts.
