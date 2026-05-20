# AzureLens — Scanner Architecture

How AzureLens collects, normalizes, and isolates posture/configuration data from a customer tenant. This document describes the **plugin architecture**, **lifecycle**, **tenant isolation**, **permission boundaries**, **scheduling**, **error handling**, **observability**, and **how scanner outputs map to ``Finding`` and ``Asset`` models**.

> Foundation note: Phase 3 introduces the contracts and skeletons only. No Microsoft Graph / Azure / Defender / Sentinel / Intune / Purview calls happen yet. See `docs/ROADMAP.md`.

---

## 1. Why a plugin model

Each Microsoft surface (Azure resources, Entra ID, M365, Intune, Defender, Sentinel, Purview) has a different API surface, throttle profile, permission model, and update cadence. Encoding each as an independently versioned, independently testable **plugin** lets us:

- Roll out a new scanner without changing the orchestrator.
- Disable a misbehaving scanner without restarting the rest.
- Map customer permission state to a concrete list of plugins that will / will not function.
- Ship community / partner scanners later without changing core code.

---

## 2. Module map

```
services/scanner/scanner/
├── __init__.py          public re-exports
├── contracts.py         Pydantic v2 wire shapes
├── context.py           ScanContext dataclass + ScanScope + CredentialMode
├── errors.py            ScannerError hierarchy
├── base.py              ScannerPlugin abstract base class
├── registry.py          PluginRegistry + default_registry singleton
├── orchestrator.py      ScanOrchestrator (resolve → invoke → aggregate)
└── plugins/
    ├── __init__.py                 (side-effect imports that self-register plugins)
    ├── azure_resource_graph.py
    ├── entra_identity.py
    ├── m365_security.py
    ├── intune_device.py
    ├── defender_cloud.py
    ├── sentinel.py
    └── purview.py
```

---

## 3. Plugin lifecycle

```
import time          PluginRegistry.register(MyScanner)         ←─ plugin module
                                       │
                                       ▼
                          ┌───────────────────────────┐
                          │  PluginRegistry (in-proc) │
                          └───────────┬───────────────┘
                                       │  filter(...) by kind/capability/asset/permission
                                       ▼
ScanRequest received  ─►  ScanOrchestrator.run(request)
                                       │
                                       ▼
                          ┌───────────────────────────┐
                          │ resolved: list[Plugin]    │
                          └───────────┬───────────────┘
                                       │  per plugin
                                       ▼
                          ┌───────────────────────────┐
                          │ build ScanContext         │
                          │  (tenant, traceparent,    │
                          │   credential_mode, scope) │
                          └───────────┬───────────────┘
                                       ▼
                          ┌───────────────────────────┐
                          │ plugin.scan(ctx) under    │
                          │ timeout + error contain.  │
                          │ (Phase 1: + retry, circuit│
                          │ breaker, rate limiter,    │
                          │ OTel span)                │
                          └───────────┬───────────────┘
                                       ▼
                          ┌───────────────────────────┐
                          │ ScanResult                │
                          │  - assets[]               │
                          │  - findings[] (RawFinding)│
                          │  - errors[]               │
                          └───────────┬───────────────┘
                                       ▼
                          ┌───────────────────────────┐
                          │ Tenant-isolation validate │  ← P0 invariant
                          └───────────┬───────────────┘
                                       ▼
                                  aggregate
                                       │
                                       ▼
                                ScanSummary
```

The lifecycle has six observable phases:

1. **Registration** — at process start, every imported plugin module calls `default_registry.register(...)`. Idempotent for the same class object; conflicting ids raise `ScannerConfigError`.
2. **Resolution** — `ScanOrchestrator._resolve_plugins` maps `ScanRequest.kinds` to a capability set (`KIND_TO_CAPABILITIES`) and asks the registry for plugins matching by **provider** + **capability**.
3. **Context building** — one `ScanContext` per invocation; immutable; carries tenant identity, correlation id, credential mode, scope, deadline.
4. **Invocation** — `plugin.scan(ctx)` under `asyncio.wait_for`. `ScannerThrottledError` and `asyncio.TimeoutError` → `PARTIAL`. Any other `ScannerError` → `FAILED`. Uncaught exceptions → `FAILED` with a sanitized message.
5. **Isolation validation** — every record on `ScanResult.assets` and `ScanResult.findings` must have `tenant_id == ctx.tenant_id`. Violation raises `TenantIsolationError` (P0).
6. **Aggregation** — `ScanSummary` collects per-plugin status, asset/finding totals, and the full error list. Overall status follows: any `FAILED` with no successes → `FAILED`; any `FAILED` or `PARTIAL` mixed with successes → `PARTIAL`; otherwise `COMPLETED`.

---

## 4. Tenant isolation

The platform-wide multi-tenant invariants (see `docs/SCHEMA_DESIGN.md` § 12) are enforced at every layer; the scanner enforces them at **two** specific points:

### 4.1 Inputs

`ScanContext.tenant_id` is the **only** tenant identity a plugin should ever look at. It is set from the validated `ScanRequest` (which in turn comes from a tenant-scoped API call or a per-tenant Service Bus message). Plugins must not read `tenant_id` from anywhere else.

### 4.2 Outputs

`ScanOrchestrator._validate_tenant_isolation` rejects any `ScanResult` whose `tenant_id`, asset `tenant_id`, or finding `tenant_id` does not match `ctx.tenant_id`. The raise is converted into a `TenantIsolationError` and surfaced as a P0 incident.

### 4.3 Scope (defense in depth)

`ScanScope` narrows what a plugin enumerates (e.g. selected subscriptions, target asset, user batch). Even if a plugin scope is wider than intended, the output validator still catches cross-tenant leakage — the two together form defense in depth.

---

## 5. Permission boundaries

Every plugin advertises a `required_permissions: list[RequiredPermission]` describing exactly what consent the customer's admin must grant for the plugin to function.

`PermissionGrantType` values:

| Value | Where granted |
|---|---|
| `ms_graph_application` | Customer Entra ID admin consents application-level Graph scope |
| `ms_graph_delegated` | User-initiated reads using OBO |
| `azure_rbac` | Role assignment at root management group / selected subscriptions |
| `defender_api` | Defender XDR / Microsoft 365 Defender (Security API) |
| `sentinel_rbac` | Sentinel RBAC on the Log Analytics workspace |
| `purview_rbac` | Purview RBAC on the Purview account |

Each declared permission carries:

- `name` — the permission identifier (e.g. `Directory.Read.All`, `Reader`).
- `optional` — `True` if the plugin can degrade gracefully without it.
- `notes` — short rationale surfaced to the customer admin in the consent UI.

The orchestrator (Phase 1) will resolve the customer's actual consent state at scan time. If a required permission is missing, the plugin is skipped and a `ScannerPermissionError` is recorded as a `ScanErrorEntry` so the consent UI can prompt the admin to re-consent.

**Principle of least privilege** is enforced top-down: scanners are read-only, and the small remediation surface (Phase 4+) uses a *separate* service principal whose write permissions are scoped narrowly via Azure Policy. See `docs/SECURITY_MODEL.md` § 6.

---

## 6. Scheduling (planned)

Phase 1 wires the orchestrator into the Azure backbone described in `docs/ARCHITECTURE.md` § 6:

| Trigger | Source | Notes |
|---|---|---|
| Bootstrap scan | `tenant.lifecycle` event on onboarding | Full scan of all kinds; produces the first executive report |
| Scheduled scan | Azure Functions Timer trigger (per tenant) | Daily full + 15-60 min incremental |
| Incremental scan | Graph delta queries + ARG diffs | Picks up changes only |
| On-demand scan | `POST /api/v1/scans` → Service Bus `scan.requested` | User-initiated |
| Targeted scan | `POST /api/v1/scans` with `target_asset_id` | Re-evaluate one asset after remediation |

Fan-out is implemented as Durable Functions orchestrators (subscription / user-batch / device-batch), with the in-process `ScanOrchestrator` running on each fan-out leaf. This document's orchestrator is the leaf-level one; the saga-level orchestration sits above it.

Per-tenant **rate limiting** is enforced by:

- a per-tenant + per-Graph-endpoint token bucket (planned helper in `packages/connectors`),
- explicit honoring of `Retry-After`,
- exponential backoff + jitter on transient errors,
- circuit breakers per `(plugin, endpoint)` so one degraded endpoint doesn't stall a whole scan.

---

## 7. Error handling

Errors are typed (see `scanner/errors.py`) and converted to `ScanErrorEntry` records on the `ScanResult`. The orchestrator's containment policy:

| Raised by plugin | Result status | `permanent` |
|---|---|---|
| `ScannerThrottledError` | `PARTIAL` | `False` |
| `asyncio.TimeoutError` | `PARTIAL` | `False` |
| `ScannerTransientError` | retried internally by the plugin; if surfaced → `FAILED` | `True` |
| `ScannerPermissionError` | `FAILED` (and surfaced to consent UI) | `True` |
| `ScannerAuthError` / `ScannerConfigError` / `ScannerPermanentError` | `FAILED` | `True` |
| `TenantIsolationError` | bubbles up; orchestrator emits a P0 incident | `True` |
| Any other `Exception` | sanitized into `ScannerError("uncaught plugin error: <type>")` → `FAILED` | `True` |

No stack traces, no internal hostnames, no API URLs are surfaced to customers — the operator-facing audit pipeline captures the full context (see `docs/SECURITY_MODEL.md` § 10).

---

## 8. Observability

Phase 1 wires the following telemetry around each plugin invocation:

- **OpenTelemetry span** `scanner.plugin.scan` with attributes:
  - `azurelens.tenant_id` (hashed in low-trust environments), `azurelens.correlation_id`, `azurelens.plugin_id`, `azurelens.plugin_version`, `azurelens.scan_kind`, `azurelens.trigger_type`.
- **Structured logs** (structlog → Application Insights) with the same attributes, redacted PII, and a result summary (`assets_emitted`, `findings_emitted`, `errors_count`).
- **Metrics** (OTel → Azure Monitor):
  - `scanner_plugin_duration_seconds{plugin_id,status}`
  - `scanner_plugin_findings_total{plugin_id,severity}`
  - `scanner_plugin_assets_total{plugin_id,asset_kind}`
  - `scanner_plugin_errors_total{plugin_id,code,permanent}`
  - `scanner_plugin_throttled_total{plugin_id,endpoint}`
- **SLOs**:
  - Bootstrap scan completion ≤ 30 min P95 on a 10k-identity / 5k-resource tenant.
  - Incremental scan ≤ 5 min P95.
  - TI ingestion freshness ≤ 90 min P95 (driven by the TI service, not the scanner, but consumed by correlation hits).

---

## 9. Output mapping — Scanner ↔ API/Persistence models

Scanner outputs are deliberately **lighter** than the persisted API shapes; the compliance and risk engines enrich them downstream.

| Scanner output | Phase 1 destination | API/persistence model |
|---|---|---|
| `ScanAssetSnapshot` | Service Bus `asset.upserted` → asset upsert worker → Cosmos `assets` container | `app.models.asset.Asset` |
| `ScanFinding` | Service Bus `finding.raw` → compliance engine → SQL `findings` table | `app.models.finding.RawFinding` → `app.models.finding.Finding` |
| `ScanErrorEntry` | Audit log + admin diagnostics; counts feed Sentinel analytics rules | n/a (operational) |
| `ScanSummary` | SQL `scan_summary` row + Service Bus `scan.completed` | `app.models.scoring.ScanSummary` |

### 9.1 ScanAssetSnapshot → Asset

```
ScanAssetSnapshot                      Asset (Cosmos)
─────────────────                      ──────────────
tenant_id        ───────────────────►  tenant_id          (partition key)
asset_id         ───────────────────►  id
asset_uri        ───────────────────►  asset_uri
asset_kind  (string from AssetKind) ►  asset_kind
provider         ───────────────────►  provider
display_name     ───────────────────►  display_name
properties       ───────────────────►  properties         (merged with kind-specific shape)
discovered_at    ───────────────────►  discovered_at / last_seen_at
source           ───────────────────►  source
(no field)                             criticality        (defaulted; set by tenant policy)
(no field)                             exposure           (computed downstream from properties)
(no field)                             relationships      (built by the asset-edge worker)
```

### 9.2 ScanFinding → RawFinding → Finding

`ScanFinding` is wire-compatible with `app.models.finding.RawFinding`:

```
ScanFinding                            RawFinding
───────────                            ──────────
tenant_id                              tenant_id
correlation_id                         correlation_id
asset_id                               asset_id
finding_type                           finding_type
title / description                    title / description
severity_hint                          severity_hint
mitre_techniques                       mitre_techniques
evidence_blob_uri                      evidence_blob_uri
detected_at                            detected_at
source_scanner                         source_scanner
metadata                               metadata
schema_version                         schema_version
```

The compliance engine then enriches `RawFinding` into a persisted `Finding` by adding:

- `framework_mappings` (multi-framework crosswalk),
- `mitre_tactics` (derived from techniques),
- `exploitability` (joined from TI / KEV / EPSS),
- `risk_score` (computed by the risk engine),
- `campaign_links` (joined from `services/threat-intel` correlations),
- `remediation` (matched by `(finding_type, technique, framework_control)`).

---

## 10. Plugin authoring checklist (for future contributors)

Before merging a new plugin:

- [ ] Class-level `metadata: ScannerMetadata` with stable `id`, `version`, full capability + asset-kind + permission lists, and a clear `description`.
- [ ] `async def scan(self, ctx)` is the only public method; idempotent; cancellation-aware.
- [ ] No secrets read directly; tokens come from the orchestrator's provider.
- [ ] No global mutable state across calls.
- [ ] All emitted records carry `ctx.tenant_id`.
- [ ] Throttling honored; backoff + jitter; circuit breaker per upstream endpoint.
- [ ] Telemetry: structured logs + OTel span + metric labels match the catalog in § 8.
- [ ] Unit tests with recorded responses (no live network in CI).
- [ ] Synthetic cross-tenant test proves the plugin cannot emit for any tenant other than `ctx.tenant_id`.
- [ ] Module top-of-file docstring lists the source APIs and TODO(phase-N) markers.
- [ ] `default_registry.register(MyScanner)` at module bottom.
- [ ] Plugin added to `scanner.plugins.__init__` side-effect imports.
- [ ] Documentation updated in `docs/ARCHITECTURE.md` § 4 and this file's § 9 mapping table if the output shape differs.

---

## 11. Roadmap

- **Phase 1** — wire credentials, retries, telemetry, Service Bus emission; light up the `azure_resource_graph`, `entra_identity`, and `defender_cloud` plugins against real APIs.
- **Phase 2** — light up `sentinel` (TI bridge half) and start feeding `services/threat-intel`.
- **Phase 4** — light up `intune_device`, `purview`, and the alert-posture half of `defender_cloud`; flesh out `m365_security`.
- **Phase 5** — AI engine consumes ScanFindings + scoring for narrative.
- **Phase 6** — tenant-offboarding cascade through the scanner state and per-tenant CMK.
- **Phase 7+** — partner / community plugin contribution model.

See `docs/ROADMAP.md`.
