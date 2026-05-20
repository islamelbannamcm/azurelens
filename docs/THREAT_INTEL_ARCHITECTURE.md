# AzureLens — Threat Intelligence Architecture

How AzureLens ingests, normalizes, deduplicates, and isolates live threat intelligence from a heterogeneous set of public, community, commercial, and customer-private feeds. This document covers the **connector model**, **ingestion lifecycle**, **STIX / TAXII alignment**, **source trust & freshness**, **deduplication**, **API-key handling**, **tenant isolation**, **observability**, and how this engine plugs into the correlator described in `docs/CORRELATION_ENGINE.md`.

> Foundation note: Phase 4 introduces the contracts and skeletons. No external feed calls happen yet. See `docs/ROADMAP.md`.

---

## 1. Why a connector model

Each TI source has its own API surface, authentication scheme, freshness, throttle profile, and trust posture:

| Source | Modality |
|---|---|
| Microsoft Defender TI | Graph + dedicated MDTI API, Azure AD auth, STIX-shaped |
| Microsoft Sentinel TI | TAXII 2.1 over the customer workspace |
| CISA KEV | Public JSON catalog |
| MITRE ATT&CK | Public STIX 2.1 bundle |
| MISP | PyMISP / REST, API key |
| OpenCTI | GraphQL, bearer token |
| AlienVault OTX | REST, API key |
| abuse.ch | URLhaus / MalwareBazaar / ThreatFox REST, optional Auth-Key |
| VirusTotal | REST, paid API key, on-demand only |
| GHSA | GitHub GraphQL, fine-grained PAT |
| NVD | JSON 2.0 feed, optional API key |

Encoding each as an independently versioned **connector** lets us add or remove sources, override per-tenant trust, and ship community / partner connectors without touching the orchestrator.

---

## 2. Module map

```
services/threat-intel/threat_intel/
├── __init__.py          public re-exports
├── contracts.py         Pydantic v2 wire shapes (metadata, request, result, normalized intel)
├── context.py           IngestionContext + FeedCursor + CredentialMode
├── errors.py            TIError hierarchy
├── base.py              TIConnector abstract base class
├── registry.py          ConnectorRegistry + default_registry singleton
├── normalizer.py        Raw → normalized intel conversion
├── correlator.py        TI ⨝ tenant posture per-dimension correlation passes
└── connectors/
    ├── __init__.py                  (side-effect imports for self-registration)
    ├── microsoft_defender_ti.py
    ├── sentinel_ti.py
    ├── cisa_kev.py
    ├── mitre_attack.py
    ├── misp.py
    ├── opencti.py
    ├── alienvault_otx.py
    ├── abuse_ch.py
    ├── github_advisories.py
    ├── nvd.py
    └── virustotal.py
```

---

## 3. Ingestion lifecycle

```
schedule (timer fn) or on-demand
        │
        ▼
ConnectorRegistry.filter(source=..., capability=..., freshness=...)
        │
        ▼ per connector
IngestionOrchestrator.run(IngestionRequest)
        │
        ▼ per connector
build IngestionContext (destination_scope, correlation_id, cursor, deadline)
        │
        ▼
connector.fetch(ctx)  ── under timeout + retry + circuit breaker (Phase 2)
        │
        ├──► RawIntelItem(s)         (when payload is vendor-format)
        │           │
        │           ▼
        │      Normalizer.normalize_batch(raws)
        │           │
        │           ▼
        └──► NormalizedIntelBase(s)  (Indicator | Campaign | Vulnerability | ...)
                    │
                    ▼
        evidence to ADLS Gen2 (immutable, CMK) ─── orchestrator helper
                    │
                    ▼
        dedupe + merge against existing corpus (per-id sha256 of canonical form)
                    │
                    ▼
        Cosmos DB upsert (ti_* containers, partition = destination_scope)
                    │
                    ▼
        index searchable fields → Azure AI Search
                    │
                    ▼
        emit ti.indicator.normalized / ti.feed.pulled events → correlation worker
```

Observable phases (one IngestionResult per connector run):

1. **Registration** — at process start, each connector module calls `default_registry.register(...)`. Idempotent for the same class object; conflicting ids raise `TIConfigError`.
2. **Resolution** — `ConnectorRegistry.filter(...)` selects connectors by source + capability + freshness tier.
3. **Context build** — `IngestionContext` carries destination scope, cursor, deadline, max_items, page_size, and (in Phase 2) a credential cache key resolved through Managed Identity → Key Vault.
4. **Fetch** — `connector.fetch(ctx)` returns an `IngestionResult` with raw items and/or normalized objects plus a `next_cursor_payload` for resumption.
5. **Normalize** — `Normalizer` converts each `raw_format` (`stix2.1`, `misp_event`, `kev_row`, `nvd_v2`, `ghsa_v1`, `otx_pulse`, `abuse_ch_v1`, `vendor_json`) into the platform's normalized model.
6. **Dedupe / merge** — canonical-form sha256 keyed; when multiple sources report the same id, trust scores are merged using a weighted average; per-source provenance preserved in `sources[]`.
7. **Persist + index** — Cosmos upsert + AI Search index update.
8. **Emit** — `ti.feed.pulled` and `ti.indicator.normalized` events trigger the correlator (see `docs/CORRELATION_ENGINE.md`).

---

## 4. STIX / TAXII alignment

We model all normalized intel as STIX 2.1 SDOs (Indicator, Campaign, ThreatActor, Malware, Tool, Vulnerability, AttackPattern, Mitigation) joined by STIX Relationships. This means:

- Sources that already speak STIX (MITRE, Sentinel TAXII, OpenCTI) skip a translation step.
- Sources that don't (KEV rows, MISP events, OTX pulses, abuse.ch JSON, NVD JSON, GHSA GraphQL) translate via a per-format handler in `Normalizer`.
- Cross-source joins use STIX ids (e.g. an `attack-pattern` from MITRE referenced by Indicators from MISP and Campaigns from Defender TI).

We do not implement the entire STIX 2.1 surface — Marking-Definitions, Identity, Course-of-Action (beyond mitigations), Observed-Data, Notes, Sightings, Opinions, and Reports are deferred until a concrete consumer exists.

TAXII 2.1 enters the picture only as a *transport* — for Sentinel TI and any partner-provided TAXII collection a customer wires in. We don't expose a TAXII server ourselves in Phase 4; that's a Phase 9 marketplace consideration.

---

## 5. Source trust & freshness

Each connector declares a `FreshnessSLA(tier, max_staleness_minutes)`:

| Tier | Default cadence | Typical sources |
|---|---|---|
| `realtime` | streaming push (webhook) | rare; reserved for partner pushes |
| `hourly` | every 60 min | Defender TI, Sentinel TI, MISP, OpenCTI, OTX, abuse.ch |
| `six_hourly` | every 6 h | KEV, NVD, GHSA |
| `daily` | every 24 h | MITRE ATT&CK |
| `weekly` | every 7 d | slow-moving reference packs |
| `on_demand` | by lookup request | VirusTotal |

Freshness breaches raise an SLO incident. The connector's status switches to `degraded` until the next successful run.

Per-source **trust score** ∈ [0, 1] is set at the connector level and overridable per tenant. When the same intel object is reported by N sources, the merged trust is a weighted average. Anomaly detection on indicator-volume spikes guards against poisoned feeds.

---

## 6. Deduplication

Three layers, top to bottom:

1. **Id-level**: every normalized object has a source-qualified id `<source>::<external_id>`. Re-ingesting the same id is a no-op for the source it came from.
2. **Canonical-form sha256**: for each object type, the normalizer computes a sha256 over the canonical form (sorted keys, normalized casing, stripped whitespace). Two different sources reporting the same content collapse into a single row with `sources[]` merged.
3. **Equivalence**: domain ↔ URL ↔ IP and CVE ↔ GHSA pairs are linked via Relationship rows so the correlator can match either side without losing provenance.

---

## 7. API-key handling

> **Hard rule: no secret ever lives in code, in environment variables on disk, or in any committed file.**

- Every connector that needs credentials declares them in `metadata.required_credentials` as `RequiredCredential(mode=..., secret_ref="kv://...")`.
- The orchestrator resolves the actual secret at fetch time via **Managed Identity → Azure Key Vault** and hands the connector an opaque credential provider bound to `ctx.credential_cache_key`. Connectors do not see the raw value.
- Credentials are scoped narrowly: each connector has its own Key Vault item; rotation is per-connector with overlap windows.
- Optional credentials (`optional=True`) allow graceful degradation — the connector may run with lower rate limits or fewer endpoints.

See `docs/SECURITY_MODEL.md` § 5.

---

## 8. Tenant isolation

Most TI lives in the **shared corpus** (`tenant_scope = "shared"`) — KEV, MITRE, Defender TI, NVD, GHSA, etc. are intentionally cross-tenant; they're public-or-shared signal.

A few categories *must* be tenant-private:

| Category | Origin |
|---|---|
| Sentinel TI indicators a customer's SOC maintains | per-tenant push |
| Tenant-private MISP feeds (when a customer brings their own MISP key) | per-tenant API key |
| Customer-curated allowlists / blocklists | per-tenant UI |
| Per-tenant trust overrides | per-tenant config |

Enforcement:

- `IngestionContext.destination_scope` is set by the orchestrator at request time. For tenant-private feeds, `destination_scope = str(tenant_id)`.
- Every normalized object carries `tenant_scope`. The orchestrator validates `obj.tenant_scope == ctx.destination_scope`; mismatches raise `TIIsolationError` (P0) and the offending rows are dropped.
- Cosmos partitioning uses `tenant_scope` as the partition key, so a tenant query never reaches another tenant's partition.
- AI Search filters are mandatory: `filter=tenant_scope eq '<id>' or tenant_scope eq 'shared'`.

Cross-tenant **VirusTotal** lookups (and any future public-source lookups) MUST strip tenant-identifying data before submission — see `connectors/virustotal.py` § Privacy notes. Default is hash-only.

---

## 9. Observability

Around each connector run we emit:

- **OpenTelemetry span** `threat_intel.connector.fetch` with attributes:
  - `azurelens.connector_id`, `azurelens.connector_version`, `azurelens.source`,
  - `azurelens.destination_scope` (hashed for non-shared),
  - `azurelens.correlation_id`,
  - `azurelens.cursor.since` / `etag`.
- **Structured logs** with the same attributes + a result summary (`raw_items`, `indicators`, `campaigns`, `vulnerabilities`, `attack_patterns`, `relationships`, `errors_count`).
- **Metrics** (OTel → Azure Monitor):
  - `ti_connector_duration_seconds{connector_id,status}`
  - `ti_connector_objects_total{connector_id,object_type}`
  - `ti_connector_errors_total{connector_id,code,permanent}`
  - `ti_connector_freshness_minutes{connector_id}` (compared to SLA)
  - `ti_corpus_size{object_type,tenant_scope}` (gauge)
  - `ti_corpus_dedup_ratio{connector_id}`
- **SLOs**:
  - TI freshness P95 ≤ `max_staleness_minutes` declared by the connector.
  - Ingestion success rate ≥ 99% per connector per 30 days.
  - Dedup overhead < 200 ms P95 per batch of 1k items.

Anomaly detection alarms on:
- Indicator volume spike from any single source (potential poisoning).
- Trust score collapse from a usually-high-trust source.
- Cursor regression (a connector asking for earlier data than the corpus already has).

---

## 10. Error handling

Errors raised inside `connector.fetch()` are caught at the orchestrator boundary and recorded as `TIErrorEntry` rows on the `IngestionResult`:

| Raised by connector | Mapped to | Effect |
|---|---|---|
| `TIRateLimitError` | `PARTIAL` | back off with jitter, honor `retry_after`, retry next window |
| `asyncio.TimeoutError` | `PARTIAL` | back off, retry next window |
| `TITransientError` | retried internally; if surfaced → `PARTIAL` then `FAILED` after N attempts | |
| `TIFeedUnavailableError` | `FAILED` | stop this window, set connector status `degraded`, raise freshness SLO alert |
| `TIAuthError` | `FAILED` | rotate / re-provision secret; pages on-call |
| `TIParseError` | `PARTIAL` | dead-letter the offending raw item; continue the batch |
| `TIQuotaExceededError` | `FAILED` | per-tenant or platform-wide; surface to ops + tenant admin |
| `TIIsolationError` | `FAILED` + P0 incident | drop offending records, page on-call |
| Any other `Exception` | sanitized into `TIError("uncaught connector error: <type>")` → `FAILED` | |

No upstream URL fragments, headers, or response bodies are surfaced to customers. Operator-only audit pipeline captures full context (see `docs/SECURITY_MODEL.md` § 10).

---

## 11. How the corpus feeds downstream services

| Downstream | Consumes | Via |
|---|---|---|
| `services/risk-engine` | KEV / EPSS / campaign-proximity flags | `correlation.hit` events |
| `services/ai-engine` | per-tenant relevant TI (RAG corpus) | AI Search index, filtered to `tenant_scope` |
| `apps/api` | `/api/v1/threat-intel/*` reads | Cosmos read replicas |
| Reporting | campaign-exposure rollups | Cosmos query + cached projections |
| Sentinel (customer-side, optional) | platform-curated indicators | TAXII export (Phase 9) |

The corpus is **read-many, write-few** — write rate is bounded by ingestion cadence; read rate is bounded by user activity. We size Cosmos accordingly (autoscale on read units, modest provisioning on writes).

---

## 12. Roadmap

- **Phase 2** — light up CISA KEV, MITRE ATT&CK, Microsoft Defender TI, Sentinel TI; first correlation passes (CVE→inventory, IOC→telemetry, technique→finding).
- **Phase 3** — MISP, OpenCTI, OTX, abuse.ch, GHSA, NVD; full normalizer handler set; per-source trust tuning.
- **Phase 4** — campaign-to-exposed-controls and malware-family-to-posture correlation; VirusTotal on-demand (opt-in).
- **Phase 5** — AI engine consumes correlation hits for campaign briefings and executive narrative.
- **Phase 9** — partner / community connector contribution model and outbound TAXII server.

See `docs/ROADMAP.md`.
