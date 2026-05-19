# services/threat-intel

Skeleton for the **Live Threat Intelligence Engine**. No TI ingestion implemented yet.

## Purpose

Continuously ingest, normalize, deduplicate, and enrich threat intelligence, then **correlate** it against each customer tenant's posture to map active attack campaigns, IOCs, TTPs, malware, and CVEs to the customer's real environment.

This drives the platform's headline capability: *"Which active, real-world attack campaigns can hit us today?"*

## Future Responsibilities

### Ingestion (`threat_intel.ingest`)

Pulls from (see `docs/ARCHITECTURE.md` § 7 and `docs/AZURE_SERVICES.md`):

- Microsoft Defender Threat Intelligence
- Microsoft Sentinel Threat Intelligence (TAXII 2.1 / STIX 2.1)
- CISA Known Exploited Vulnerabilities (KEV) catalog
- MITRE ATT&CK (STIX 2.1)
- MISP threat-intel feeds
- OpenCTI
- AlienVault OTX
- abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- VirusTotal (optional, on-demand)
- GitHub Security Advisories (GHSA)
- CVE / NVD JSON feeds

Each source has its own connector with: cursor/ETag handling, per-source trust score, freshness SLO, anomaly-on-volume detection, dead-letter on parse failure.

### Normalization (`threat_intel.normalize`)

Maps every source format to the internal STIX-aligned model:
`Indicator`, `Campaign`, `ThreatActor`, `Malware`, `Tool`, `Vulnerability`, `AttackPattern`, `Mitigation`, plus `Relationship` edges. Schema in `docs/SCHEMA_DESIGN.md` § 5.

### Correlation (`threat_intel.correlate`)

Joins the TI graph against the customer's asset graph along multiple dimensions:

- CVE ⨝ inventory (image / package / OS)
- IP / domain / URL ⨝ NSG flow logs, App Gateway logs, firewall logs
- TTP ⨝ posture finding (missing control)
- Campaign target sector ⨝ customer industry profile
- Affected platform ⨝ customer tech stack

Produces `CorrelationHit` records that boost the risk score and feed the AI engine's campaign-briefing prompts.

## Inputs (planned)

- Timer triggers (per-source cadence).
- `tenant.lifecycle` events (to (re)build per-tenant correlations on onboarding).
- `finding.normalized` events (to re-evaluate correlations when posture changes).

## Outputs (planned)

- Cosmos DB containers `ti_indicators`, `ti_campaigns`, `ti_vulnerabilities`, `ti_threat_actors`, `ti_malware`, `ti_tools`, `ti_attack_patterns`, `ti_relationships`, `ti_correlations`.
- Azure AI Search index for TI corpus (RAG retrieval).
- Service Bus event `correlation.hit` for downstream scoring + notification.

## Privacy & Trust

- **Hash-only lookups** for public sources that may log queries (e.g., VirusTotal); never send customer-identifying data to public TI sources.
- **Per-source trust scoring** (configurable per tenant); anomaly detection on volume spikes prevents poisoned feeds from skewing scores.
- **Sandboxed parsing** + size caps + AV scan on raw blobs in ADLS.

## Local Development (planned)

```bash
cd services/threat-intel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m threat_intel.main --once
```

No external network calls in this skeleton. No API keys required.

## Status

Skeleton only. Real ingestion + correlation arrive in Phase 2 (`docs/ROADMAP.md`).
