# services/scanner

Skeleton for the **Scanning Engine** worker service. No scanner logic implemented yet.

## Purpose

Continuously enumerate and analyze a customer's Azure tenant, Microsoft 365 environment, identities, devices, configurations, and policies. Produces normalized **raw findings** to the async backbone, where the compliance, risk, and AI engines pick them up.

This top-level `scanner` service is a unifying skeleton; per `docs/ARCHITECTURE.md` § 3 the production layout will split into independently deployable workers — kept here as logical scopes inside one package for the foundation phase.

## Future Responsibilities

| Scope | Sources | Outputs |
|---|---|---|
| `scanner.azure` | Azure Resource Graph (KQL), ARM REST, Defender for Cloud, Azure Policy | Asset graph + posture findings for IaaS/PaaS |
| `scanner.m365` | Microsoft Graph (Entra ID, Conditional Access, EXO, SPO, Teams, OD), OAuth grants | Identity, collaboration, app-consent findings |
| `scanner.intune` | Graph Intune endpoints (devices, compliance, configuration, endpoint security) | Device & MDM posture |
| `scanner.defender` | Microsoft Defender XDR (Advanced Hunting, alerts, incidents), Defender for Cloud | Alerts + Secure Score deltas |
| `scanner.purview` | Purview REST, M365 DLP, sensitivity labels | Data-governance findings |

### Behaviors common to all scanner scopes

- **Idempotent**: re-running a scan against unchanged state produces zero new findings.
- **Resumable**: Durable Functions / saga checkpoints; partial scans clearly marked as such.
- **Rate-aware**: per-endpoint token-bucket; honors `Retry-After`; exponential backoff with jitter.
- **Tenant-isolated**: every emitted event carries `tenant_id`; cross-tenant emission is impossible.
- **Evidence-first**: raw API responses (sanitized) persisted to ADLS Gen2 before normalized findings emit.
- **Read-only by default**: a separate, opt-in remediation service principal handles writes.

## Inputs (planned)

- Trigger from Service Bus topic `scan.requested`.
- Tenant connector config from Cosmos DB (`tenant_connectors`).
- Reference framework packs from `packages/frameworks` (later phase).

## Outputs (planned)

- Service Bus topic `finding.raw` — normalized `RawFinding` envelopes.
- ADLS Gen2 blobs at `tenants/{tenant_id}/findings/{finding_id}/{eval_ts}.json`.
- App Insights traces with W3C `traceparent` propagation.

## Local Development (planned)

```bash
cd services/scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m scanner.main --once    # one-shot dry run (Phase 1+)
```

No Microsoft API credentials are required for the skeleton — there are no Microsoft calls in this branch. Local secrets, when introduced, will go in `.env` (gitignored) and resolve through Managed Identity in cloud environments. See `docs/SECURITY_MODEL.md`.

## Status

Skeleton only. Real Azure / Graph / Defender / Sentinel / Intune / Purview calls land in Phases 1 and 4 per `docs/ROADMAP.md`.
