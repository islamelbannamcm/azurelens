# services/risk-engine

Skeleton for the **Risk Scoring Engine**. No scoring logic implemented yet.

## Purpose

Convert normalized findings + threat-intelligence correlations into:

1. **Per-finding risk scores** (0–100).
2. **Per-domain scores**: identity, Azure exposure, device, threat exposure, M365 compliance.
3. **Per-tenant overall posture score** (0–100) with a banded label (`critical | weak | moderate | strong | excellent`).

These scores drive the executive dashboard, the prioritized remediation backlog, and the AI engine's narrative.

## Scoring Model (planned)

Stateless, deterministic, fully auditable. Inputs:

- `Finding` (severity, evidence, framework tags, MITRE techniques, asset)
- `Asset` (criticality set by tenant; public/internal exposure)
- `CorrelationHit` from `services/threat-intel` (active campaign on this asset)
- `Vulnerability` flags (CISA KEV, EPSS, active exploitation)
- `ScoringPolicy` (tenant-overridable weights — see `docs/SCHEMA_DESIGN.md` § 7.3)

Formula (v1):

```
risk = base_severity
     × exploitability_factor       # active KEV → ×1.5
     × exposure_factor              # public-facing → ×1.3
     × business_impact_factor       # tenant-set asset criticality
     × compliance_weight            # max across mapped frameworks
     × campaign_proximity_factor    # live campaign hits this asset → ×1.4
```

All weights live in a versioned `scoring_policies` document in Cosmos DB; changes are auditable and tenant-overridable.

## Inputs (planned)

- Service Bus topic `finding.normalized` from the compliance engine.
- Service Bus topic `correlation.hit` from the threat-intel engine.
- Optional re-score triggers on policy change.

## Outputs (planned)

- Updates to `findings.risk_score` and `scores_current` (Azure SQL).
- Daily snapshots to `scores_history` for trend analysis.
- Cosmos read model for fast dashboard queries.
- Service Bus event `score.updated` for downstream notification.

## Properties

- **Deterministic**: same inputs ⇒ same outputs; version of policy used is recorded on each finding for auditability.
- **Idempotent**: re-scoring an unchanged finding produces no event/no DB write.
- **Explainable**: every score carries a structured breakdown (per factor + reference to policy version) — surfaced to the AI engine for human-readable summaries.

## Local Development (planned)

```bash
cd services/risk-engine
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m risk_engine.main --once
```

## Status

Skeleton only. Real scoring lands in Phase 1 (baseline) and Phase 2 (campaign / exploitability factors). See `docs/ROADMAP.md`.
