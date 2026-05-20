# AzureLens — Risk Scoring Model

How AzureLens turns findings, asset context, threat-intelligence correlations, compliance signals, and tenant-set business impact into deterministic, bounded, explainable scores. This document covers the **direction convention**, **formulas**, **factors**, **weights**, **policy profiles**, **score bands**, **examples**, **tuning guidance**, **limitations**, and the planned **AI enhancement layer**.

> Foundation note: Phase 5 introduces the formulas and contracts. Real scoring against persisted findings runs in Phase 1 (baseline) and Phase 2 (TI factors). The shapes here are stable and forward-compatible.

---

## 1. Direction convention (read this first)

| Score | Range | Direction |
|---|---|---|
| Per-finding **risk_score** | 0 – 100 | **higher = worse** |
| Per-domain **posture sub-score** | 0 – 100 | **higher = better** |
| Tenant **overall posture** | 0 – 100 | **higher = better** |

The calculator handles the inversion explicitly: `posture = 100 - blended_risk`. This document uses "risk" only for the finding-level number; everywhere else "score" means posture.

---

## 2. Module map

```
services/risk-engine/risk_engine/
├── __init__.py          public re-exports
├── contracts.py         Pydantic v2 inputs / outputs / breakdown / reasons
├── errors.py            exception hierarchy
├── weights.py           WeightProfile + default tables (severity, factors, aggregate)
├── policy.py            5 named ScoringPolicy profiles + registry
├── formulas.py          pure scoring functions (factor + finding + domain + overall)
├── calculator.py        RiskCalculator — the boundary the worker uses
└── explainability.py    deterministic rule-based reason generation
```

---

## 3. Factors

Each factor is centered around **1.0** (except `base_severity`, which is score-points). Per-factor functions live in `formulas.py` and are pure.

| Factor | Type | Range | Drives |
|---|---|---|---|
| `base_severity` | enum → points | 5 – 100 | Severity (INFO → CRITICAL) |
| `exploitability_factor` | multiplier | 0.9 – 1.65 | Exploitability (NONE → ACTIVE), KEV escalation, active-campaign link |
| `exposure_factor` | multiplier | 1.0 – 1.3 | ExposureLevel (INTERNAL / PARTNER / PUBLIC / UNKNOWN) |
| `business_impact_factor` | multiplier | 0.8 – 2.05 | Asset criticality × data classification × regulated-data flag |
| `compliance_weight` | multiplier | 1.0 – 1.6 | Max framework weight in scope × audit-horizon boost |
| `campaign_proximity_factor` | multiplier | 1.0 – 1.8 | TI correlation hit count + KEV + active campaign link |
| `confidence_factor` | multiplier | 0.6 – 1.0 | Producing scanner's confidence (0..100) |
| `detection_coverage_factor` | multiplier | 0.85 – 1.15 | Detection coverage on / around the asset (0..1) |
| `remediation_complexity_factor` | multiplier | 0.95 – 1.10 | Estimated remediation effort |

### Domain-side amplifiers

For per-domain sub-scores, additional small amplifiers apply to capture the requirement's per-domain factors:

| Domain | Amplifier captures |
|---|---|
| `identity` | privileged identity impact, missing MFA, missing PIM, phishing-resistant MFA absent, risky-user level |
| `azure_exposure` | internet-facing, public RDP / SSH, count of high-risk open ports |
| `device` | missing Defender, missing backup on critical assets, missing encryption at rest |
| `m365_compliance` | high control criticality, near-term audit horizon |
| `threat_exposure` | KEV CVE, active campaign link, multi-dimension TI hits |

All amplifiers are bounded (≤ 1.8) so no single dimension can flip the score on its own.

---

## 4. Formulas

### 4.1 Per-finding risk score (higher = worse)

```
risk = clamp_0_100(
    base_severity
  × exploitability_factor
  × exposure_factor
  × business_impact_factor
  × compliance_weight
  × campaign_proximity_factor
  × confidence_factor
  × detection_coverage_factor
  × remediation_complexity_factor
)
```

Each factor function is pure, deterministic, and unit-testable in isolation. The breakdown (`ScoreBreakdown`) records every multiplier *and* the raw unclamped product, so the path from inputs to score is fully auditable.

### 4.2 Per-domain posture sub-score (higher = better)

```
risks_in_domain = [
    clamp_0_100(finding_risk(fi) × domain_amplifier(fi))
    for fi in finding_inputs
]

posture_sub_score = 100 - (0.8 × mean(risks_in_domain) + 0.2 × max(risks_in_domain))
```

- Empty domain → score is **100** (no signal = no penalty).
- The 80/20 mean/worst blend keeps aggregates stable when many findings exist, while still letting a single critical finding move the needle.

### 4.3 Tenant overall posture (higher = better)

```
overall = clamp_0_100(
    sum_over_domains(
        sub_scores[domain] × aggregate_weight[domain]
    )
    / sum(aggregate_weight)
)
```

Missing sub-scores default to **100** — a brand-new tenant on Day 0 starts at 100 and decays as scans land, not the other way around. The aggregate weights MUST sum to 1.0 (validated on `WeightProfile`).

### 4.4 Band classification

Posture-direction bands (from `WeightProfile.band_thresholds`):

| Band | Minimum value |
|---|---|
| `excellent` | 90 |
| `strong` | 75 |
| `moderate` | 60 |
| `weak` | 40 |
| `critical` | 0 |

For finding-direction risk scores, the calculator inverts (`100 - risk`) before classifying, so a finding with risk 70 lands in the worst band (`critical`).

---

## 5. Policy profiles

Five built-in named policies live in `policy.py`; tenants pick one as their default and may register custom variants via `register_policy`.

| Profile | What it boosts | What it dampens |
|---|---|---|
| `default` | balanced | none |
| `executive` | business impact, active campaigns; identity + Azure exposure dominate the overall mix | informational noise; compliance + threat-exposure weights are reduced |
| `compliance_focused` | framework weights (+10%), audit-horizon urgency, compliance-domain weight | none |
| `threat_focused` | exploitability (+10%), KEV / active-campaign boosts, threat-exposure domain weight | none |
| `identity_focused` | identity-relevant framework weights; identity-domain weight (0.45) | other domains |

Each policy is a `ScoringPolicy(id, version, title, description, weights, created_at)` — a `ScoringPolicyRef(policy_id, version)` is stamped on every score so audits can reproduce the calculation against the exact weights used.

---

## 6. Worked examples

### 6.1 *RDP exposed to the public internet on a critical VM*

Inputs:

- severity = HIGH (base 70)
- exploitability = ACTIVE (multiplier 1.5)
- exposure = PUBLIC (×1.3)
- public_rdp_open = True (drives `_azure_exposure_amplifier` ×1.30 at domain level)
- asset.criticality = HIGH → business_impact ≈ 1.31
- compliance: cis_azure + mcsb mapped → compliance_weight ≈ 1.10
- TI: KEV link present, 2 correlation hits → campaign_proximity ≈ 1.10 × kev_boost ≈ 1.27 (capped at 1.40)
- confidence = 95 → confidence_factor ≈ 0.98
- detection_coverage = 0.5 → ≈ 1.00
- remediation_complexity = LOW → 0.98

Raw product ≈ 70 × 1.5 × 1.3 × 1.31 × 1.10 × 1.27 × 0.98 × 1.00 × 0.98 ≈ **190** → **clamped to 100**.

`band` (finding-direction): `critical`. The breakdown records all nine multipliers and the unclamped 190 so the over-saturation is visible during tuning.

### 6.2 *Privileged Global Admin without MFA*

Inputs:

- severity = HIGH (base 70)
- exploitability = NONE → 0.9 (no KEV / active link)
- exposure = INTERNAL (×1.0)
- asset.is_privileged_identity = True, mfa_enabled = False → `_identity_amplifier` 1.2 × 1.25 = 1.5 at the identity-domain level
- business_impact (criticality HIGH) ≈ 1.31
- compliance (zero_trust + nist_csf, audit in 60 days) ≈ 1.10
- confidence 90 → 0.97
- detection 0.7 → 0.96
- remediation MEDIUM → 1.00

Finding-level risk ≈ 70 × 0.9 × 1.0 × 1.31 × 1.10 × 1.0 × 0.97 × 0.96 × 1.00 ≈ **84**.
Identity-domain amplifier 1.5 raises the per-domain contribution before being averaged in.

### 6.3 *Tenant with strong posture except devices*

```
sub_scores = {
    "identity":         88,
    "azure_exposure":   85,
    "device":           42,
    "m365_compliance":  90,
    "threat_exposure":  92,
}

# default aggregate weights
overall = 0.30×88 + 0.25×85 + 0.15×42 + 0.15×90 + 0.15×92 = 80.1
band    = "strong"
```

The explainer surfaces `overall_domain_drag_device` as the dominant reason ("device sub-score is 42; weight 0.15 contributes -8.7 points").

---

## 7. Tuning guidance

1. **Tune one factor at a time.** Because formulas are linear products, changing two factors simultaneously makes attribution hard. The breakdown is your friend.
2. **Keep multipliers bounded.** If you find yourself needing a factor > 2.0, you probably want a domain amplifier, not a base-factor change.
3. **Re-bin only with reason.** Band thresholds are tenant-visible. Move them only when external benchmarks change (CIS major-version bump, MCSB rev).
4. **Run shadow.** Tuning a policy in Phase 1+ deploys side-by-side ("shadow scoring") for at least one scan cycle so you see deltas without changing what users see.
5. **Mind the cap.** A finding's raw unclamped score is preserved in `breakdown.raw_unclamped`. Sustained over-saturation (raw ≫ 100) signals factors compound too aggressively.

---

## 8. Score bands cheat-sheet

| Band | Posture | Finding-direction risk | Operational meaning |
|---|---|---|---|
| `excellent` | 90 – 100 | 0 – 10 | No material action required; maintain |
| `strong` | 75 – 89 | 11 – 25 | Targeted improvements; routine cadence |
| `moderate` | 60 – 74 | 26 – 40 | Prioritized remediation needed within the quarter |
| `weak` | 40 – 59 | 41 – 60 | Active risk management; report to executive |
| `critical` | 0 – 39 | 61 – 100 | Immediate action; pages security on-call |

---

## 9. How the scoring engine maps to the rest of the platform

| Upstream | Provides | Output |
|---|---|---|
| `services/scanner` (Phase 1+) | `RawFinding` envelopes → normalized `Finding` | feeds `FindingScoreInput.severity, asset, ...` |
| `services/threat-intel` (Phase 2) | `CorrelationCandidate`s | feeds `ThreatIntelContext` |
| `services/compliance-engine` (Phase 3) | framework mappings + control criticality + audit horizon | feeds `ComplianceContext` |
| Tenant config (Phase 1) | asset criticality, data classification, regulated-data flag | feeds `BusinessImpactContext` |

| Downstream | Consumes | Surface |
|---|---|---|
| `apps/api` (Phase 2) | `RiskScoreOutput` / `DomainScoreOutput` / `OverallScoreOutput` | `/api/v1/scores/*`, `/api/v1/findings/{id}` (`risk_score`) |
| `services/ai-engine` (Phase 5) | `ExplainabilityReason`s as grounding | executive narrative + finding explanations |
| `services/reporting` (Phase 3) | per-tenant score history | trend dashboards, executive PDFs |
| Power BI Embedded (Phase 3) | score snapshots | dashboards with RLS |

---

## 10. Limitations

- **Linearity.** The product-of-factors model is intentional (predictable, auditable, tunable). It will not capture every real-world non-linear interaction — *e.g.* the combinatorial blow-up of "privileged identity + no MFA + active phishing campaign + audit next week". The domain amplifiers + the campaign-proximity factor exist to approximate this.
- **No learned weights.** All weights are hand-curated. We deliberately *don't* train weights on historical incidents in Phase 5 — that's a Phase 8+ research workstream behind explicit feature flags, and only as a *suggestion overlay* on top of deterministic scoring.
- **Single tenant at a time.** Scoring is per-tenant. Cross-tenant insights (e.g. "industry-wide TI exposure trends") are out of scope here.
- **No time series inside the calculator.** The calculator is point-in-time. Trends are computed downstream from `scores_history`.
- **Confidence ≠ probability.** `confidence_factor` reflects scanner confidence, not the probability of exploitation; the latter, where available (EPSS), feeds `exploitability_factor` separately.

---

## 11. Future AI enhancement plan

These additions are explicitly *out of scope* for Phase 5 — listed here so the contracts above accommodate them without churn.

| Phase | AI addition | Where it lands |
|---|---|---|
| 5 | LLM **summarization** of `ExplainabilityReason` chains into executive-grade narrative | `services/ai-engine` consumes `RiskScoreOutput.reasons[]` as grounding. AI never invents new reasons. |
| 6 | LLM **prioritization tie-break** for findings that score within ε of each other; bounded by allowlist of remediation actions | suggestion overlay on `GET /api/v1/findings` |
| 7 | **Calibration model** on historical incidents to *suggest* (never overwrite) tweaks to per-factor weights per tenant | reviewed by humans before policy version bump |
| 8 | **Predictive risk**: short-horizon forecast of which controls will degrade next given current campaign drift | new Cosmos container; surfaced via `/api/v1/scores/forecast` |
| 8 | **Counterfactual narrative**: "if you fix X, your identity score lifts by Y" | derived deterministically from formulas; AI only renders the prose |

The two architectural invariants are:

1. **Deterministic scoring stays the source of truth.** AI augments narrative + prioritization tie-breaks; it does not produce or replace numbers.
2. **Every AI augmentation cites its grounding** (the structured breakdown + reasons + finding ids). No groundless text reaches the customer.

See `docs/ARCHITECTURE.md` § 8 and `docs/SECURITY_MODEL.md` § 11.
