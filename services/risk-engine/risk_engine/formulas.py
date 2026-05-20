"""Deterministic, bounded, explainable scoring formulas.

Every function in this module is a **pure function** of its arguments:
no I/O, no time-dependence (except where ``now`` is passed in explicitly),
no global state. This is what makes the model auditable and trivially
testable with property-based tests in Phase 1+.

Conventions
-----------
* ``base_severity_score`` is in score-points (0..100).
* Every other factor is a unit-less multiplier centered around 1.0.
* ``compute_finding_risk_score`` returns a finding-direction score
  (higher = worse) in [0, 100].
* The per-domain and overall aggregators return posture-direction scores
  (higher = better) in [0, 100].

Performance: every function in this module is O(1) per call (or O(N) over
its input list); no formula here scales worse than linearly in the
number of findings it aggregates.
"""

from __future__ import annotations

from collections.abc import Iterable
from math import isfinite
from uuid import UUID

from risk_engine.contracts import (
    AssetContext,
    BusinessImpactContext,
    ComplianceContext,
    Criticality,
    DataClassification,
    DomainScoreInput,
    Exploitability,
    ExposureLevel,
    FindingScoreInput,
    OverallScoreInput,
    RemediationComplexity,
    ScoreBreakdown,
    ScoreKind,
    Severity,
    ThreatIntelContext,
)
from risk_engine.weights import WeightProfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def clamp(value: float, *, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp ``value`` to ``[lo, hi]``. NaN / inf collapse to ``lo``."""
    if not isfinite(value):
        return lo
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def round_score(value: float, *, ndigits: int = 2) -> float:
    """Round a score to N digits; keeps test fixtures stable."""
    return round(value, ndigits)


def to_int_score(value: float) -> int:
    """Convert a [0, 100] float to an int (banker's rounding -> half-up)."""
    return max(0, min(100, int(round(clamp(value)))))


# ---------------------------------------------------------------------------
# Single-factor functions
# ---------------------------------------------------------------------------


def base_severity_score(severity: Severity, weights: WeightProfile) -> float:
    """Return the base severity in score-points (0..100)."""
    return float(weights.severity_base.get(severity, weights.severity_base[Severity.MEDIUM]))


def exploitability_factor(
    exploitability: Exploitability,
    *,
    has_kev_cve: bool,
    has_active_campaign_link: bool,
    weights: WeightProfile,
) -> float:
    """Multiplier driven by how exploitable the issue is.

    KEV escalates anything < ACTIVE to ACTIVE; an active campaign link
    on top of that adds the active-link boost. The result is bounded
    by the largest table entry.
    """
    if has_kev_cve and exploitability is not Exploitability.ACTIVE:
        exploitability = Exploitability.ACTIVE
    factor = weights.exploitability.get(exploitability, 1.0)
    if has_active_campaign_link:
        factor *= weights.campaign_active_link_boost
    upper = max(weights.exploitability.values()) * weights.campaign_active_link_boost
    return min(factor, upper)


def exposure_factor(exposure: ExposureLevel, weights: WeightProfile) -> float:
    return float(weights.exposure.get(exposure, 1.0))


def business_impact_factor(business: BusinessImpactContext, weights: WeightProfile) -> float:
    """Multiplier from asset criticality, data classification, and regulated-data flag.

    Caps at the product of the per-table maxima to avoid runaway compounding.
    """
    crit = weights.business_impact_criticality.get(business.asset_criticality, 1.0)
    data = weights.business_impact_data.get(business.data_classification, 1.0)
    reg = 1.05 if business.regulated_data else 1.0
    cap = (
        max(weights.business_impact_criticality.values())
        * max(weights.business_impact_data.values())
        * 1.05
    )
    return min(crit * data * reg, cap)


def compliance_weight(compliance: ComplianceContext, weights: WeightProfile) -> float:
    """Compliance weight = MAX framework weight in scope × audit-horizon boost.

    Empty mapping → 1.0 (no compliance influence).
    """
    base = 1.0
    if compliance.mapped_frameworks:
        framework_max = max(
            (weights.framework_weights.get(fw, 1.0) for fw in compliance.mapped_frameworks),
            default=1.0,
        )
        base = framework_max

    if compliance.audit_horizon_days is not None:
        for max_days, boost in sorted(weights.audit_horizon_boost, key=lambda t: t[0]):
            if compliance.audit_horizon_days <= max_days:
                base *= boost
                break

    return base


def campaign_proximity_factor(threat: ThreatIntelContext, weights: WeightProfile) -> float:
    """Boost driven by correlation-hit count + KEV + active campaign linkage."""
    factor = weights.campaign_proximity_base + (
        weights.campaign_proximity_per_hit * max(0, threat.correlation_hit_count)
    )
    if threat.has_kev_cve:
        factor *= weights.campaign_kev_boost
    if threat.has_active_campaign_link:
        factor *= weights.campaign_active_link_boost
    return min(factor, weights.campaign_proximity_max)


def confidence_factor(confidence: int, weights: WeightProfile) -> float:
    """Linearly interpolate confidence ∈ [0, 100] into [confidence_min, confidence_max]."""
    pct = max(0, min(100, confidence)) / 100.0
    return weights.confidence_min + pct * (weights.confidence_max - weights.confidence_min)


def detection_coverage_factor(detection_coverage: float, weights: WeightProfile) -> float:
    """Low detection coverage → risk is higher (less likely to be caught).

    coverage 1.0 → detection_min ; coverage 0.0 → detection_max.
    """
    cov = max(0.0, min(1.0, detection_coverage))
    return weights.detection_max - cov * (weights.detection_max - weights.detection_min)


def remediation_complexity_factor(
    complexity: RemediationComplexity, weights: WeightProfile
) -> float:
    return float(weights.remediation_complexity.get(complexity, 1.0))


# ---------------------------------------------------------------------------
# Finding-level risk score (higher = worse)
# ---------------------------------------------------------------------------


def compute_finding_risk_score(
    fi: FindingScoreInput, weights: WeightProfile
) -> tuple[float, ScoreBreakdown]:
    """Combine factors into a finding risk score in [0, 100] (higher = worse).

    Returns ``(score, breakdown)`` so callers can persist the breakdown
    alongside the score for explainability.
    """
    base = base_severity_score(fi.severity, weights)
    expl = exploitability_factor(
        fi.exploitability,
        has_kev_cve=fi.threat.has_kev_cve,
        has_active_campaign_link=fi.threat.has_active_campaign_link,
        weights=weights,
    )
    expo = exposure_factor(fi.asset.exposure, weights)
    biz = business_impact_factor(fi.business, weights)
    comp = compliance_weight(fi.compliance, weights)
    camp = campaign_proximity_factor(fi.threat, weights)
    conf = confidence_factor(fi.confidence, weights)
    det = detection_coverage_factor(fi.asset.detection_coverage, weights)
    rem = remediation_complexity_factor(fi.remediation_complexity, weights)

    raw = base * expl * expo * biz * comp * camp * conf * det * rem
    clamped = clamp(raw)

    breakdown = ScoreBreakdown(
        base_severity=base,
        exploitability_factor=expl,
        exposure_factor=expo,
        business_impact_factor=biz,
        compliance_weight=comp,
        campaign_proximity_factor=camp,
        confidence_factor=conf,
        detection_coverage_factor=det,
        remediation_complexity_factor=rem,
        raw_unclamped=raw,
        clamped=clamped,
    )
    return round_score(clamped), breakdown


# ---------------------------------------------------------------------------
# Domain-level posture sub-scores (higher = better)
#
# Each per-domain score is:  100 - mean(risk_score over findings of that domain)
# but with a domain-specific dampener / amplifier for the signals the domain
# cares about most. Findings outside the domain are filtered by the caller.
# ---------------------------------------------------------------------------


def _posture_from_risks(risks: Iterable[float]) -> float:
    """Convert a sequence of finding risks → a posture score.

    Uses the mean to keep the score stable when many findings exist; uses
    a small worst-case bias so a single critical finding still moves the
    needle.
    """
    risks = list(risks)
    if not risks:
        return 100.0  # no findings, no risk — perfect posture
    mean = sum(risks) / len(risks)
    worst = max(risks)
    # 80% mean + 20% worst — keeps aggregates stable, lets one critical bite.
    risk_blend = 0.8 * mean + 0.2 * worst
    return clamp(100.0 - risk_blend)


def _identity_amplifier(fi: FindingScoreInput) -> float:
    """Domain-specific amplifier applied to identity findings.

    Captures the requirement's identity-side factors:
      * privileged identity impact
      * missing MFA
      * missing PIM
    """
    a = 1.0
    asset = fi.asset
    if asset.is_privileged_identity:
        a *= 1.2
    if asset.mfa_enabled is False:
        a *= 1.25
    if asset.mfa_enabled is True and asset.mfa_phishing_resistant is False:
        a *= 1.05
    if asset.pim_eligible is False and asset.is_privileged_identity:
        a *= 1.15
    if asset.risk_level in {"medium", "high"}:
        a *= 1.10
    return min(a, 1.8)


def _azure_exposure_amplifier(fi: FindingScoreInput) -> float:
    """Captures public RDP/SSH, internet-facing, high-risk open ports."""
    a = 1.0
    asset = fi.asset
    if asset.is_internet_facing:
        a *= 1.15
    if asset.public_rdp_open:
        a *= 1.30
    if asset.public_ssh_open:
        a *= 1.20
    if asset.open_high_risk_ports:
        a *= 1.0 + min(0.20, 0.04 * len(asset.open_high_risk_ports))
    return min(a, 1.8)


def _device_amplifier(fi: FindingScoreInput) -> float:
    """Captures missing Defender / backup / encryption on devices and IaaS."""
    a = 1.0
    asset = fi.asset
    if asset.defender_onboarded is False:
        a *= 1.25
    if asset.backup_enabled is False and asset.criticality in {Criticality.HIGH, Criticality.CRITICAL}:
        a *= 1.15
    if asset.encryption_at_rest is False:
        a *= 1.10
    return min(a, 1.6)


def _compliance_amplifier(fi: FindingScoreInput) -> float:
    """Boost when control criticality is high or audit horizon is close."""
    a = 1.0
    if fi.compliance.highest_control_criticality is Criticality.HIGH:
        a *= 1.10
    elif fi.compliance.highest_control_criticality is Criticality.CRITICAL:
        a *= 1.25
    if fi.compliance.audit_horizon_days is not None and fi.compliance.audit_horizon_days <= 30:
        a *= 1.10
    return min(a, 1.5)


def _threat_amplifier(fi: FindingScoreInput) -> float:
    """Boost when TI correlations are present."""
    a = 1.0
    if fi.threat.has_kev_cve:
        a *= 1.20
    if fi.threat.has_active_campaign_link:
        a *= 1.20
    if fi.threat.correlation_hit_count >= 3:
        a *= 1.10
    return min(a, 1.8)


_DOMAIN_AMPLIFIERS = {
    ScoreKind.IDENTITY: _identity_amplifier,
    ScoreKind.AZURE_EXPOSURE: _azure_exposure_amplifier,
    ScoreKind.DEVICE: _device_amplifier,
    ScoreKind.M365_COMPLIANCE: _compliance_amplifier,
    ScoreKind.THREAT_EXPOSURE: _threat_amplifier,
}


def compute_domain_posture_score(
    di: DomainScoreInput, weights: WeightProfile
) -> tuple[float, dict[str, float], list[UUID]]:
    """Aggregate a domain's findings into a posture sub-score.

    Returns ``(score, factor_breakdown, contributing_finding_ids)`` where
    ``factor_breakdown`` is the mean of each factor across the inputs, useful
    for the explainability rules in ``explainability.py``.
    """
    amplifier = _DOMAIN_AMPLIFIERS.get(di.score_kind, lambda _fi: 1.0)
    risks: list[float] = []
    breakdowns: list[ScoreBreakdown] = []
    contributors: list[UUID] = []

    for fi in di.finding_inputs:
        risk, bd = compute_finding_risk_score(fi, weights)
        risk = clamp(risk * amplifier(fi))
        risks.append(risk)
        breakdowns.append(bd)
        contributors.append(fi.finding_id)

    score = _posture_from_risks(risks)

    factor_means: dict[str, float] = {}
    if breakdowns:
        for name in (
            "base_severity",
            "exploitability_factor",
            "exposure_factor",
            "business_impact_factor",
            "compliance_weight",
            "campaign_proximity_factor",
            "confidence_factor",
            "detection_coverage_factor",
            "remediation_complexity_factor",
        ):
            factor_means[name] = round_score(
                sum(getattr(b, name) for b in breakdowns) / len(breakdowns), ndigits=4
            )

    return round_score(score), factor_means, contributors


# ---------------------------------------------------------------------------
# Tenant overall posture
# ---------------------------------------------------------------------------


def compute_overall_posture_score(oi: OverallScoreInput, weights: WeightProfile) -> float:
    """Weighted average of the per-domain posture scores.

    Missing domains are treated as 100 (no signal = no penalty); this lets
    new tenants on Day 0 start at 100 and decay as scans run, rather than
    starting at 0 and rising as data arrives.
    """
    total_weight = 0.0
    total = 0.0
    for kind, weight in weights.aggregate.items():
        sub = oi.sub_scores.get(kind, 100.0)
        sub = clamp(sub)
        total += sub * weight
        total_weight += weight

    if total_weight == 0.0:
        return 100.0
    return round_score(clamp(total / total_weight))


# ---------------------------------------------------------------------------
# Band classification
# ---------------------------------------------------------------------------


def classify_band(score: float, weights: WeightProfile) -> str:
    """Map a posture-direction score to a band name string.

    The caller wraps this into the ``ScoreBand`` enum. We return the raw
    string to avoid a cross-module import here.
    """
    s = int(round(clamp(score)))
    for name in ("excellent", "strong", "moderate", "weak", "critical"):
        threshold = weights.band_thresholds.get(name)
        if threshold is not None and s >= threshold:
            return name
    return "critical"


def classify_finding_band(risk_score: float, weights: WeightProfile) -> str:
    """Map a FINDING-direction risk score to a band (higher risk = worse band).

    Internally we invert and reuse ``classify_band``: a risk of 70 inverts
    to a posture of 30, which falls in the 'critical' band — i.e. the
    finding itself is in the worst band.
    """
    inverted = clamp(100.0 - clamp(risk_score))
    return classify_band(inverted, weights)
