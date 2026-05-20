"""Deterministic, rule-based explainability.

For every score we produce a small, ordered list of ``ExplainabilityReason``
records that say *why* the score is high or low. The rules here are pure
functions of the inputs and the breakdown — no LLM, no randomness, no
network. The AI engine consumes these as grounding material for executive
narrative but never replaces them.

Each reason carries:

  * a stable ``code`` (machine-readable, never localized),
  * a short ``title``,
  * a longer ``detail`` (safe to surface to operators),
  * a ``category`` and ``factor_name``,
  * a signed ``contribution_delta`` measured in score-points.

Convention: ``contribution_delta`` is positive when the reason makes the
score WORSE (in finding-direction) or BETTER (in posture-direction). The
calculator wires the right sign per output type.
"""

from __future__ import annotations

from risk_engine.contracts import (
    Criticality,
    DomainScoreInput,
    Exploitability,
    ExposureLevel,
    ExplainabilityReason,
    ExplainabilityReasonCategory,
    FindingScoreInput,
    OverallScoreInput,
    ScoreBreakdown,
    ScoreKind,
    Severity,
)
from risk_engine.weights import WeightProfile


# Maximum reasons surfaced per output; keeps narratives focused.
_MAX_REASONS_FINDING = 6
_MAX_REASONS_DOMAIN = 5
_MAX_REASONS_OVERALL = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _delta_from_factor(base: float, factor: float) -> float:
    """How many score-points a multiplier contributed (signed).

    +X means it raised the score by X points relative to the no-effect baseline
    of ``factor=1.0``.
    """
    return round((base * factor) - base, 2)


def _reason(
    *,
    code: str,
    title: str,
    detail: str,
    category: ExplainabilityReasonCategory,
    factor_name: str,
    contribution_delta: float,
) -> ExplainabilityReason:
    return ExplainabilityReason(
        code=code,
        title=title,
        detail=detail,
        category=category,
        factor_name=factor_name,
        contribution_delta=contribution_delta,
    )


# ---------------------------------------------------------------------------
# Finding-level reasons (finding-direction: higher = worse)
# ---------------------------------------------------------------------------


def explain_finding_score(
    fi: FindingScoreInput, breakdown: ScoreBreakdown, weights: WeightProfile
) -> list[ExplainabilityReason]:
    """Produce ordered reasons for a single finding's risk score."""
    reasons: list[ExplainabilityReason] = []
    base = breakdown.base_severity

    # --- Severity ---------------------------------------------------------
    if fi.severity in {Severity.HIGH, Severity.CRITICAL}:
        reasons.append(
            _reason(
                code=f"high_severity_{fi.severity.value}",
                title=f"Severity is {fi.severity.value}",
                detail=(
                    f"The finding is rated {fi.severity.value}, which contributes "
                    f"{base:.0f} base points to the risk score."
                ),
                category=ExplainabilityReasonCategory.SEVERITY,
                factor_name="base_severity",
                contribution_delta=round(base, 2),
            )
        )

    # --- Exploitability / KEV / active campaign ---------------------------
    if fi.threat.has_kev_cve:
        reasons.append(
            _reason(
                code="active_exploitation_kev",
                title="Actively exploited in the wild (CISA KEV)",
                detail=(
                    "A CVE associated with this finding is on the CISA Known "
                    "Exploited Vulnerabilities catalog, indicating active "
                    "in-the-wild exploitation."
                ),
                category=ExplainabilityReasonCategory.THREAT_INTEL,
                factor_name="exploitability_factor",
                contribution_delta=_delta_from_factor(base, breakdown.exploitability_factor),
            )
        )
    elif fi.exploitability is Exploitability.ACTIVE:
        reasons.append(
            _reason(
                code="active_exploitation",
                title="Active exploitation observed",
                detail="Exploit activity tied to this issue has been observed in the wild.",
                category=ExplainabilityReasonCategory.EXPLOITABILITY,
                factor_name="exploitability_factor",
                contribution_delta=_delta_from_factor(base, breakdown.exploitability_factor),
            )
        )

    # --- Internet / public-port exposure ---------------------------------
    if fi.asset.public_rdp_open:
        reasons.append(
            _reason(
                code="public_rdp_exposed",
                title="RDP exposed to the public internet",
                detail=(
                    "TCP/3389 is reachable from 0.0.0.0/0. Public RDP is the "
                    "primary initial-access vector for multiple active ransomware "
                    "campaigns (MITRE T1133, T1110)."
                ),
                category=ExplainabilityReasonCategory.EXPOSURE,
                factor_name="exposure_factor",
                contribution_delta=_delta_from_factor(base, breakdown.exposure_factor),
            )
        )
    elif fi.asset.public_ssh_open:
        reasons.append(
            _reason(
                code="public_ssh_exposed",
                title="SSH exposed to the public internet",
                detail=(
                    "TCP/22 is reachable from 0.0.0.0/0. Restrict to Bastion or "
                    "narrow source ranges."
                ),
                category=ExplainabilityReasonCategory.EXPOSURE,
                factor_name="exposure_factor",
                contribution_delta=_delta_from_factor(base, breakdown.exposure_factor),
            )
        )
    elif fi.asset.exposure is ExposureLevel.PUBLIC:
        reasons.append(
            _reason(
                code="internet_exposed",
                title="Asset is internet-facing",
                detail=(
                    "The affected asset is reachable from the public internet, "
                    "which raises both attacker discovery and exploitation risk."
                ),
                category=ExplainabilityReasonCategory.EXPOSURE,
                factor_name="exposure_factor",
                contribution_delta=_delta_from_factor(base, breakdown.exposure_factor),
            )
        )

    # --- Identity (privileged / MFA / PIM) -------------------------------
    if fi.asset.is_privileged_identity and fi.asset.mfa_enabled is False:
        reasons.append(
            _reason(
                code="privileged_identity_no_mfa",
                title="Privileged identity without MFA",
                detail=(
                    "The affected principal holds privileged roles but does not "
                    "have MFA enforced. This is a top initial-access vector "
                    "(MITRE T1078)."
                ),
                category=ExplainabilityReasonCategory.IDENTITY,
                factor_name="business_impact_factor",
                contribution_delta=_delta_from_factor(base, breakdown.business_impact_factor),
            )
        )
    if fi.asset.is_privileged_identity and fi.asset.pim_eligible is False:
        reasons.append(
            _reason(
                code="privileged_identity_no_pim",
                title="Privileged role without PIM eligibility",
                detail=(
                    "The principal holds a privileged role permanently rather "
                    "than through Privileged Identity Management (PIM) JIT "
                    "activation, widening the standing-access blast radius."
                ),
                category=ExplainabilityReasonCategory.IDENTITY,
                factor_name="business_impact_factor",
                contribution_delta=_delta_from_factor(base, breakdown.business_impact_factor),
            )
        )

    # --- Device / endpoint hygiene ---------------------------------------
    if fi.asset.defender_onboarded is False:
        reasons.append(
            _reason(
                code="missing_defender_coverage",
                title="Defender for Endpoint not onboarded",
                detail=(
                    "The affected asset is not onboarded to Microsoft Defender "
                    "for Endpoint, reducing detection coverage."
                ),
                category=ExplainabilityReasonCategory.DEVICE,
                factor_name="detection_coverage_factor",
                contribution_delta=_delta_from_factor(base, breakdown.detection_coverage_factor),
            )
        )

    # --- Compliance + audit horizon --------------------------------------
    if (
        fi.compliance.audit_horizon_days is not None
        and fi.compliance.audit_horizon_days <= 30
    ):
        reasons.append(
            _reason(
                code="audit_horizon_close",
                title="Audit within 30 days",
                detail=(
                    "The mapped compliance framework has an audit horizon within "
                    "30 days; weight is temporarily boosted."
                ),
                category=ExplainabilityReasonCategory.COMPLIANCE,
                factor_name="compliance_weight",
                contribution_delta=_delta_from_factor(base, breakdown.compliance_weight),
            )
        )
    if fi.compliance.highest_control_criticality in {Criticality.HIGH, Criticality.CRITICAL}:
        reasons.append(
            _reason(
                code="high_compliance_control_criticality",
                title="Maps to a high-criticality compliance control",
                detail=(
                    "The finding violates a compliance control marked "
                    f"{fi.compliance.highest_control_criticality.value}, which "
                    "raises its compliance weight."
                ),
                category=ExplainabilityReasonCategory.COMPLIANCE,
                factor_name="compliance_weight",
                contribution_delta=_delta_from_factor(base, breakdown.compliance_weight),
            )
        )

    # --- Business impact -------------------------------------------------
    if fi.business.asset_criticality in {Criticality.HIGH, Criticality.CRITICAL}:
        reasons.append(
            _reason(
                code="high_business_criticality",
                title=f"Business criticality is {fi.business.asset_criticality.value}",
                detail=(
                    "Tenant policy marks the affected asset as "
                    f"{fi.business.asset_criticality.value} criticality."
                ),
                category=ExplainabilityReasonCategory.BUSINESS_IMPACT,
                factor_name="business_impact_factor",
                contribution_delta=_delta_from_factor(base, breakdown.business_impact_factor),
            )
        )

    # --- Threat-intel correlation hits -----------------------------------
    if fi.threat.has_active_campaign_link:
        reasons.append(
            _reason(
                code="active_campaign_correlation",
                title="Linked to an active threat campaign",
                detail=(
                    "Threat-intelligence correlation links this finding to an "
                    "active campaign tracked by the platform."
                ),
                category=ExplainabilityReasonCategory.THREAT_INTEL,
                factor_name="campaign_proximity_factor",
                contribution_delta=_delta_from_factor(base, breakdown.campaign_proximity_factor),
            )
        )
    if fi.threat.correlation_hit_count >= 3:
        reasons.append(
            _reason(
                code="multi_dimension_ti_hits",
                title="Multiple TI correlations",
                detail=(
                    f"{fi.threat.correlation_hit_count} threat-intelligence "
                    "correlation hits attached to this finding."
                ),
                category=ExplainabilityReasonCategory.THREAT_INTEL,
                factor_name="campaign_proximity_factor",
                contribution_delta=_delta_from_factor(base, breakdown.campaign_proximity_factor),
            )
        )

    # --- Detection coverage ----------------------------------------------
    if fi.asset.detection_coverage < 0.4:
        reasons.append(
            _reason(
                code="weak_detection_coverage",
                title="Weak detection coverage",
                detail=(
                    "Detection coverage on / around this asset is low; an attack "
                    "is less likely to be observed in time."
                ),
                category=ExplainabilityReasonCategory.DETECTION,
                factor_name="detection_coverage_factor",
                contribution_delta=_delta_from_factor(base, breakdown.detection_coverage_factor),
            )
        )

    # --- Remediation complexity (dampener narrative) ---------------------
    if breakdown.remediation_complexity_factor > 1.0:
        reasons.append(
            _reason(
                code="complex_remediation",
                title="Remediation is complex",
                detail=(
                    "The recommended remediation is complex enough that the "
                    "finding is kept high in the backlog until completed."
                ),
                category=ExplainabilityReasonCategory.REMEDIATION,
                factor_name="remediation_complexity_factor",
                contribution_delta=_delta_from_factor(base, breakdown.remediation_complexity_factor),
            )
        )

    # --- Low confidence (dampener narrative) -----------------------------
    if fi.confidence < 50:
        reasons.append(
            _reason(
                code="low_confidence",
                title="Low scanner confidence",
                detail=(
                    f"Scanner reported the finding at confidence {fi.confidence}/100; "
                    "the risk score has been dampened accordingly."
                ),
                category=ExplainabilityReasonCategory.CONFIDENCE,
                factor_name="confidence_factor",
                # confidence < 1.0 dampens; reflect negative contribution
                contribution_delta=_delta_from_factor(base, breakdown.confidence_factor),
            )
        )

    # Rank by absolute contribution and keep the top N.
    reasons.sort(key=lambda r: abs(r.contribution_delta), reverse=True)
    _ = weights  # weights param reserved for future per-policy reason gates
    return reasons[:_MAX_REASONS_FINDING]


# ---------------------------------------------------------------------------
# Domain-level reasons (posture-direction: higher = better)
# ---------------------------------------------------------------------------


def explain_domain_score(
    di: DomainScoreInput, factor_breakdown: dict[str, float], weights: WeightProfile
) -> list[ExplainabilityReason]:
    """Produce ordered reasons for one domain's posture sub-score."""
    reasons: list[ExplainabilityReason] = []
    n = len(di.finding_inputs)

    if n == 0:
        reasons.append(
            _reason(
                code="no_findings_in_domain",
                title="No findings in this domain",
                detail=(
                    f"No findings detected in the {di.score_kind.value} domain; "
                    "the score is at the no-signal baseline."
                ),
                category=_category_for_domain(di.score_kind),
                factor_name="aggregate",
                contribution_delta=0.0,
            )
        )
        return reasons

    # Surface specific painful conditions per domain.
    if di.score_kind is ScoreKind.IDENTITY:
        n_priv_no_mfa = sum(
            1 for fi in di.finding_inputs if fi.asset.is_privileged_identity and fi.asset.mfa_enabled is False
        )
        n_no_pim = sum(
            1 for fi in di.finding_inputs if fi.asset.is_privileged_identity and fi.asset.pim_eligible is False
        )
        if n_priv_no_mfa:
            reasons.append(
                _reason(
                    code="domain_identity_priv_no_mfa",
                    title=f"{n_priv_no_mfa} privileged identity findings without MFA",
                    detail=(
                        f"{n_priv_no_mfa} of {n} identity findings affect privileged "
                        "principals without MFA enforced."
                    ),
                    category=ExplainabilityReasonCategory.IDENTITY,
                    factor_name="business_impact_factor",
                    contribution_delta=-1.0 * n_priv_no_mfa,
                )
            )
        if n_no_pim:
            reasons.append(
                _reason(
                    code="domain_identity_no_pim",
                    title=f"{n_no_pim} privileged roles without PIM",
                    detail=(
                        f"{n_no_pim} of {n} findings involve privileged roles held "
                        "permanently rather than via PIM JIT activation."
                    ),
                    category=ExplainabilityReasonCategory.IDENTITY,
                    factor_name="business_impact_factor",
                    contribution_delta=-1.0 * n_no_pim,
                )
            )
    elif di.score_kind is ScoreKind.AZURE_EXPOSURE:
        n_rdp = sum(1 for fi in di.finding_inputs if fi.asset.public_rdp_open)
        n_ssh = sum(1 for fi in di.finding_inputs if fi.asset.public_ssh_open)
        if n_rdp:
            reasons.append(
                _reason(
                    code="domain_azure_public_rdp",
                    title=f"{n_rdp} assets with public RDP",
                    detail=f"{n_rdp} Azure assets have RDP reachable from the internet.",
                    category=ExplainabilityReasonCategory.EXPOSURE,
                    factor_name="exposure_factor",
                    contribution_delta=-1.5 * n_rdp,
                )
            )
        if n_ssh:
            reasons.append(
                _reason(
                    code="domain_azure_public_ssh",
                    title=f"{n_ssh} assets with public SSH",
                    detail=f"{n_ssh} Azure assets have SSH reachable from the internet.",
                    category=ExplainabilityReasonCategory.EXPOSURE,
                    factor_name="exposure_factor",
                    contribution_delta=-1.0 * n_ssh,
                )
            )
    elif di.score_kind is ScoreKind.DEVICE:
        n_no_def = sum(
            1 for fi in di.finding_inputs if fi.asset.defender_onboarded is False
        )
        if n_no_def:
            reasons.append(
                _reason(
                    code="domain_device_missing_defender",
                    title=f"{n_no_def} assets not onboarded to Defender",
                    detail=(
                        f"{n_no_def} of {n} device findings affect endpoints not "
                        "onboarded to Microsoft Defender for Endpoint."
                    ),
                    category=ExplainabilityReasonCategory.DEVICE,
                    factor_name="detection_coverage_factor",
                    contribution_delta=-1.0 * n_no_def,
                )
            )
    elif di.score_kind is ScoreKind.THREAT_EXPOSURE:
        n_kev = sum(1 for fi in di.finding_inputs if fi.threat.has_kev_cve)
        n_camp = sum(1 for fi in di.finding_inputs if fi.threat.has_active_campaign_link)
        if n_kev:
            reasons.append(
                _reason(
                    code="domain_threat_kev_hits",
                    title=f"{n_kev} findings with KEV CVEs",
                    detail=f"{n_kev} findings reference CVEs on the CISA KEV catalog.",
                    category=ExplainabilityReasonCategory.THREAT_INTEL,
                    factor_name="campaign_proximity_factor",
                    contribution_delta=-1.5 * n_kev,
                )
            )
        if n_camp:
            reasons.append(
                _reason(
                    code="domain_threat_active_campaigns",
                    title=f"{n_camp} findings linked to active campaigns",
                    detail=(
                        f"{n_camp} findings correlate to active threat campaigns "
                        "tracked by the platform."
                    ),
                    category=ExplainabilityReasonCategory.THREAT_INTEL,
                    factor_name="campaign_proximity_factor",
                    contribution_delta=-1.5 * n_camp,
                )
            )
    elif di.score_kind is ScoreKind.M365_COMPLIANCE:
        n_audit = sum(
            1
            for fi in di.finding_inputs
            if fi.compliance.audit_horizon_days is not None
            and fi.compliance.audit_horizon_days <= 30
        )
        if n_audit:
            reasons.append(
                _reason(
                    code="domain_compliance_audit_near",
                    title=f"{n_audit} findings under near-term audit horizon",
                    detail=(
                        f"{n_audit} compliance findings are under a framework "
                        "whose next audit is within 30 days."
                    ),
                    category=ExplainabilityReasonCategory.COMPLIANCE,
                    factor_name="compliance_weight",
                    contribution_delta=-1.0 * n_audit,
                )
            )

    # Generic "many findings of severity X" reason.
    n_high = sum(
        1 for fi in di.finding_inputs if fi.severity in {Severity.HIGH, Severity.CRITICAL}
    )
    if n_high:
        reasons.append(
            _reason(
                code="domain_many_high_severity",
                title=f"{n_high} high or critical findings",
                detail=(
                    f"{n_high} of {n} findings in this domain are rated HIGH or "
                    "CRITICAL severity."
                ),
                category=_category_for_domain(di.score_kind),
                factor_name="base_severity",
                contribution_delta=-1.0 * n_high,
            )
        )

    _ = (factor_breakdown, weights)  # reserved for per-policy reason gates
    reasons.sort(key=lambda r: abs(r.contribution_delta), reverse=True)
    return reasons[:_MAX_REASONS_DOMAIN]


# ---------------------------------------------------------------------------
# Overall-tenant reasons
# ---------------------------------------------------------------------------


def explain_overall_score(
    oi: OverallScoreInput, weights: WeightProfile
) -> list[ExplainabilityReason]:
    """Produce reasons for the tenant overall posture score."""
    reasons: list[ExplainabilityReason] = []
    if not oi.sub_scores:
        reasons.append(
            _reason(
                code="overall_no_signals",
                title="No domain signals yet",
                detail="No per-domain scores supplied; overall is at the baseline.",
                category=ExplainabilityReasonCategory.SEVERITY,
                factor_name="aggregate",
                contribution_delta=0.0,
            )
        )
        return reasons

    # Rank domains by (weight × distance-from-100) → "what is pulling down the score most".
    contributions: list[tuple[ScoreKind, float, float, float]] = []
    for kind, weight in weights.aggregate.items():
        sub = float(oi.sub_scores.get(kind, 100))
        pull = (100.0 - sub) * weight
        contributions.append((kind, sub, weight, pull))

    contributions.sort(key=lambda t: t[3], reverse=True)

    for kind, sub, weight, pull in contributions[:_MAX_REASONS_OVERALL]:
        if pull <= 0.0:
            continue
        reasons.append(
            _reason(
                code=f"overall_domain_drag_{kind.value}",
                title=f"{kind.value} domain pulls the overall score down",
                detail=(
                    f"The {kind.value} sub-score is {sub:.0f}; this domain carries "
                    f"weight {weight:.2f} in the overall posture calculation, "
                    f"contributing approximately -{pull:.1f} points."
                ),
                category=_category_for_domain(kind),
                factor_name="aggregate",
                contribution_delta=-round(pull, 2),
            )
        )

    if not reasons:
        reasons.append(
            _reason(
                code="overall_all_domains_strong",
                title="All domains at or near best posture",
                detail="No domain materially pulls the overall score down.",
                category=ExplainabilityReasonCategory.SEVERITY,
                factor_name="aggregate",
                contribution_delta=0.0,
            )
        )
    return reasons[:_MAX_REASONS_OVERALL]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _category_for_domain(kind: ScoreKind) -> ExplainabilityReasonCategory:
    return {
        ScoreKind.IDENTITY: ExplainabilityReasonCategory.IDENTITY,
        ScoreKind.AZURE_EXPOSURE: ExplainabilityReasonCategory.EXPOSURE,
        ScoreKind.DEVICE: ExplainabilityReasonCategory.DEVICE,
        ScoreKind.M365_COMPLIANCE: ExplainabilityReasonCategory.COMPLIANCE,
        ScoreKind.THREAT_EXPOSURE: ExplainabilityReasonCategory.THREAT_INTEL,
    }.get(kind, ExplainabilityReasonCategory.SEVERITY)
