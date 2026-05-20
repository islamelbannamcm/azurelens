"""Risk-engine wire contracts (Pydantic v2).

These shapes describe everything that crosses the scoring boundary:

  * inputs that drive a per-finding score (severity, exploitability, asset
    context, TI context, business impact, compliance context),
  * inputs that drive per-domain sub-scores (identity, azure exposure,
    device, compliance, threat exposure),
  * outputs (`RiskScoreOutput` + per-factor `ScoreBreakdown` +
    `ExplainabilityReason`s),
  * scoring-policy descriptors.

Enums mirror the canonical wire enums in ``apps/api/app/models/`` so
emitted outputs flow into ``apps/api/app/models/scoring.py`` and
``apps/api/app/models/finding.py`` without translation. When
``packages/shared-types`` lands, these local enums will be replaced by
re-exports.

Score-direction convention (important)
-------------------------------------
* Per-FINDING ``risk_score`` ∈ [0, 100]. **Higher = worse.**
* Per-DOMAIN sub-score and per-TENANT overall ``posture`` ∈ [0, 100].
  **Higher = better.**

The calculator handles the inversion explicitly; readers of this module
should keep the convention straight.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Base config
# ---------------------------------------------------------------------------


_MODEL_CONFIG = ConfigDict(
    extra="forbid",
    str_strip_whitespace=True,
    validate_assignment=True,
    populate_by_name=True,
    use_enum_values=False,
)


class _Model(BaseModel):
    """Local strict base mirroring the API's ``AzureLensModel`` configuration."""

    model_config = _MODEL_CONFIG


# ---------------------------------------------------------------------------
# Mirrored enums (must match apps/api/app/models/*)
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exploitability(str, Enum):
    NONE = "none"
    THEORETICAL = "theoretical"
    POC = "poc"
    ACTIVE = "active"


class ExposureLevel(str, Enum):
    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class Criticality(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreKind(str, Enum):
    OVERALL = "overall"
    IDENTITY = "identity"
    AZURE_EXPOSURE = "azure_exposure"
    DEVICE = "device"
    THREAT_EXPOSURE = "threat_exposure"
    M365_COMPLIANCE = "m365_compliance"


class ScoreBand(str, Enum):
    CRITICAL = "critical"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    EXCELLENT = "excellent"


class RemediationComplexity(str, Enum):
    TRIVIAL = "trivial"      # < 30 min, no change-control
    LOW = "low"               # < 2 h
    MEDIUM = "medium"         # < 1 day
    HIGH = "high"             # > 1 day, change-control
    EXTREME = "extreme"       # multi-team / multi-quarter


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ---------------------------------------------------------------------------
# Context inputs
# ---------------------------------------------------------------------------


class AssetContext(_Model):
    """Per-asset attributes that drive the asset/identity/device formulas."""

    asset_id: str
    asset_kind: str = Field(..., description="AssetKind enum value, e.g. 'azure.vm'.")
    exposure: ExposureLevel = Field(default=ExposureLevel.UNKNOWN)
    criticality: Criticality = Field(default=Criticality.MODERATE)

    # Network / endpoint exposure
    is_internet_facing: bool = Field(default=False)
    public_rdp_open: bool = Field(default=False)
    public_ssh_open: bool = Field(default=False)
    open_high_risk_ports: list[int] = Field(default_factory=list)

    # Endpoint hygiene
    defender_onboarded: bool | None = Field(
        default=None,
        description="None when not applicable (e.g. PaaS resource without endpoint).",
    )
    backup_enabled: bool | None = Field(default=None)
    encryption_at_rest: bool | None = Field(default=None)

    # Identity attributes (used when asset_kind is m365.user / m365.service_principal)
    is_privileged_identity: bool = Field(default=False)
    mfa_enabled: bool | None = Field(default=None)
    mfa_phishing_resistant: bool | None = Field(default=None)
    pim_eligible: bool | None = Field(default=None)
    risk_level: str | None = Field(
        default=None,
        description="Entra ID risky-user level: 'none' | 'low' | 'medium' | 'high'.",
    )

    # Detection coverage on / around this asset (0..1)
    detection_coverage: float = Field(default=0.5, ge=0.0, le=1.0)


class ComplianceContext(_Model):
    """Compliance signal that influences a finding's weight."""

    mapped_frameworks: list[str] = Field(
        default_factory=list,
        description="ComplianceFramework enum values, e.g. ['cis_azure', 'nist_csf'].",
    )
    highest_control_criticality: Criticality = Field(default=Criticality.MODERATE)
    audit_horizon_days: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Days until next external audit. Findings under audit get a temporary "
            "weight boost so the prioritized backlog reflects audit urgency."
        ),
    )


class ThreatIntelContext(_Model):
    """Live-threat signal joined to the finding by the correlator."""

    has_kev_cve: bool = Field(default=False)
    has_active_campaign_link: bool = Field(default=False)
    correlation_hit_count: int = Field(default=0, ge=0)
    hit_dimensions: list[str] = Field(
        default_factory=list,
        description="CorrelationDimension enum values, e.g. ['cve_in_inventory'].",
    )


class BusinessImpactContext(_Model):
    """Tenant-set business-impact attributes for the affected asset / data."""

    asset_criticality: Criticality = Field(default=Criticality.MODERATE)
    data_classification: DataClassification | None = Field(default=None)
    regulated_data: bool = Field(default=False)
    users_impacted_estimate: int | None = Field(default=None, ge=0)
    revenue_impact_tier: str | None = Field(
        default=None,
        description="Free-form tier id, e.g. 'tier_1_revenue' set by tenant policy.",
    )


# ---------------------------------------------------------------------------
# Scoring inputs
# ---------------------------------------------------------------------------


class FindingScoreInput(_Model):
    """Input for ``RiskCalculator.score_finding``."""

    finding_id: UUID
    tenant_id: UUID
    finding_type: str
    severity: Severity = Field(default=Severity.MEDIUM)
    exploitability: Exploitability = Field(default=Exploitability.NONE)
    mitre_techniques: list[str] = Field(default_factory=list)

    asset: AssetContext
    compliance: ComplianceContext = Field(default_factory=ComplianceContext)
    threat: ThreatIntelContext = Field(default_factory=ThreatIntelContext)
    business: BusinessImpactContext = Field(default_factory=BusinessImpactContext)

    remediation_complexity: RemediationComplexity = Field(default=RemediationComplexity.MEDIUM)
    confidence: int = Field(
        default=80,
        ge=0,
        le=100,
        description="Producing scanner's confidence in the detection (0-100).",
    )


class DomainScoreInput(_Model):
    """Input for any per-domain sub-score (identity, azure exposure, device, ...).

    The calculator aggregates ``finding_inputs`` belonging to a single
    domain into one bounded score.
    """

    tenant_id: UUID
    score_kind: ScoreKind
    finding_inputs: list[FindingScoreInput] = Field(default_factory=list)
    # Optional domain-wide signals (e.g. % devices with Defender onboarded,
    # % users with phishing-resistant MFA). Free-form to keep the contract
    # open for future signal types.
    domain_signals: dict[str, float] = Field(default_factory=dict)


class OverallScoreInput(_Model):
    """Input for ``RiskCalculator.score_overall``."""

    tenant_id: UUID
    sub_scores: dict[ScoreKind, float] = Field(
        default_factory=dict,
        description="Per-domain posture scores (higher = better, 0..100).",
    )


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------


class ScoreBreakdown(_Model):
    """Per-factor contribution; persisted alongside the score for explainability."""

    base_severity: float = Field(..., ge=0.0)
    exploitability_factor: float = Field(..., gt=0.0)
    exposure_factor: float = Field(..., gt=0.0)
    business_impact_factor: float = Field(..., gt=0.0)
    compliance_weight: float = Field(..., gt=0.0)
    campaign_proximity_factor: float = Field(..., gt=0.0)
    confidence_factor: float = Field(..., gt=0.0)
    detection_coverage_factor: float = Field(..., gt=0.0)
    remediation_complexity_factor: float = Field(..., gt=0.0)

    raw_unclamped: float = Field(
        ...,
        description="Raw product before clamping; useful for debugging tuning.",
    )
    clamped: float = Field(..., ge=0.0, le=100.0)


class ExplainabilityReasonCategory(str, Enum):
    SEVERITY = "severity"
    EXPLOITABILITY = "exploitability"
    EXPOSURE = "exposure"
    IDENTITY = "identity"
    DEVICE = "device"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intel"
    BUSINESS_IMPACT = "business_impact"
    DETECTION = "detection"
    REMEDIATION = "remediation"
    CONFIDENCE = "confidence"


class ExplainabilityReason(_Model):
    """One human-readable reason a score is high or low.

    Generated by deterministic rule-based templates (no LLM); the AI engine
    consumes these as grounding material for executive narrative but never
    invents new reasons.
    """

    code: str = Field(
        ...,
        description="Stable identifier, e.g. 'active_exploitation_kev'.",
        pattern=r"^[a-z][a-z0-9_]{2,80}$",
    )
    title: str = Field(..., min_length=1, max_length=200)
    detail: str = Field(..., min_length=1, max_length=1000)
    category: ExplainabilityReasonCategory
    factor_name: str = Field(
        ...,
        description="Name of the score factor this reason explains, e.g. 'exploitability_factor'.",
        max_length=80,
    )
    contribution_delta: float = Field(
        ...,
        description=(
            "Signed contribution to the score, in score-points. Positive ⇒ this "
            "reason made the score WORSE (for finding scores) or BETTER (for "
            "posture scores)."
        ),
    )


class ScoringPolicyRef(_Model):
    """Pointer to the policy used for a calculation (recorded on every score)."""

    policy_id: str = Field(default="default")
    version: int = Field(default=1, ge=1)


class RiskScoreOutput(_Model):
    """Per-finding risk score result (higher = worse)."""

    finding_id: UUID
    tenant_id: UUID
    score: float = Field(..., ge=0.0, le=100.0)
    band: ScoreBand
    breakdown: ScoreBreakdown
    reasons: list[ExplainabilityReason] = Field(default_factory=list)
    policy: ScoringPolicyRef = Field(default_factory=ScoringPolicyRef)
    calculated_at: datetime


class DomainScoreOutput(_Model):
    """Per-domain posture score result (higher = better)."""

    tenant_id: UUID
    score_kind: ScoreKind
    value: int = Field(..., ge=0, le=100)
    band: ScoreBand
    contributing_finding_ids: list[UUID] = Field(default_factory=list)
    factor_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Per-factor aggregate contributions for this domain (0..100 each).",
    )
    reasons: list[ExplainabilityReason] = Field(default_factory=list)
    policy: ScoringPolicyRef = Field(default_factory=ScoringPolicyRef)
    calculated_at: datetime


class OverallScoreOutput(_Model):
    """Tenant overall posture score (higher = better)."""

    tenant_id: UUID
    value: int = Field(..., ge=0, le=100)
    band: ScoreBand
    sub_scores: dict[ScoreKind, int] = Field(default_factory=dict)
    reasons: list[ExplainabilityReason] = Field(default_factory=list)
    policy: ScoringPolicyRef = Field(default_factory=ScoringPolicyRef)
    calculated_at: datetime


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


class ScoringDecision(_Model):
    """A single rule decision recorded during explainability generation.

    Internal debugging aid; not surfaced to end users.
    """

    rule_id: str
    matched: bool
    detail: dict[str, Any] = Field(default_factory=dict)
