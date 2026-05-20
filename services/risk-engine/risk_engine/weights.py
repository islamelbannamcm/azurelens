"""Default scoring weights.

This module holds the **default** weight tables and the ``WeightProfile``
Pydantic model that the calculator consumes. Named policy profiles in
``policy.py`` build ``ScoringPolicy`` instances on top of these defaults
(default / executive / compliance-focused / threat-focused /
identity-focused).

Tuning principles
-----------------
* Most multipliers are centered around **1.0**: values > 1 raise the
  risk; values < 1 dampen it. ``base_severity`` is the only quantity
  measured directly in score-points (0-100).
* Multipliers are bounded — typically 0.6 to 1.6 — so a single factor
  cannot dominate the final score on its own.
* Aggregate weights across ``ScoreKind`` sum to **1.0** so the overall
  posture score remains a weighted average of bounded sub-scores and
  stays inside [0, 100].
* No nonlinearities here — all formulas in ``formulas.py`` are
  deterministic, idempotent, and trivially testable.
"""

from __future__ import annotations

from typing import Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

from risk_engine.contracts import (
    Criticality,
    DataClassification,
    Exploitability,
    ExposureLevel,
    RemediationComplexity,
    ScoreKind,
    Severity,
)
from risk_engine.errors import RiskConfigError


# ---------------------------------------------------------------------------
# Default tables (centered around 1.0 where applicable)
# ---------------------------------------------------------------------------


#: Base severity expressed directly in score-points (0..100).
DEFAULT_SEVERITY_BASE: Mapping[Severity, float] = {
    Severity.INFO: 5.0,
    Severity.LOW: 15.0,
    Severity.MEDIUM: 40.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 100.0,
}

#: Risk multiplier driven by how exploitable the underlying issue is.
DEFAULT_EXPLOITABILITY: Mapping[Exploitability, float] = {
    Exploitability.NONE: 0.9,
    Exploitability.THEORETICAL: 1.0,
    Exploitability.POC: 1.2,
    Exploitability.ACTIVE: 1.5,  # KEV-listed / observed in-the-wild
}

#: Where the affected asset is reachable from.
DEFAULT_EXPOSURE: Mapping[ExposureLevel, float] = {
    ExposureLevel.INTERNAL: 1.0,
    ExposureLevel.PARTNER: 1.1,
    ExposureLevel.PUBLIC: 1.3,
    ExposureLevel.UNKNOWN: 1.05,  # conservative
}

#: Tenant-set business impact multiplier from asset criticality.
DEFAULT_BUSINESS_IMPACT_CRITICALITY: Mapping[Criticality, float] = {
    Criticality.LOW: 0.8,
    Criticality.MODERATE: 1.0,
    Criticality.HIGH: 1.25,
    Criticality.CRITICAL: 1.5,
}

#: Additional small boost when the affected data is regulated / restricted.
DEFAULT_BUSINESS_IMPACT_DATA: Mapping[DataClassification | None, float] = {
    None: 1.0,
    DataClassification.PUBLIC: 1.0,
    DataClassification.INTERNAL: 1.05,
    DataClassification.CONFIDENTIAL: 1.15,
    DataClassification.RESTRICTED: 1.3,
}

#: Compliance weight floor; final value is the MAX over mapped frameworks.
DEFAULT_FRAMEWORK_WEIGHTS: Mapping[str, float] = {
    "cis_azure": 1.1,
    "mcsb": 1.1,
    "nist_csf": 1.1,
    "nist_800_53": 1.15,
    "iso_27001": 1.15,
    "soc2": 1.2,
    "gdpr": 1.25,
    "zero_trust": 1.1,
    "azure_waf": 1.05,
    "m365_baseline": 1.1,
    "cis_m365": 1.1,
    "hipaa": 1.3,
    "pci_dss": 1.3,
}

#: Boost when the next audit is near (audit_horizon_days).
DEFAULT_AUDIT_HORIZON_BOOST: tuple[tuple[int, float], ...] = (
    (7, 1.25),   # audit within 7 days
    (30, 1.15),  # audit within 30 days
    (90, 1.05),  # audit within 90 days
)

#: Campaign-proximity boost. Driven by the number of correlation hits and
#: whether an active campaign link or KEV CVE is in scope.
DEFAULT_CAMPAIGN_PROXIMITY_BASE: float = 1.0
DEFAULT_CAMPAIGN_PROXIMITY_PER_HIT: float = 0.05  # additive per hit
DEFAULT_CAMPAIGN_PROXIMITY_MAX: float = 1.4
DEFAULT_CAMPAIGN_KEV_BOOST: float = 1.15            # multiplied in if KEV in scope
DEFAULT_CAMPAIGN_ACTIVE_LINK_BOOST: float = 1.1     # multiplied in if active campaign

#: Confidence factor: scanner produced this finding at confidence c ∈ [0, 100].
#: Effective multiplier in [0.6, 1.0] — low confidence dampens score.
DEFAULT_CONFIDENCE_MIN: float = 0.6
DEFAULT_CONFIDENCE_MAX: float = 1.0

#: Detection coverage (0..1) → multiplier in [0.85, 1.15]. Low coverage
#: raises risk because attacks are less likely to be noticed.
DEFAULT_DETECTION_MIN: float = 0.85
DEFAULT_DETECTION_MAX: float = 1.15

#: Remediation complexity → multiplier in [0.95, 1.10]. Harder remediations
#: keep the score slightly higher in the prioritized backlog.
DEFAULT_REMEDIATION_COMPLEXITY: Mapping[RemediationComplexity, float] = {
    RemediationComplexity.TRIVIAL: 0.95,
    RemediationComplexity.LOW: 0.98,
    RemediationComplexity.MEDIUM: 1.00,
    RemediationComplexity.HIGH: 1.05,
    RemediationComplexity.EXTREME: 1.10,
}

#: Per-domain aggregate weights for the overall posture score; MUST sum to 1.0.
DEFAULT_AGGREGATE_WEIGHTS: Mapping[ScoreKind, float] = {
    ScoreKind.IDENTITY: 0.30,
    ScoreKind.AZURE_EXPOSURE: 0.25,
    ScoreKind.DEVICE: 0.15,
    ScoreKind.M365_COMPLIANCE: 0.15,
    ScoreKind.THREAT_EXPOSURE: 0.15,
    # ScoreKind.OVERALL is the *output*; never appears in the weight map.
}

#: Score band thresholds (posture-direction: higher = better).
DEFAULT_BAND_THRESHOLDS: Mapping[str, int] = {
    # band         : minimum value (inclusive)
    "excellent": 90,
    "strong": 75,
    "moderate": 60,
    "weak": 40,
    "critical": 0,
}


# ---------------------------------------------------------------------------
# WeightProfile model
# ---------------------------------------------------------------------------


class WeightProfile(BaseModel):
    """Mutable, versioned bag of scoring weights.

    Instances are normally built via ``WeightProfile.default()`` and then
    perturbed by named policies in ``policy.py``.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Severity & factors
    severity_base: dict[Severity, float] = Field(default_factory=lambda: dict(DEFAULT_SEVERITY_BASE))
    exploitability: dict[Exploitability, float] = Field(
        default_factory=lambda: dict(DEFAULT_EXPLOITABILITY)
    )
    exposure: dict[ExposureLevel, float] = Field(default_factory=lambda: dict(DEFAULT_EXPOSURE))
    business_impact_criticality: dict[Criticality, float] = Field(
        default_factory=lambda: dict(DEFAULT_BUSINESS_IMPACT_CRITICALITY)
    )
    business_impact_data: dict[DataClassification | None, float] = Field(
        default_factory=lambda: dict(DEFAULT_BUSINESS_IMPACT_DATA)
    )
    framework_weights: dict[str, float] = Field(
        default_factory=lambda: dict(DEFAULT_FRAMEWORK_WEIGHTS)
    )
    audit_horizon_boost: list[tuple[int, float]] = Field(
        default_factory=lambda: list(DEFAULT_AUDIT_HORIZON_BOOST)
    )

    campaign_proximity_base: float = Field(default=DEFAULT_CAMPAIGN_PROXIMITY_BASE, gt=0.0)
    campaign_proximity_per_hit: float = Field(default=DEFAULT_CAMPAIGN_PROXIMITY_PER_HIT, ge=0.0)
    campaign_proximity_max: float = Field(default=DEFAULT_CAMPAIGN_PROXIMITY_MAX, gt=0.0)
    campaign_kev_boost: float = Field(default=DEFAULT_CAMPAIGN_KEV_BOOST, gt=0.0)
    campaign_active_link_boost: float = Field(default=DEFAULT_CAMPAIGN_ACTIVE_LINK_BOOST, gt=0.0)

    confidence_min: float = Field(default=DEFAULT_CONFIDENCE_MIN, gt=0.0)
    confidence_max: float = Field(default=DEFAULT_CONFIDENCE_MAX, gt=0.0)

    detection_min: float = Field(default=DEFAULT_DETECTION_MIN, gt=0.0)
    detection_max: float = Field(default=DEFAULT_DETECTION_MAX, gt=0.0)

    remediation_complexity: dict[RemediationComplexity, float] = Field(
        default_factory=lambda: dict(DEFAULT_REMEDIATION_COMPLEXITY)
    )

    aggregate: dict[ScoreKind, float] = Field(default_factory=lambda: dict(DEFAULT_AGGREGATE_WEIGHTS))
    band_thresholds: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_BAND_THRESHOLDS))

    # ---------------------------------------------------------------- helpers

    @classmethod
    def default(cls) -> "WeightProfile":
        """Return a fresh profile pre-populated with the module defaults."""
        return cls()

    @field_validator("aggregate")
    @classmethod
    def _aggregate_must_sum_to_one(
        cls, value: dict[ScoreKind, float]
    ) -> dict[ScoreKind, float]:
        total = sum(value.values())
        if not 0.999 <= total <= 1.001:
            raise RiskConfigError(
                "aggregate weights must sum to 1.0",
                context={"sum": total, "weights": {k.value: v for k, v in value.items()}},
            )
        return value

    @field_validator("confidence_min", "detection_min")
    @classmethod
    def _min_in_unit_interval(cls, value: float) -> float:
        if not 0.0 < value <= 1.0:
            raise RiskConfigError("min factor must be in (0, 1]", context={"value": value})
        return value

    @field_validator("confidence_max", "detection_max")
    @classmethod
    def _max_positive(cls, value: float) -> float:
        if value <= 0.0:
            raise RiskConfigError("max factor must be positive", context={"value": value})
        return value
