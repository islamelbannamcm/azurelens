"""AzureLens Risk Scoring engine.

Deterministic, bounded, explainable scoring (introduced in Phase 5):

  risk_engine.contracts        Pydantic v2 wire shapes (inputs, contexts, outputs, reasons)
  risk_engine.errors           Exception hierarchy
  risk_engine.weights          WeightProfile + default tables
  risk_engine.policy           5 named ScoringPolicy profiles + registry
  risk_engine.formulas         Pure scoring formulas (factor + finding + domain + overall)
  risk_engine.calculator       RiskCalculator (entry point used by the worker)
  risk_engine.explainability   Deterministic rule-based reason generation

Nothing in this package performs network calls, SDK calls, persistence,
or LLM inference. See docs/RISK_SCORING_MODEL.md.
"""

from __future__ import annotations

from risk_engine.calculator import RiskCalculator
from risk_engine.contracts import (
    AssetContext,
    BusinessImpactContext,
    ComplianceContext,
    Criticality,
    DataClassification,
    DomainScoreInput,
    DomainScoreOutput,
    Exploitability,
    ExplainabilityReason,
    ExplainabilityReasonCategory,
    ExposureLevel,
    FindingScoreInput,
    OverallScoreInput,
    OverallScoreOutput,
    RemediationComplexity,
    RiskScoreOutput,
    ScoreBand,
    ScoreBreakdown,
    ScoreKind,
    ScoringDecision,
    ScoringPolicyRef,
    Severity,
    ThreatIntelContext,
)
from risk_engine.errors import (
    BoundsViolationError,
    ExplainabilityError,
    RiskConfigError,
    RiskEngineError,
    RiskInputError,
    RiskPolicyError,
)
from risk_engine.explainability import (
    explain_domain_score,
    explain_finding_score,
    explain_overall_score,
)
from risk_engine.formulas import (
    base_severity_score,
    business_impact_factor,
    campaign_proximity_factor,
    clamp,
    classify_band,
    classify_finding_band,
    compliance_weight,
    compute_domain_posture_score,
    compute_finding_risk_score,
    compute_overall_posture_score,
    confidence_factor,
    detection_coverage_factor,
    exploitability_factor,
    exposure_factor,
    remediation_complexity_factor,
    round_score,
    to_int_score,
)
from risk_engine.policy import (
    ScoringPolicy,
    compliance_focused_policy,
    default_policy,
    executive_policy,
    get_policy,
    identity_focused_policy,
    list_policies,
    register_policy,
    threat_focused_policy,
)
from risk_engine.weights import WeightProfile

__all__ = [
    # calculator
    "RiskCalculator",
    # contracts
    "AssetContext",
    "BusinessImpactContext",
    "ComplianceContext",
    "Criticality",
    "DataClassification",
    "DomainScoreInput",
    "DomainScoreOutput",
    "Exploitability",
    "ExplainabilityReason",
    "ExplainabilityReasonCategory",
    "ExposureLevel",
    "FindingScoreInput",
    "OverallScoreInput",
    "OverallScoreOutput",
    "RemediationComplexity",
    "RiskScoreOutput",
    "ScoreBand",
    "ScoreBreakdown",
    "ScoreKind",
    "ScoringDecision",
    "ScoringPolicyRef",
    "Severity",
    "ThreatIntelContext",
    # errors
    "BoundsViolationError",
    "ExplainabilityError",
    "RiskConfigError",
    "RiskEngineError",
    "RiskInputError",
    "RiskPolicyError",
    # explainability
    "explain_domain_score",
    "explain_finding_score",
    "explain_overall_score",
    # formulas
    "base_severity_score",
    "business_impact_factor",
    "campaign_proximity_factor",
    "clamp",
    "classify_band",
    "classify_finding_band",
    "compliance_weight",
    "compute_domain_posture_score",
    "compute_finding_risk_score",
    "compute_overall_posture_score",
    "confidence_factor",
    "detection_coverage_factor",
    "exploitability_factor",
    "exposure_factor",
    "remediation_complexity_factor",
    "round_score",
    "to_int_score",
    # policy
    "ScoringPolicy",
    "compliance_focused_policy",
    "default_policy",
    "executive_policy",
    "get_policy",
    "identity_focused_policy",
    "list_policies",
    "register_policy",
    "threat_focused_policy",
    # weights
    "WeightProfile",
]
