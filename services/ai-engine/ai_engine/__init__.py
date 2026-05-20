"""AzureLens AI Analysis Engine.

Phase 6 introduces deterministic contracts, prompt templates, safety
controls, grounding enforcement, a remediation advisor, and a report
generator. Azure OpenAI itself is wired in Phase 5 (per
``docs/ROADMAP.md``) — until then, every "AI" output in this package is
produced by deterministic, evidence-bound code paths.

Module map:

  ai_engine.contracts         Pydantic v2 wire shapes (request, response,
                              structured outputs, remediation, report, safety)
  ai_engine.errors            Exception hierarchy
  ai_engine.safety            SafetyEvaluator (input + output, rule-based)
  ai_engine.grounding         GroundingValidator + EvidenceBuilder
  ai_engine.prompt_templates  Six built-in prompt templates with safety preamble
  ai_engine.remediation_advisor  Deterministic remediation library + AI-enhance hook
  ai_engine.report_generator  Deterministic report sections + AI-enhance hooks

Nothing in this package performs network calls, SDK calls, or token
acquisition in this branch. See ``docs/AI_ANALYSIS_ENGINE.md`` and
``docs/PROMPT_SAFETY_MODEL.md``.
"""

from __future__ import annotations

from ai_engine.contracts import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIAuditEntry,
    AnalysisKind,
    ApprovalRequirement,
    Audience,
    AuditorEvidenceSummary,
    CampaignExposureExplanation,
    ComplianceImpactExplanation,
    ConfidenceLevel,
    EvidenceType,
    ExecutiveSummary,
    FindingExplanation,
    GroundedEvidenceItem,
    ModelDeploymentRef,
    OutputFormat,
    PromptSafetyDecision,
    RemediationRecommendation,
    RemediationStep,
    RemediationStepKind,
    ReportGenerationRequest,
    ReportGenerationResult,
    ReportGenerationStatus,
    ReportSection,
    SafetyDecisionOutcome,
    SafetyRiskCategory,
    ScoreBand,
    Severity,
    TechnicalRemediation,
)
from ai_engine.errors import (
    AIConfigError,
    AIContentFilteredError,
    AIEngineError,
    AIGroundingError,
    AIModelUnavailableError,
    AIPromptError,
    AIQuotaExceededError,
    AISafetyError,
    PromptInjectionDetectedError,
    TenantIsolationError,
)
from ai_engine.grounding import (
    CITATION_PATTERN,
    ENTITY_LIKE_PATTERN,
    EvidenceBuilder,
    GroundingValidationResult,
    GroundingValidator,
)
from ai_engine.prompt_templates import (
    AUDITOR_EVIDENCE_V1,
    CAMPAIGN_EXPOSURE_V1,
    COMPLIANCE_IMPACT_V1,
    EXEC_SUMMARY_V1,
    FINDING_EXPLANATION_V1,
    PromptTemplate,
    REMEDIATION_GUIDANCE_V1,
    SAFETY_PREAMBLE,
    get_all_templates_by_kind,
    get_template,
    list_templates,
    register_template,
)
from ai_engine.remediation_advisor import RemediationAdvisor
from ai_engine.report_generator import (
    CampaignSnippet,
    FindingSnippet,
    ReportGenerator,
    ReportInputs,
    ScoreSnippet,
)
from ai_engine.safety import SafetyEvaluator

__all__ = [
    # contracts — analysis
    "AIAnalysisRequest",
    "AIAnalysisResponse",
    "AIAuditEntry",
    "AnalysisKind",
    "ApprovalRequirement",
    "Audience",
    "AuditorEvidenceSummary",
    "CampaignExposureExplanation",
    "ComplianceImpactExplanation",
    "ConfidenceLevel",
    "EvidenceType",
    "ExecutiveSummary",
    "FindingExplanation",
    "GroundedEvidenceItem",
    "ModelDeploymentRef",
    "OutputFormat",
    "PromptSafetyDecision",
    "RemediationRecommendation",
    "RemediationStep",
    "RemediationStepKind",
    "ReportGenerationRequest",
    "ReportGenerationResult",
    "ReportGenerationStatus",
    "ReportSection",
    "SafetyDecisionOutcome",
    "SafetyRiskCategory",
    "ScoreBand",
    "Severity",
    "TechnicalRemediation",
    # errors
    "AIConfigError",
    "AIContentFilteredError",
    "AIEngineError",
    "AIGroundingError",
    "AIModelUnavailableError",
    "AIPromptError",
    "AIQuotaExceededError",
    "AISafetyError",
    "PromptInjectionDetectedError",
    "TenantIsolationError",
    # grounding
    "CITATION_PATTERN",
    "ENTITY_LIKE_PATTERN",
    "EvidenceBuilder",
    "GroundingValidationResult",
    "GroundingValidator",
    # prompt templates
    "AUDITOR_EVIDENCE_V1",
    "CAMPAIGN_EXPOSURE_V1",
    "COMPLIANCE_IMPACT_V1",
    "EXEC_SUMMARY_V1",
    "FINDING_EXPLANATION_V1",
    "PromptTemplate",
    "REMEDIATION_GUIDANCE_V1",
    "SAFETY_PREAMBLE",
    "get_all_templates_by_kind",
    "get_template",
    "list_templates",
    "register_template",
    # remediation
    "RemediationAdvisor",
    # report
    "CampaignSnippet",
    "FindingSnippet",
    "ReportGenerator",
    "ReportInputs",
    "ScoreSnippet",
    # safety
    "SafetyEvaluator",
]
