"""AI-engine wire contracts (Pydantic v2).

Everything that crosses the AI-engine boundary lives here:

  * AI analysis request + response,
  * audience- and kind-specific structured outputs (executive summary,
    finding explanation, technical remediation, compliance impact,
    campaign exposure, auditor evidence summary),
  * grounded evidence items (the only ingredient the AI may use),
  * report-generation request + sections,
  * remediation recommendations + steps,
  * prompt safety decision.

Enums mirror the canonical wire enums in ``apps/api/app/models/*`` so
outputs flow into the persistence layer without translation. When
``packages/shared-types`` lands, these local enums will be replaced by
re-exports.

Multi-tenant invariant: every request and every produced object carries
``tenant_id``; the safety + grounding layers re-check it. See
docs/PROMPT_SAFETY_MODEL.md.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


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
# Mirrored enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreBand(str, Enum):
    CRITICAL = "critical"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    EXCELLENT = "excellent"


class RemediationStepKind(str, Enum):
    AZURE_CLI = "azure_cli"
    POWERSHELL = "powershell"
    MS_GRAPH = "ms_graph"
    AZURE_POLICY = "azure_policy"
    DOC_LINK = "doc_link"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# AI-engine local enums
# ---------------------------------------------------------------------------


class AnalysisKind(str, Enum):
    """What kind of analysis the AI engine has been asked to produce."""

    EXECUTIVE_SUMMARY = "executive_summary"
    FINDING_EXPLANATION = "finding_explanation"
    REMEDIATION_GUIDANCE = "remediation_guidance"
    COMPLIANCE_IMPACT = "compliance_impact"
    CAMPAIGN_EXPOSURE = "campaign_exposure"
    AUDITOR_EVIDENCE = "auditor_evidence"
    COPILOT_QA = "copilot_qa"


class Audience(str, Enum):
    """Reading audience; selects tone, vocabulary, and depth."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE_OFFICER = "compliance_officer"
    SOC_ANALYST = "soc_analyst"
    AUDITOR = "auditor"
    IT_MANAGER = "it_manager"
    GENERAL = "general"


class OutputFormat(str, Enum):
    MARKDOWN = "markdown"
    PLAIN_TEXT = "plain_text"
    JSON = "json"
    STRUCTURED = "structured"


class ApprovalRequirement(str, Enum):
    """How much human gating a remediation step needs."""

    NONE = "none"                       # read-only / informational
    SINGLE_APPROVER = "single_approver"
    DUAL_CONTROL = "dual_control"
    CHANGE_ADVISORY = "change_advisory"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SafetyDecisionOutcome(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class SafetyRiskCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    PII_EXPOSURE = "pii_exposure"
    SECRET_EXPOSURE = "secret_exposure"
    CROSS_TENANT_REFERENCE = "cross_tenant_reference"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    HALLUCINATION_RISK = "hallucination_risk"
    SENSITIVE_DATA = "sensitive_data"
    UNGROUNDED_ASSERTION = "ungrounded_assertion"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"


class EvidenceType(str, Enum):
    FINDING = "finding"
    ASSET = "asset"
    SCORE = "score"
    EXPLAINABILITY_REASON = "explainability_reason"
    TI_CAMPAIGN = "ti_campaign"
    TI_INDICATOR = "ti_indicator"
    TI_VULNERABILITY = "ti_vulnerability"
    TI_ATTACK_PATTERN = "ti_attack_pattern"
    FRAMEWORK_CONTROL = "framework_control"
    REMEDIATION_TEMPLATE = "remediation_template"


class ReportGenerationStatus(str, Enum):
    DRAFT = "draft"
    COMPLETE = "complete"
    FAILED = "failed"
    PARTIAL = "partial"


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------


class GroundedEvidenceItem(_Model):
    """One piece of evidence the AI engine is permitted to draw from.

    Every claim in any AI-generated output MUST reference at least one
    ``GroundedEvidenceItem`` via its ``citation_token``. The grounding
    validator enforces this; see ``ai_engine.grounding``.
    """

    evidence_id: str = Field(
        ...,
        description=(
            "Stable, tenant-scoped id, e.g. 'finding::<uuid>' or 'ti_campaign::<id>'. "
            "Used to look up the source record in audits."
        ),
        max_length=200,
    )
    evidence_type: EvidenceType
    ref_id: str = Field(..., description="Id of the underlying record.", max_length=200)
    summary: str = Field(
        ..., min_length=1, max_length=2000, description="Short structured summary safe to render."
    )
    citation_token: str = Field(
        ...,
        description="Opaque token the AI must include to cite this item, e.g. '[[evi:1]]'.",
        pattern=r"^\[\[evi:[A-Za-z0-9_\-]{1,40}\]\]$",
    )
    redacted_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Small PII-redacted structured payload the AI may read.",
    )
    source_uri: str | None = Field(
        default=None,
        description="Audit-trail URI (internal); never surfaced to end users.",
        max_length=500,
    )


# ---------------------------------------------------------------------------
# Model deployment reference
# ---------------------------------------------------------------------------


class ModelDeploymentRef(_Model):
    """Identifies which Azure OpenAI deployment produced (or would produce) a response."""

    deployment_name: str = Field(..., max_length=200)
    api_version: str = Field(default="unspecified", max_length=40)
    region: str | None = Field(default=None, max_length=40)
    ptu: bool = Field(
        default=False,
        description="Whether the deployment uses Provisioned Throughput Units (Enterprise tier).",
    )


# ---------------------------------------------------------------------------
# AI request / response
# ---------------------------------------------------------------------------


class AIAnalysisRequest(_Model):
    """Request to the AI engine.

    The orchestrator builds this from a Service Bus envelope or a copilot
    HTTP call. ``evidence`` is pre-built by the caller; the engine never
    fetches additional data implicitly.
    """

    request_id: UUID
    tenant_id: UUID
    correlation_id: str = Field(..., min_length=1)
    kind: AnalysisKind
    audience: Audience = Field(default=Audience.GENERAL)
    output_format: OutputFormat = Field(default=OutputFormat.MARKDOWN)
    template_id: str = Field(..., max_length=120)
    template_version: str | None = Field(default=None, max_length=40)
    evidence: list[GroundedEvidenceItem] = Field(default_factory=list)
    locale: str = Field(default="en", max_length=10)
    max_output_tokens: int = Field(default=800, ge=64, le=4096)
    requested_by: UUID | None = Field(default=None)
    requested_at: datetime
    # Free-form parameters specific to a template (e.g. desired bullet count).
    parameters: dict[str, Any] = Field(default_factory=dict)


class PromptSafetyDecision(_Model):
    """Outcome of the safety layer for one analysis call."""

    decision_id: UUID
    outcome: SafetyDecisionOutcome
    risks: list[SafetyRiskCategory] = Field(default_factory=list)
    redactions_applied: list[str] = Field(default_factory=list)
    detail: str = Field(default="", max_length=2000)
    evaluated_at: datetime


class AIAnalysisResponse(_Model):
    """Generic response from the AI engine.

    For analysis kinds that have a strict structured shape (executive
    summary, finding explanation, etc.), the structured form lives in
    ``structured_output`` and the rendered markdown lives in ``output``.
    """

    response_id: UUID
    request_id: UUID
    tenant_id: UUID
    correlation_id: str
    kind: AnalysisKind
    template_id: str
    template_version: str | None = Field(default=None)
    model_deployment: ModelDeploymentRef | None = Field(
        default=None, description="None when the response is deterministic-only (no LLM run)."
    )
    output: str = Field(default="", description="Rendered text in the requested output_format.")
    structured_output: dict[str, Any] | None = Field(default=None)
    citations: list[str] = Field(
        default_factory=list,
        description="citation_token values referenced by the output.",
    )
    safety_decision: PromptSafetyDecision
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    generated_at: datetime
    generated_by_ai: bool = Field(
        default=False,
        description=(
            "False when the response is pure deterministic rendering (this branch); "
            "True once Azure OpenAI is wired in Phase 5."
        ),
    )


# ---------------------------------------------------------------------------
# Structured outputs (per AnalysisKind)
# ---------------------------------------------------------------------------


class ExecutiveSummary(_Model):
    title: str = Field(..., min_length=1, max_length=200)
    overview: str = Field(..., min_length=1, max_length=4000)
    top_risks: list[str] = Field(default_factory=list, max_length=10)
    prioritized_actions: list[str] = Field(default_factory=list, max_length=10)
    citations: list[str] = Field(default_factory=list)


class FindingExplanation(_Model):
    finding_id: UUID
    title: str = Field(..., min_length=1, max_length=300)
    business_impact_paragraph: str = Field(..., min_length=1, max_length=2000)
    technical_paragraph: str = Field(..., min_length=1, max_length=4000)
    mitre_mapping_summary: str | None = Field(default=None, max_length=1500)
    compliance_summary: str | None = Field(default=None, max_length=1500)
    citations: list[str] = Field(default_factory=list)


class ComplianceImpactExplanation(_Model):
    finding_id: UUID
    mapped_frameworks: list[str] = Field(default_factory=list)
    per_framework_impact: dict[str, str] = Field(default_factory=dict)
    audit_horizon_note: str | None = Field(default=None, max_length=1000)
    citations: list[str] = Field(default_factory=list)


class CampaignExposureExplanation(_Model):
    tenant_id: UUID
    campaign_id: str = Field(..., max_length=200)
    campaign_name: str = Field(..., max_length=300)
    exposure_summary: str = Field(..., min_length=1, max_length=4000)
    mapped_assets_count: int = Field(default=0, ge=0)
    mapped_findings_count: int = Field(default=0, ge=0)
    citations: list[str] = Field(default_factory=list)


class AuditorEvidenceSummary(_Model):
    tenant_id: UUID
    framework: str = Field(..., max_length=80)
    audit_window: str | None = Field(default=None, max_length=80)
    evidence_summary: str = Field(..., min_length=1, max_length=4000)
    evidence_finding_count: int = Field(default=0, ge=0)
    citations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Remediation contracts
# ---------------------------------------------------------------------------


class RemediationStep(_Model):
    """One executable step inside a remediation recommendation."""

    kind: RemediationStepKind
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(..., min_length=1, max_length=2000)
    code: str | None = Field(
        default=None,
        description="CLI / PS / Graph body / Policy JSON. Required for executable kinds.",
        max_length=10000,
    )
    docs_url: HttpUrl | None = Field(default=None)
    approval_required: ApprovalRequirement = Field(default=ApprovalRequirement.SINGLE_APPROVER)
    estimated_minutes: int | None = Field(default=None, ge=0)


class RemediationRecommendation(_Model):
    """Audience-shaped remediation; deterministic by default, optionally AI-rewritten."""

    recommendation_id: UUID
    tenant_id: UUID
    finding_id: UUID | None = Field(default=None)
    audience: Audience
    title: str = Field(..., min_length=1, max_length=300)
    summary: str = Field(..., min_length=1, max_length=4000)
    steps: list[RemediationStep] = Field(default_factory=list)
    rollback: list[RemediationStep] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    estimated_minutes: int | None = Field(default=None, ge=0)
    risk_reduction_estimate: int | None = Field(default=None, ge=0, le=100)
    approval_required: ApprovalRequirement = Field(default=ApprovalRequirement.SINGLE_APPROVER)
    citations: list[str] = Field(default_factory=list)
    ai_enhanced: bool = Field(default=False)
    generated_at: datetime


class TechnicalRemediation(_Model):
    """Technical-audience structured remediation output (one of the AnalysisKind shapes)."""

    finding_id: UUID | None = Field(default=None)
    title: str = Field(..., min_length=1, max_length=300)
    summary: str = Field(..., min_length=1, max_length=4000)
    steps: list[RemediationStep] = Field(default_factory=list)
    rollback: list[RemediationStep] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Report generation contracts
# ---------------------------------------------------------------------------


class ReportSection(_Model):
    """One section of a generated report.

    The deterministic baseline body is always populated; ``ai_enhanced``
    flips to True once an AI summarizer has rewritten / extended it.
    """

    section_id: str = Field(
        ...,
        description="Stable section id, e.g. 'overview', 'identity', 'threat_exposure'.",
        pattern=r"^[a-z][a-z0-9_]{0,60}$",
    )
    title: str = Field(..., min_length=1, max_length=200)
    order: int = Field(..., ge=0)
    body: str = Field(..., min_length=0, max_length=20000, description="Markdown.")
    ai_enhanced: bool = Field(default=False)
    citations: list[str] = Field(default_factory=list)
    structured_data: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime


class ReportGenerationRequest(_Model):
    request_id: UUID
    tenant_id: UUID
    correlation_id: str = Field(..., min_length=1)
    report_kind: str = Field(
        ...,
        description="ReportType enum value (executive_pdf | technical_pdf | audit_evidence_zip | board_pptx | csv_export | json_export).",
        max_length=80,
    )
    title: str | None = Field(default=None, max_length=300)
    audience: Audience = Field(default=Audience.EXECUTIVE)
    locale: str = Field(default="en", max_length=10)
    sections_requested: list[str] = Field(
        default_factory=lambda: [
            "overview",
            "posture",
            "identity",
            "device",
            "compliance",
            "threat_exposure",
            "prioritized_remediations",
            "evidence",
        ]
    )
    parameters: dict[str, Any] = Field(default_factory=dict)
    requested_by: UUID | None = Field(default=None)
    requested_at: datetime


class ReportGenerationResult(_Model):
    result_id: UUID
    request_id: UUID
    tenant_id: UUID
    title: str = Field(..., min_length=1, max_length=300)
    sections: list[ReportSection] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    status: ReportGenerationStatus = Field(default=ReportGenerationStatus.DRAFT)
    error_summary: str | None = Field(default=None, max_length=2000)
    generated_at: datetime


# ---------------------------------------------------------------------------
# Audit log shape (referenced by safety layer)
# ---------------------------------------------------------------------------


class AIAuditEntry(_Model):
    """Single audit record for one analysis call.

    Persisted in Cosmos ``ai_prompts`` per docs/SCHEMA_DESIGN.md § 9.1
    (with PII redacted by the safety layer before persistence).
    """

    event_id: UUID
    tenant_id: UUID
    request_id: UUID
    response_id: UUID | None = Field(default=None)
    template_id: str
    template_version: str | None = Field(default=None)
    model_deployment: ModelDeploymentRef | None = Field(default=None)
    prompt_redacted: str = Field(default="", max_length=20000)
    response_redacted: str = Field(default="", max_length=20000)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    safety_decision: PromptSafetyDecision | None = Field(default=None)
    correlation_id: str
    user_oid: UUID | None = Field(default=None)
    created_at: datetime
    ttl_days: int = Field(default=365, ge=1, le=2555)
