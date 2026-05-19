"""Finding models — the central security/compliance artifact.

A Finding is a normalized, framework-mapped security/compliance gap detected
against an asset. The platform's posture score, executive narrative, remediation
backlog, and audit evidence pack all derive from Findings.

Future work (Phase 1+):
  * Persist current state in Azure SQL (``findings`` table) with row-level
    security keyed on ``tenant_id`` (docs/SCHEMA_DESIGN.md § 4.1).
  * Append every evaluation to ``findings_history`` for trend analysis.
  * Persist raw evidence to ADLS Gen2 (``finding.evidence_blob_uri``).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import Field, HttpUrl

from app.models.common import AzureLensModel, TenantScoped


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class Exploitability(str, Enum):
    """How exploitable the underlying issue is in the wild."""

    NONE = "none"
    THEORETICAL = "theoretical"
    POC = "poc"
    ACTIVE = "active"


class MitreTactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics (Cloud-relevant subset highlighted)."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CampaignLinkRef(AzureLensModel):
    """Lightweight pointer from a finding to a live campaign correlation hit."""

    campaign_id: str
    name: str
    source: str = Field(..., description="TI source, e.g. 'defender_ti', 'sentinel_ti'.")
    confidence: int = Field(..., ge=0, le=100)


class RemediationSummary(AzureLensModel):
    """Inline remediation reference for quick reads (full templates live in services/remediation)."""

    template_id: str
    title: str
    estimated_minutes: int | None = Field(default=None, ge=0)
    risk_reduction_estimate: int | None = Field(default=None, ge=0, le=100)
    docs_url: HttpUrl | None = Field(default=None)


class Finding(TenantScoped):
    """Normalized, framework-mapped security/compliance finding."""

    id: UUID = Field(..., description="Stable internal finding id.")
    finding_type: str = Field(
        ...,
        description=(
            "Stable, dotted finding-type id, e.g. ``identity.mfa.privileged.missing`` "
            "or ``azure.storage.public_access``."
        ),
    )
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(..., min_length=1, max_length=5000)

    severity: Severity = Field(default=Severity.MEDIUM)
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    exploitability: Exploitability = Field(default=Exploitability.NONE)

    asset_id: str = Field(..., description="Asset.id this finding is attached to.")

    # MITRE — techniques and tactics
    mitre_tactics: list[MitreTactic] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique ids, e.g. ['T1078', 'T1556.001'].",
    )

    # Multi-framework mapping; full shape in compliance.FrameworkMappings
    framework_mappings: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Framework→control mapping, e.g. "
            "``{'cis_azure': ['1.1.1'], 'nist_csf': ['PR.AC-1']}``. "
            "See app.models.compliance.FrameworkMappings for the strict shape."
        ),
    )

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    campaign_links: list[CampaignLinkRef] = Field(default_factory=list)
    remediation: RemediationSummary | None = Field(default=None)

    first_seen_at: datetime
    last_seen_at: datetime
    last_evaluated_at: datetime

    evidence_blob_uri: str | None = Field(
        default=None,
        description="ADLS Gen2 URI of the raw evidence snapshot for this evaluation.",
    )

    acknowledged_by: UUID | None = Field(default=None)
    acknowledged_at: datetime | None = Field(default=None)
    suppression_reason: str | None = Field(default=None, max_length=1000)

    source_scanner: str = Field(
        ..., description="Producing scanner: 'scanner-azure', 'scanner-m365', ..."
    )
    schema_version: int = Field(default=1, ge=1)


class FindingSummary(AzureLensModel):
    """Compact projection for list endpoints and dashboards."""

    id: UUID
    tenant_id: UUID
    title: str
    finding_type: str
    severity: Severity
    status: FindingStatus
    risk_score: float = Field(..., ge=0.0, le=100.0)
    asset_id: str
    last_seen_at: datetime


class FindingAcknowledgeRequest(AzureLensModel):
    """Body for ``POST /findings/{id}/acknowledge``."""

    note: str | None = Field(default=None, max_length=1000)
    suppress_until: datetime | None = Field(
        default=None,
        description="If set, treat as suppression with an expiry; otherwise plain acknowledgement.",
    )


class RawFinding(TenantScoped):
    """Envelope emitted by scanners to the ``finding.raw`` Service Bus topic.

    The compliance engine consumes RawFindings, applies framework mappings,
    deduplicates, and produces the persisted ``Finding``.
    """

    correlation_id: str = Field(..., description="W3C traceparent for end-to-end tracing.")
    asset_id: str
    finding_type: str
    title: str
    description: str
    severity_hint: Severity = Field(default=Severity.MEDIUM)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_blob_uri: str | None = Field(default=None)
    detected_at: datetime
    source_scanner: str
    schema_version: int = Field(default=1, ge=1)
    # Free-form metadata; scanners include scanner-specific fields here.
    metadata: dict[str, Any] = Field(default_factory=dict)
