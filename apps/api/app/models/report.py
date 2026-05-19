"""Report & remediation-action models.

Reports are immutable artifacts produced by ``services/reporting``:
executive PDFs, technical PDFs, audit-evidence ZIPs, board PPTX decks, CSV/JSON
exports. All reports are signed (``sha256`` + signing key id) and stored in
immutable Blob containers per tenant.

Future work (Phase 1 → Phase 3):
  * Reporting service renders templates with Headless Chromium / pptxgenjs.
  * Audit-evidence pack format reviewed by an external auditor before GA.
  * Power BI Embedded datasets in addition to static artifacts.
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


class ReportType(str, Enum):
    EXECUTIVE_PDF = "executive_pdf"
    TECHNICAL_PDF = "technical_pdf"
    AUDIT_EVIDENCE_ZIP = "audit_evidence_zip"
    BOARD_PPTX = "board_pptx"
    CSV_EXPORT = "csv_export"
    JSON_EXPORT = "json_export"


class ReportStatus(str, Enum):
    REQUESTED = "requested"
    QUEUED = "queued"
    RENDERING = "rendering"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"


class RemediationStatus(str, Enum):
    """Lifecycle of a remediation action (manual or, when enabled, one-click)."""

    NOT_STARTED = "not_started"
    SUGGESTED = "suggested"
    REQUESTED = "requested"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RemediationStepKind(str, Enum):
    """Categories of executable remediation steps surfaced in the UI."""

    AZURE_CLI = "azure_cli"
    POWERSHELL = "powershell"
    MS_GRAPH = "ms_graph"
    AZURE_POLICY = "azure_policy"
    DOC_LINK = "doc_link"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------


class ReportRequest(AzureLensModel):
    """Body for ``POST /reports``."""

    type: ReportType
    title: str | None = Field(default=None, max_length=300)
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Type-specific parameters, e.g. {'framework': 'cis_azure'} for a compliance "
            "report, or {'asset_id': '...'} for a targeted technical report."
        ),
    )
    # TODO(phase-3): include `recipients: list[EmailStr]` for direct email delivery.


class Report(TenantScoped):
    """A generated report artifact."""

    id: UUID
    type: ReportType
    status: ReportStatus = Field(default=ReportStatus.REQUESTED)
    title: str | None = Field(default=None, max_length=300)
    parameters: dict[str, Any] = Field(default_factory=dict)

    blob_uri: HttpUrl | None = Field(
        default=None,
        description="Signed, expiring URL for download. Available when status is READY.",
    )
    sha256: str | None = Field(
        default=None,
        description="Content hash of the produced artifact.",
        min_length=64,
        max_length=64,
    )
    signed_by: str | None = Field(
        default=None,
        description="Signing key identifier (KV key version) used to sign the SHA.",
    )

    requested_by: UUID
    requested_at: datetime
    generated_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    error_summary: str | None = Field(default=None, max_length=2000)
    schema_version: int = Field(default=1, ge=1)


# ---------------------------------------------------------------------------
# Remediation models (subset surfaced via the reports/findings APIs)
# ---------------------------------------------------------------------------


class RemediationStep(AzureLensModel):
    """One executable step inside a remediation template."""

    kind: RemediationStepKind
    title: str = Field(..., min_length=1, max_length=300)
    code: str | None = Field(
        default=None,
        description="Snippet (CLI / PS / Graph body / Policy JSON). Required for executable kinds.",
        max_length=10000,
    )
    docs_url: HttpUrl | None = Field(default=None)


class RemediationTemplate(AzureLensModel):
    """A reusable remediation template (full library lives in services/remediation)."""

    template_id: str
    title: str
    version: int = Field(default=1, ge=1)
    applies_to_finding_types: list[str] = Field(default_factory=list)
    steps: list[RemediationStep] = Field(default_factory=list)
    rollback_steps: list[RemediationStep] = Field(default_factory=list)
    estimated_minutes: int | None = Field(default=None, ge=0)
    risk_reduction_estimate: int | None = Field(default=None, ge=0, le=100)


class RemediationAction(TenantScoped):
    """Auditable record of a remediation action requested/executed against a finding."""

    id: UUID
    finding_id: UUID
    template_id: str
    status: RemediationStatus = Field(default=RemediationStatus.NOT_STARTED)
    requested_by: UUID
    approved_by: UUID | None = Field(default=None, description="4-eyes approver if required.")
    requested_at: datetime
    started_at: datetime | None = Field(default=None)
    ended_at: datetime | None = Field(default=None)
    diff_before: dict[str, Any] = Field(default_factory=dict)
    diff_after: dict[str, Any] = Field(default_factory=dict)
    error_summary: str | None = Field(default=None, max_length=2000)
