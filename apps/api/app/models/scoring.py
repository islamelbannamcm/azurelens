"""Scoring & scan models.

Scores aggregate findings into executive-grade numbers. The scoring formula
is owned by ``services/risk-engine``; this module only defines the *result*
shapes consumed by the API and dashboards.

Future work (Phase 1+):
  * ``services/risk-engine`` consumes ``finding.normalized`` and
    ``correlation.hit`` events; writes Score rows to Azure SQL.
  * Daily snapshots persisted to ``scores_history`` for trend analysis.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import Field

from app.models.common import AzureLensModel, TenantScoped


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


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


class ScanKind(str, Enum):
    AZURE = "azure"
    M365 = "m365"
    INTUNE = "intune"
    DEFENDER = "defender"
    PURVIEW = "purview"
    FULL = "full"            # composite scan covering all kinds


class ScanTriggerType(str, Enum):
    BOOTSTRAP = "bootstrap"
    SCHEDULED = "scheduled"
    INCREMENTAL = "incremental"
    ON_DEMAND = "on_demand"
    TARGETED = "targeted"


class ScanStatus(str, Enum):
    REQUESTED = "requested"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScoringPolicyRef(AzureLensModel):
    """Pointer to the scoring policy used for a given calculation.

    Policies are versioned in Cosmos DB; recording the version on each score
    makes audits reproducible.
    """

    policy_id: str = Field(default="default", description="Policy identifier.")
    version: int = Field(default=1, ge=1)


class ScoreBreakdown(AzureLensModel):
    """Per-factor contribution to a finding's risk score (for explainability)."""

    base_severity: float = Field(..., ge=0.0)
    exploitability_factor: float = Field(..., gt=0.0)
    exposure_factor: float = Field(..., gt=0.0)
    business_impact_factor: float = Field(..., gt=0.0)
    compliance_weight: float = Field(..., gt=0.0)
    campaign_proximity_factor: float = Field(..., gt=0.0)


class Score(TenantScoped):
    """Per-tenant, per-kind score (current value)."""

    score_kind: ScoreKind
    value: int = Field(..., ge=0, le=100)
    band: ScoreBand
    contributing_finding_ids: list[UUID] = Field(default_factory=list)
    policy: ScoringPolicyRef = Field(default_factory=ScoringPolicyRef)
    calculated_at: datetime


class ScoreSnapshot(TenantScoped):
    """One daily history row in ``scores_history``."""

    score_kind: ScoreKind
    value: int = Field(..., ge=0, le=100)
    band: ScoreBand
    recorded_date: datetime
    policy: ScoringPolicyRef = Field(default_factory=ScoringPolicyRef)


class ScanRequest(AzureLensModel):
    """Body for ``POST /scans``."""

    kinds: list[ScanKind] = Field(default_factory=lambda: [ScanKind.FULL])
    trigger_type: ScanTriggerType = Field(default=ScanTriggerType.ON_DEMAND)
    target_asset_id: str | None = Field(
        default=None,
        description="If set, run a targeted scan against just this asset.",
    )

    # TODO(phase-1): subscription_scope, user_batch_size, retention_override


class ScanSummary(TenantScoped):
    """Status row for one scan run."""

    id: UUID
    kinds: list[ScanKind]
    trigger_type: ScanTriggerType
    status: ScanStatus = Field(default=ScanStatus.REQUESTED)
    requested_at: datetime
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    partitions_total: int | None = Field(default=None, ge=0)
    partitions_completed: int = Field(default=0, ge=0)
    findings_produced: int = Field(default=0, ge=0)
    error_summary: str | None = Field(default=None, max_length=2000)
