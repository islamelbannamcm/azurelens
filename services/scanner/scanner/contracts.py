"""Scanner data contracts (Pydantic v2).

These shapes describe everything that crosses a plugin boundary:

  * what a scan REQUESTS,
  * what a plugin DECLARES (metadata + capabilities + required permissions),
  * what a plugin EMITS (assets + raw findings + errors),
  * what the orchestrator AGGREGATES (per-plugin result + scan summary).

Enums mirror the canonical wire enums in ``apps/api/app/models/`` so emitted
findings can be mapped to the persistence layer without translation. When
``packages/shared-types`` lands (later phase), these local enums will be
replaced by re-exports from that package; keep the string values in sync
in the meantime.

Multi-tenant invariant: every emitted record carries ``tenant_id`` and the
orchestrator validates it against the ``ScanContext.tenant_id``. See
docs/SCHEMA_DESIGN.md § 12.
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
    """Local strict base; mirrors the API's ``AzureLensModel`` configuration."""

    model_config = _MODEL_CONFIG


# ---------------------------------------------------------------------------
# Mirrored enums (must match apps/api/app/models/*)
# ---------------------------------------------------------------------------


class CloudProvider(str, Enum):
    AZURE = "azure"
    M365 = "m365"
    ENTRA_ID = "entra_id"
    INTUNE = "intune"
    DEFENDER_XDR = "defender_xdr"
    PURVIEW = "purview"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanKind(str, Enum):
    AZURE = "azure"
    M365 = "m365"
    INTUNE = "intune"
    DEFENDER = "defender"
    SENTINEL = "sentinel"
    PURVIEW = "purview"
    FULL = "full"


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
# Capability + permission contracts
# ---------------------------------------------------------------------------


class ScannerCapability(str, Enum):
    """Coarse-grained capability tags a plugin advertises.

    The orchestrator uses these to map a ``ScanRequest``'s kinds + scope to
    a set of eligible plugins. New capabilities may be added in MINOR
    versions; consumers MUST tolerate unknown values gracefully.
    """

    # Azure
    AZURE_INVENTORY = "azure.inventory"
    AZURE_NETWORK_POSTURE = "azure.network_posture"
    AZURE_IDENTITY_POSTURE = "azure.identity_posture"
    AZURE_DATA_POSTURE = "azure.data_posture"
    AZURE_POLICY_POSTURE = "azure.policy_posture"

    # Entra ID / M365 identity
    ENTRA_IDENTITY = "entra.identity"
    ENTRA_CONDITIONAL_ACCESS = "entra.conditional_access"
    ENTRA_PRIVILEGED_ACCESS = "entra.privileged_access"
    ENTRA_RISK = "entra.risk"
    ENTRA_APP_CONSENT = "entra.app_consent"

    # M365 collaboration
    M365_COLLABORATION = "m365.collaboration"
    M365_SECURE_SCORE = "m365.secure_score"

    # Intune
    INTUNE_DEVICE_INVENTORY = "intune.device_inventory"
    INTUNE_COMPLIANCE_POSTURE = "intune.compliance_posture"
    INTUNE_CONFIG_POSTURE = "intune.config_posture"

    # Defender
    DEFENDER_RECOMMENDATIONS = "defender.recommendations"
    DEFENDER_SECURE_SCORE = "defender.secure_score"
    DEFENDER_XDR_ALERTS = "defender.xdr_alerts"

    # Sentinel
    SENTINEL_ANALYTICS_POSTURE = "sentinel.analytics_posture"
    SENTINEL_THREAT_INTEL_BRIDGE = "sentinel.threat_intel_bridge"

    # Purview
    PURVIEW_SENSITIVITY = "purview.sensitivity"
    PURVIEW_DLP = "purview.dlp"
    PURVIEW_RETENTION = "purview.retention"


class PermissionGrantType(str, Enum):
    """Where a required permission must be granted."""

    MS_GRAPH_APPLICATION = "ms_graph_application"
    MS_GRAPH_DELEGATED = "ms_graph_delegated"
    AZURE_RBAC = "azure_rbac"
    DEFENDER_API = "defender_api"
    SENTINEL_RBAC = "sentinel_rbac"
    PURVIEW_RBAC = "purview_rbac"


class RequiredPermission(_Model):
    """A single permission the plugin needs to function."""

    grant_type: PermissionGrantType
    name: str = Field(
        ...,
        description="Permission identifier, e.g. 'Directory.Read.All' or 'Reader'.",
        min_length=1,
        max_length=200,
    )
    optional: bool = Field(
        default=False,
        description="If True, the plugin can degrade gracefully without this permission.",
    )
    notes: str | None = Field(default=None, max_length=500)


# ---------------------------------------------------------------------------
# Scanner metadata
# ---------------------------------------------------------------------------


class ScannerMetadata(_Model):
    """Static descriptor each plugin publishes about itself."""

    id: str = Field(
        ...,
        description="Stable plugin id (snake_case), e.g. 'azure_resource_graph'.",
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
    )
    name: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., description="Semantic version of the plugin.")
    provider: CloudProvider
    capabilities: list[ScannerCapability] = Field(default_factory=list)
    supported_asset_kinds: list[str] = Field(
        default_factory=list,
        description="AssetKind enum values this plugin emits (see app.models.asset.AssetKind).",
    )
    required_permissions: list[RequiredPermission] = Field(default_factory=list)
    description: str = Field(default="", max_length=2000)


# ---------------------------------------------------------------------------
# Scan request
# ---------------------------------------------------------------------------


class ScanRequest(_Model):
    """A request to scan a tenant."""

    request_id: UUID
    tenant_id: UUID
    azure_tenant_id: UUID
    kinds: list[ScanKind] = Field(default_factory=lambda: [ScanKind.FULL])
    trigger_type: ScanTriggerType = Field(default=ScanTriggerType.ON_DEMAND)
    requested_by: UUID | None = Field(default=None)
    target_asset_id: str | None = Field(default=None)
    correlation_id: str = Field(..., min_length=1, description="W3C traceparent for tracing.")
    requested_at: datetime
    overrides: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form, scan-kind-specific overrides (e.g. subscription subset).",
    )


# ---------------------------------------------------------------------------
# Scan outputs
# ---------------------------------------------------------------------------


class ScanAssetSnapshot(_Model):
    """Lightweight asset snapshot emitted by a plugin.

    The asset upsert happens in a downstream worker; this envelope is what
    Service Bus topic ``asset.upserted`` will carry in Phase 1.
    """

    tenant_id: UUID
    asset_id: str = Field(..., description="sha256 of canonical asset_uri.")
    asset_uri: str
    asset_kind: str = Field(..., description="AssetKind enum value.")
    provider: CloudProvider
    display_name: str | None = Field(default=None, max_length=400)
    properties: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime
    source: str = Field(..., description="Producing plugin id.")
    schema_version: int = Field(default=1, ge=1)


class ScanFinding(_Model):
    """Raw finding envelope emitted by a plugin.

    Mirrors ``app.models.finding.RawFinding`` (Phase 2). The compliance
    engine consumes these, applies framework mappings, and persists as
    ``Finding`` rows.
    """

    tenant_id: UUID
    correlation_id: str
    asset_id: str
    finding_type: str = Field(
        ...,
        description="Stable dotted id, e.g. 'azure.network.rdp_public_exposed'.",
        pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
    )
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(..., min_length=1, max_length=5000)
    severity_hint: Severity = Field(default=Severity.MEDIUM)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_blob_uri: str | None = Field(default=None)
    detected_at: datetime
    source_scanner: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: int = Field(default=1, ge=1)


class ScanErrorEntry(_Model):
    """One error captured during a plugin run; recorded on ``ScanResult.errors``."""

    code: str
    message: str
    permanent: bool = Field(
        default=False,
        description="If True, do not retry this work item.",
    )
    context: dict[str, Any] = Field(default_factory=dict)


class ScanResult(_Model):
    """Per-plugin result returned to the orchestrator."""

    plugin_id: str
    tenant_id: UUID
    correlation_id: str
    started_at: datetime
    ended_at: datetime
    status: ScanStatus
    assets: list[ScanAssetSnapshot] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)
    errors: list[ScanErrorEntry] = Field(default_factory=list)

    @property
    def is_partial(self) -> bool:
        return self.status is ScanStatus.PARTIAL


class ScanSummary(_Model):
    """Aggregate result for one ``ScanRequest`` across all plugins."""

    request_id: UUID
    tenant_id: UUID
    correlation_id: str
    status: ScanStatus
    started_at: datetime
    ended_at: datetime
    plugins_attempted: list[str] = Field(default_factory=list)
    plugins_succeeded: list[str] = Field(default_factory=list)
    plugins_partial: list[str] = Field(default_factory=list)
    plugins_failed: list[str] = Field(default_factory=list)
    total_assets: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    errors: list[ScanErrorEntry] = Field(default_factory=list)
