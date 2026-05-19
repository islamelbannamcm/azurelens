"""Domain & API schemas (Pydantic v2).

This package is the single source of truth for the wire and persistence shapes
that the API layer accepts and returns. Models are intentionally framework-agnostic
(no FastAPI imports) so they can be reused by:

  - the FastAPI surface in ``app/api/v1/*``
  - the worker services (``services/scanner``, ``services/threat-intel``,
    ``services/risk-engine``, ``services/ai-engine``)
  - the cross-language ``packages/contracts/`` contract pack (OpenAPI export
    in a later phase)

Multi-tenant invariant: every major model carries ``tenant_id``. See
``docs/SCHEMA_DESIGN.md`` § 12.
"""

from __future__ import annotations

from app.models.asset import (
    Asset,
    AssetEdge,
    AssetEdgeType,
    AssetKind,
    AssetSummary,
    CloudProvider,
    Criticality,
    ExposureLevel,
)
from app.models.common import (
    AuditMetadata,
    Page,
    PageMeta,
    PageParams,
    TenantScoped,
)
from app.models.compliance import (
    ComplianceFramework,
    ComplianceControlStatus,
    ComplianceControlState,
    ComplianceFrameworkPosture,
    FrameworkMappings,
)
from app.models.finding import (
    Exploitability,
    Finding,
    FindingStatus,
    MitreTactic,
    RawFinding,
    Severity,
)
from app.models.report import (
    Report,
    ReportRequest,
    ReportStatus,
    ReportType,
)
from app.models.scoring import (
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Score,
    ScoreBand,
    ScoreKind,
    ScoringPolicyRef,
)
from app.models.tenant import (
    ConnectorStatus,
    ConnectorType,
    Role,
    Tenant,
    TenantConnector,
    TenantStatus,
    TenantTier,
)
from app.models.threat_intel import (
    Campaign,
    Confidence,
    CorrelationHit,
    Indicator,
    IndicatorType,
    Severity as TiSeverity,  # re-export for clarity; same enum
    StixObjectType,
    TIRelationship,
    TISource,
    Vulnerability,
)

__all__ = [
    # common
    "AuditMetadata",
    "Page",
    "PageMeta",
    "PageParams",
    "TenantScoped",
    # tenant
    "ConnectorStatus",
    "ConnectorType",
    "Role",
    "Tenant",
    "TenantConnector",
    "TenantStatus",
    "TenantTier",
    # asset
    "Asset",
    "AssetEdge",
    "AssetEdgeType",
    "AssetKind",
    "AssetSummary",
    "CloudProvider",
    "Criticality",
    "ExposureLevel",
    # finding
    "Exploitability",
    "Finding",
    "FindingStatus",
    "MitreTactic",
    "RawFinding",
    "Severity",
    # threat intel
    "Campaign",
    "Confidence",
    "CorrelationHit",
    "Indicator",
    "IndicatorType",
    "StixObjectType",
    "TIRelationship",
    "TISource",
    "Vulnerability",
    "TiSeverity",
    # compliance
    "ComplianceFramework",
    "ComplianceControlStatus",
    "ComplianceControlState",
    "ComplianceFrameworkPosture",
    "FrameworkMappings",
    # scoring / scans
    "ScanRequest",
    "ScanStatus",
    "ScanSummary",
    "Score",
    "ScoreBand",
    "ScoreKind",
    "ScoringPolicyRef",
    # report
    "Report",
    "ReportRequest",
    "ReportStatus",
    "ReportType",
]
