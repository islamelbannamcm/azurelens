"""AzureLens Threat Intelligence engine.

Connector-based architecture (introduced in Phase 4):

  threat_intel.contracts    Pydantic v2 wire shapes (metadata, request, result,
                             normalized intel, correlation)
  threat_intel.context      Per-ingestion runtime context dataclass
  threat_intel.errors       Exception hierarchy
  threat_intel.base         TIConnector abstract base class
  threat_intel.registry     Connector registry + default singleton
  threat_intel.normalizer   Raw-format → normalized intel conversion
  threat_intel.correlator   TI ⨝ tenant posture per-dimension correlation passes
  threat_intel.connectors   Built-in connector stubs (Phase 2 / 4 flesh these out):
                             microsoft_defender_ti, sentinel_ti, cisa_kev,
                             mitre_attack, misp, opencti, alienvault_otx,
                             abuse_ch, github_advisories, nvd, virustotal

Nothing in this package performs network calls, SDK calls, or credential
acquisition in this branch. See docs/THREAT_INTEL_ARCHITECTURE.md and
docs/CORRELATION_ENGINE.md.
"""

from __future__ import annotations

from threat_intel.base import TIConnector
from threat_intel.context import (
    SHARED_CORPUS,
    CredentialMode,
    FeedCursor,
    IngestionContext,
)
from threat_intel.contracts import (
    ConnectorCapability,
    CorrelationCandidate,
    CorrelationDimension,
    CorrelationResult,
    FreshnessSLA,
    FreshnessTier,
    IndicatorType,
    IngestionRequest,
    IngestionResult,
    IngestionStatus,
    IngestionSummary,
    NormalizedAttackPattern,
    NormalizedCampaign,
    NormalizedIndicator,
    NormalizedIntelBase,
    NormalizedMalware,
    NormalizedRelationship,
    NormalizedThreatActor,
    NormalizedTool,
    NormalizedVulnerability,
    RawIntelItem,
    RequiredCredential,
    Severity,
    StixObjectType,
    TIConnectorMetadata,
    TIErrorEntry,
    TISource,
)
from threat_intel.correlator import (
    AssetView,
    Correlator,
    FindingView,
    TenantProfile,
)
from threat_intel.errors import (
    ConnectorNotFoundError,
    DependencyMissingError,
    TIAuthError,
    TIConfigError,
    TIError,
    TIFeedUnavailableError,
    TIIsolationError,
    TIParseError,
    TIPermanentError,
    TIQuotaExceededError,
    TIRateLimitError,
    TITransientError,
)
from threat_intel.normalizer import Normalizer, RawHandler
from threat_intel.registry import ConnectorRegistry, default_registry

__all__ = [
    # base
    "TIConnector",
    # context
    "SHARED_CORPUS",
    "CredentialMode",
    "FeedCursor",
    "IngestionContext",
    # contracts
    "ConnectorCapability",
    "CorrelationCandidate",
    "CorrelationDimension",
    "CorrelationResult",
    "FreshnessSLA",
    "FreshnessTier",
    "IndicatorType",
    "IngestionRequest",
    "IngestionResult",
    "IngestionStatus",
    "IngestionSummary",
    "NormalizedAttackPattern",
    "NormalizedCampaign",
    "NormalizedIndicator",
    "NormalizedIntelBase",
    "NormalizedMalware",
    "NormalizedRelationship",
    "NormalizedThreatActor",
    "NormalizedTool",
    "NormalizedVulnerability",
    "RawIntelItem",
    "RequiredCredential",
    "Severity",
    "StixObjectType",
    "TIConnectorMetadata",
    "TIErrorEntry",
    "TISource",
    # correlator
    "AssetView",
    "Correlator",
    "FindingView",
    "TenantProfile",
    # errors
    "ConnectorNotFoundError",
    "DependencyMissingError",
    "TIAuthError",
    "TIConfigError",
    "TIError",
    "TIFeedUnavailableError",
    "TIIsolationError",
    "TIParseError",
    "TIPermanentError",
    "TIQuotaExceededError",
    "TIRateLimitError",
    "TITransientError",
    # normalizer
    "Normalizer",
    "RawHandler",
    # registry
    "ConnectorRegistry",
    "default_registry",
]
