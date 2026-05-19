"""AzureLens scanning engine.

Plugin-based architecture (introduced in Phase 3):

  scanner.contracts       Pydantic v2 wire shapes (metadata, request, result, summary)
  scanner.context         Per-request runtime context dataclass
  scanner.errors          Exception hierarchy
  scanner.base            ScannerPlugin abstract base class
  scanner.registry        Plugin registry + default singleton
  scanner.orchestrator    ScanOrchestrator (resolve → invoke → aggregate)
  scanner.plugins         Built-in plugin stubs (Phase 1+ flesh these out):
                            azure_resource_graph, entra_identity, m365_security,
                            intune_device, defender_cloud, sentinel, purview

Nothing in this package performs network calls, SDK calls, or token
acquisition in this branch. See docs/SCANNER_ARCHITECTURE.md.
"""

from __future__ import annotations

from scanner.base import ScannerPlugin
from scanner.context import CredentialMode, ScanContext, ScanScope
from scanner.contracts import (
    CloudProvider,
    PermissionGrantType,
    RequiredPermission,
    ScanAssetSnapshot,
    ScanErrorEntry,
    ScanFinding,
    ScanKind,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ScanTriggerType,
    ScannerCapability,
    ScannerMetadata,
    Severity,
)
from scanner.errors import (
    DependencyMissingError,
    PluginNotFoundError,
    ScannerAuthError,
    ScannerConfigError,
    ScannerError,
    ScannerPermanentError,
    ScannerPermissionError,
    ScannerThrottledError,
    ScannerTransientError,
    TenantIsolationError,
)
from scanner.orchestrator import KIND_TO_CAPABILITIES, ScanOrchestrator
from scanner.registry import PluginRegistry, default_registry

__all__ = [
    # base
    "ScannerPlugin",
    # context
    "CredentialMode",
    "ScanContext",
    "ScanScope",
    # contracts
    "CloudProvider",
    "PermissionGrantType",
    "RequiredPermission",
    "ScanAssetSnapshot",
    "ScanErrorEntry",
    "ScanFinding",
    "ScanKind",
    "ScanRequest",
    "ScanResult",
    "ScanStatus",
    "ScanSummary",
    "ScanTriggerType",
    "ScannerCapability",
    "ScannerMetadata",
    "Severity",
    # errors
    "DependencyMissingError",
    "PluginNotFoundError",
    "ScannerAuthError",
    "ScannerConfigError",
    "ScannerError",
    "ScannerPermanentError",
    "ScannerPermissionError",
    "ScannerThrottledError",
    "ScannerTransientError",
    "TenantIsolationError",
    # orchestration
    "KIND_TO_CAPABILITIES",
    "ScanOrchestrator",
    "PluginRegistry",
    "default_registry",
]
