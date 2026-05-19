"""Microsoft Sentinel scanner plugin (STUB).

In Phase 1 this plugin will evaluate Sentinel posture: presence and health
of analytics rules, data-connector status, workspace retention/audit-log
coverage, and a bridge that emits Sentinel-derived threat-intel hints to
``services/threat-intel`` for correlation.

NO Sentinel / Log Analytics calls happen here today.
"""

from __future__ import annotations

from scanner.base import ScannerPlugin
from scanner.context import ScanContext
from scanner.contracts import (
    CloudProvider,
    PermissionGrantType,
    RequiredPermission,
    ScanResult,
    ScanStatus,
    ScannerCapability,
    ScannerMetadata,
)
from scanner.registry import default_registry


class SentinelScanner(ScannerPlugin):
    """Evaluates Microsoft Sentinel posture and bridges TI to the platform."""

    metadata = ScannerMetadata(
        id="sentinel",
        name="Microsoft Sentinel Scanner",
        version="0.0.0",
        provider=CloudProvider.AZURE,
        capabilities=[
            ScannerCapability.SENTINEL_ANALYTICS_POSTURE,
            ScannerCapability.SENTINEL_THREAT_INTEL_BRIDGE,
        ],
        # Sentinel posture surfaces as findings hung off the Log Analytics
        # workspace / connected resources, not as new asset kinds — so we
        # don't declare any AssetKind here.
        supported_asset_kinds=[],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.SENTINEL_RBAC,
                name="Microsoft Sentinel Reader",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.AZURE_RBAC,
                name="Log Analytics Reader",
                optional=True,
                notes="Required for narrow KQL queries on the customer workspace.",
            ),
        ],
        description=(
            "Evaluates Microsoft Sentinel posture (analytics rules, data "
            "connectors, retention, audit coverage) and bridges Sentinel TI "
            "into the platform threat-intelligence corpus for correlation."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1 / phase-2):
          * Enumerate Sentinel workspaces the platform can read.
          * Pull analytics-rule definitions; flag missing/disabled rules from
            the recommended baseline (MCSB Logging-and-Threat-Detection).
          * Check data-connector health (last ingestion timestamps,
            enabled/disabled, errors).
          * Pull Sentinel TI indicators (TAXII 2.1) and forward to
            ``services/threat-intel`` as a TI source — NOT scanner findings;
            this plugin is a *bridge*.
          * Emit ``ScanFinding`` for posture gaps (no analytics rules,
            missing audit-log connector, short workspace retention, etc.).
        """
        now = ScanContext.now()
        return ScanResult(
            plugin_id=self.metadata.id,
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            started_at=now,
            ended_at=now,
            status=ScanStatus.COMPLETED,
        )


default_registry.register(SentinelScanner)
