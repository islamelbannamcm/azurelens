"""Microsoft Purview scanner plugin (STUB).

In Phase 1 this plugin will evaluate Microsoft Purview data-governance
posture: sensitivity-label scope, DLP policy coverage, retention policies,
and eDiscovery readiness.

NO Purview API calls happen here today.
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


class PurviewScanner(ScannerPlugin):
    """Evaluates Microsoft Purview data-governance posture."""

    metadata = ScannerMetadata(
        id="purview",
        name="Microsoft Purview Scanner",
        version="0.0.0",
        provider=CloudProvider.PURVIEW,
        capabilities=[
            ScannerCapability.PURVIEW_SENSITIVITY,
            ScannerCapability.PURVIEW_DLP,
            ScannerCapability.PURVIEW_RETENTION,
        ],
        supported_asset_kinds=[
            "purview.sensitivity_label",
            "purview.dlp_policy",
            "purview.retention_policy",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="InformationProtectionPolicy.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.PURVIEW_RBAC,
                name="Data Reader",
                notes="Granted at the Purview account scope.",
            ),
        ],
        description=(
            "Evaluates Microsoft Purview data-governance posture: sensitivity "
            "labels, DLP policies, retention policies, and eDiscovery readiness."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1 / phase-4):
          * Pull sensitivity-label policies via Graph
            ``/informationProtection/policy/labels``.
          * Pull DLP policies and detect coverage gaps (e.g. financial PII
            without DLP scope).
          * Pull retention / eDiscovery policies and detect missing or weak
            retention for high-criticality workloads.
          * Emit ``ScanFinding`` per gap, mapped to GDPR Art. 5/25/32, ISO
            27001 A.5.34/A.8.10, and SOC 2 CC6 controls.
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


default_registry.register(PurviewScanner)
