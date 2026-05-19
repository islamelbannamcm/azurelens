"""Intune device scanner plugin (STUB).

In Phase 1 this plugin will evaluate Intune-managed device posture via the
Microsoft Graph Intune endpoints: enrolled devices, compliance state,
configuration profiles, endpoint-security policies, Defender for Endpoint
onboarding, BitLocker, firewall, antivirus, OS patch level, and per-device
risk.

NO Microsoft Graph calls happen here today.
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


class IntuneDeviceScanner(ScannerPlugin):
    """Evaluates Intune-managed device posture via Microsoft Graph."""

    metadata = ScannerMetadata(
        id="intune_device",
        name="Intune Device Scanner",
        version="0.0.0",
        provider=CloudProvider.INTUNE,
        capabilities=[
            ScannerCapability.INTUNE_DEVICE_INVENTORY,
            ScannerCapability.INTUNE_COMPLIANCE_POSTURE,
            ScannerCapability.INTUNE_CONFIG_POSTURE,
        ],
        supported_asset_kinds=[
            "intune.device",
            "intune.compliance_policy",
            "intune.configuration_profile",
            "intune.endpoint_security_policy",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="DeviceManagementManagedDevices.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="DeviceManagementConfiguration.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="DeviceManagementServiceConfig.Read.All",
            ),
        ],
        description=(
            "Evaluates Intune-managed device posture: compliance policies, "
            "configuration profiles, endpoint-security policies, Defender "
            "onboarding, BitLocker, firewall, antivirus, and update compliance."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1):
          * Page through ``/deviceManagement/managedDevices``,
            ``/deviceManagement/deviceCompliancePolicies``,
            ``/deviceManagement/deviceConfigurations``,
            ``/deviceManagement/configurationPolicies`` (Settings Catalog),
            and ``/deviceManagement/endpointSecurityPolicies`` via the Graph
            Intune endpoints. Use ``$batch`` to reduce request count.
          * Emit ``ScanAssetSnapshot`` per device + policy and ``ScanFinding``
            per posture gap (non-compliant devices, missing Defender onboarding,
            disabled BitLocker, weak compliance policies).
          * Use ``ctx.scope.device_ids`` for targeted scans.
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


default_registry.register(IntuneDeviceScanner)
