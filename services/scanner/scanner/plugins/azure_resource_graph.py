"""Azure Resource Graph scanner plugin (STUB).

In Phase 1 this plugin will use Azure Resource Graph (ARG) KQL queries plus
narrow ARM REST calls to enumerate every subscription, resource group, and
supported resource type the customer has granted ``Reader`` on. Outputs
``ScanAssetSnapshot``s and raw posture findings (open ports, missing private
endpoints, public storage, weak NSG rules, missing CMK, public RDP/SSH,
non-compliant Key Vaults, etc.).

NO network calls, NO SDK calls, NO credentials are read here today.
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


class AzureResourceGraphScanner(ScannerPlugin):
    """Enumerates and posture-checks Azure resources via Azure Resource Graph."""

    metadata = ScannerMetadata(
        id="azure_resource_graph",
        name="Azure Resource Graph Scanner",
        version="0.0.0",
        provider=CloudProvider.AZURE,
        capabilities=[
            ScannerCapability.AZURE_INVENTORY,
            ScannerCapability.AZURE_NETWORK_POSTURE,
            ScannerCapability.AZURE_DATA_POSTURE,
            ScannerCapability.AZURE_POLICY_POSTURE,
        ],
        supported_asset_kinds=[
            "azure.subscription",
            "azure.resource_group",
            "azure.vm",
            "azure.disk",
            "azure.storage_account",
            "azure.key_vault",
            "azure.sql_server",
            "azure.sql_database",
            "azure.cosmosdb",
            "azure.app_service",
            "azure.function_app",
            "azure.container_app",
            "azure.aks",
            "azure.vnet",
            "azure.subnet",
            "azure.nsg",
            "azure.public_ip",
            "azure.load_balancer",
            "azure.app_gateway",
            "azure.front_door",
            "azure.firewall",
            "azure.private_endpoint",
            "azure.role_assignment",
            "azure.policy_assignment",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.AZURE_RBAC,
                name="Reader",
                notes="Granted at the root management group or selected subscriptions.",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.AZURE_RBAC,
                name="Security Reader",
                optional=True,
                notes="Required for posture sourced from Defender for Cloud sub-assessments.",
            ),
        ],
        description=(
            "Uses Azure Resource Graph KQL queries plus narrow ARM REST calls to "
            "enumerate Azure assets and compute posture findings against Microsoft "
            "Cloud Security Benchmark and CIS Azure baseline controls."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1):
          * Acquire ARM token via the orchestrator's token provider
            (DefaultAzureCredential / workload identity).
          * Execute paged KQL queries via ``azure-mgmt-resourcegraph`` (1k rows/page).
          * Enrich with narrow ARM REST calls for properties ARG does not expose
            (``azure-mgmt-network``, ``azure-mgmt-compute``, ``azure-mgmt-storage``,
            ``azure-mgmt-keyvault``, ``azure-mgmt-security``, ``azure-mgmt-policyinsights``).
          * Emit one ``ScanAssetSnapshot`` per resource and one ``ScanFinding`` per
            detected posture gap. Use ``ctx.scope.subscription_ids`` when set.
          * Persist raw evidence to ADLS via the platform helper before normalizing.
          * Respect per-Graph-endpoint rate limits; back off on 429 with jitter.
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


default_registry.register(AzureResourceGraphScanner)
