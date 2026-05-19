"""Asset graph models.

Assets are everything we discover in the customer environment: Azure resources,
Entra ID identities, Intune devices, M365 collaboration objects, Purview data
assets. Findings hang off assets; the asset graph is the join key for threat-
to-environment correlation.

Future work (Phase 1+):
  * persist in Cosmos DB containers ``assets`` and ``asset_edges`` with
    partition key ``tenant_id`` (see docs/SCHEMA_DESIGN.md § 3).
  * scanner workers emit assets via the ``finding.raw`` envelope and Asset
    upserts via a dedicated ``asset.upserted`` event.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import Field

from app.models.common import AzureLensModel, TenantScoped


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CloudProvider(str, Enum):
    """Source plane an asset belongs to."""

    AZURE = "azure"
    M365 = "m365"
    ENTRA_ID = "entra_id"
    INTUNE = "intune"
    DEFENDER_XDR = "defender_xdr"
    PURVIEW = "purview"
    # Future-proofing entries (not used in MVP):
    AWS = "aws"
    GCP = "gcp"


class AssetKind(str, Enum):
    """Canonical asset taxonomy.

    Values are lowercase, dotted, ``<provider>.<kind>`` to keep them stable
    across the wire and indexable in AI Search.
    """

    # Azure — IaaS / PaaS
    AZURE_SUBSCRIPTION = "azure.subscription"
    AZURE_RESOURCE_GROUP = "azure.resource_group"
    AZURE_VM = "azure.vm"
    AZURE_DISK = "azure.disk"
    AZURE_STORAGE_ACCOUNT = "azure.storage_account"
    AZURE_KEY_VAULT = "azure.key_vault"
    AZURE_SQL_SERVER = "azure.sql_server"
    AZURE_SQL_DATABASE = "azure.sql_database"
    AZURE_COSMOSDB = "azure.cosmosdb"
    AZURE_APP_SERVICE = "azure.app_service"
    AZURE_FUNCTION_APP = "azure.function_app"
    AZURE_CONTAINER_APP = "azure.container_app"
    AZURE_AKS = "azure.aks"
    AZURE_VNET = "azure.vnet"
    AZURE_SUBNET = "azure.subnet"
    AZURE_NSG = "azure.nsg"
    AZURE_PUBLIC_IP = "azure.public_ip"
    AZURE_LOAD_BALANCER = "azure.load_balancer"
    AZURE_APP_GATEWAY = "azure.app_gateway"
    AZURE_FRONT_DOOR = "azure.front_door"
    AZURE_FIREWALL = "azure.firewall"
    AZURE_PRIVATE_ENDPOINT = "azure.private_endpoint"
    AZURE_ROLE_ASSIGNMENT = "azure.role_assignment"
    AZURE_POLICY_ASSIGNMENT = "azure.policy_assignment"

    # Entra ID / M365
    M365_USER = "m365.user"
    M365_GROUP = "m365.group"
    M365_DIRECTORY_ROLE = "m365.directory_role"
    M365_CONDITIONAL_ACCESS_POLICY = "m365.conditional_access_policy"
    M365_APPLICATION = "m365.application"
    M365_SERVICE_PRINCIPAL = "m365.service_principal"
    M365_OAUTH_GRANT = "m365.oauth_grant"
    M365_MAILBOX = "m365.mailbox"
    M365_SHAREPOINT_SITE = "m365.sharepoint_site"
    M365_TEAMS_TEAM = "m365.teams_team"
    M365_ONEDRIVE = "m365.onedrive"

    # Intune
    INTUNE_DEVICE = "intune.device"
    INTUNE_COMPLIANCE_POLICY = "intune.compliance_policy"
    INTUNE_CONFIGURATION_PROFILE = "intune.configuration_profile"
    INTUNE_ENDPOINT_SECURITY_POLICY = "intune.endpoint_security_policy"

    # Purview / data
    PURVIEW_SENSITIVITY_LABEL = "purview.sensitivity_label"
    PURVIEW_DLP_POLICY = "purview.dlp_policy"
    PURVIEW_RETENTION_POLICY = "purview.retention_policy"

    # Defender
    DEFENDER_RECOMMENDATION = "defender.recommendation"
    DEFENDER_SECURE_SCORE_CONTROL = "defender.secure_score_control"

    # Fallback for forward compatibility
    UNKNOWN = "unknown"


class AssetEdgeType(str, Enum):
    LOCATED_IN = "located_in"          # vm located_in resource_group
    OWNED_BY = "owned_by"              # group owned_by user
    USES_IDENTITY = "uses_identity"    # vm uses_identity managed_identity
    HAS_ROLE = "has_role"              # principal has_role role_assignment
    EXPOSES = "exposes"                # vm exposes public_ip
    DEPENDS_ON = "depends_on"          # app_service depends_on sql_server
    GOVERNED_BY = "governed_by"        # resource governed_by policy_assignment
    PROTECTS = "protects"              # ca_policy protects user
    ENCRYPTS = "encrypts"              # key_vault encrypts storage_account
    MEMBER_OF = "member_of"            # user member_of group


class Criticality(str, Enum):
    """Business criticality assigned by the tenant (override-able per asset)."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ExposureLevel(str, Enum):
    """Where the asset is reachable from."""

    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AssetRelationshipRef(AzureLensModel):
    """Inline relationship descriptor embedded on an Asset for quick reads."""

    type: AssetEdgeType
    to_asset_id: str = Field(..., description="Stable id of the related asset.")
    properties: dict[str, Any] = Field(default_factory=dict)


class Asset(TenantScoped):
    """A discovered object in the customer environment."""

    id: str = Field(
        ...,
        description="Stable asset id (sha256 of canonical ``asset_uri``).",
    )
    asset_uri: str = Field(
        ...,
        description=(
            "Canonical fully-qualified identifier, e.g. "
            "``azure://subscriptions/<sub>/resourceGroups/<rg>/providers/...`` "
            "or ``m365://users/<oid>``."
        ),
    )
    asset_kind: AssetKind = Field(default=AssetKind.UNKNOWN)
    provider: CloudProvider

    subscription_id: UUID | None = Field(default=None)
    resource_group: str | None = Field(default=None)
    location: str | None = Field(default=None, description="Azure region or tenant region.")

    display_name: str | None = Field(default=None, max_length=400)
    tags: dict[str, str] = Field(default_factory=dict)

    criticality: Criticality = Field(default=Criticality.MODERATE)
    exposure: ExposureLevel = Field(default=ExposureLevel.UNKNOWN)
    owners: list[str] = Field(
        default_factory=list,
        description="Hashed UPNs / object ids of responsible owners.",
    )

    # Asset-kind-specific properties. Shape varies by kind; see SCHEMA_DESIGN.md § 3.2.
    properties: dict[str, Any] = Field(default_factory=dict)
    relationships: list[AssetRelationshipRef] = Field(default_factory=list)

    discovered_at: datetime
    last_seen_at: datetime
    source: str = Field(..., description="Producing scanner, e.g. 'scanner-azure'.")
    schema_version: int = Field(default=1, ge=1)

    # TODO(phase-1): add `inventory_hash` to dedupe unchanged assets quickly.
    # TODO(phase-2): add `cve_inventory` for software/image CVE matching.


class AssetSummary(AzureLensModel):
    """Compact projection for list endpoints and dashboards."""

    id: str
    tenant_id: UUID
    asset_kind: AssetKind
    provider: CloudProvider
    display_name: str | None = None
    exposure: ExposureLevel
    criticality: Criticality
    open_finding_count: int = Field(default=0, ge=0)
    highest_finding_severity: str | None = Field(
        default=None,
        description="String form of Severity enum for cheap projection.",
    )


class AssetEdge(TenantScoped):
    """An edge in the asset graph (Cosmos container ``asset_edges``)."""

    id: str = Field(..., description="Stable edge id: '<from>__<type>__<to>'.")
    from_asset_id: str
    to_asset_id: str
    edge_type: AssetEdgeType
    properties: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime
