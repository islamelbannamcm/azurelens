"""Tenant, connector, and role models.

A *tenant* in AzureLens corresponds 1:1 with a customer Microsoft Entra ID
tenant (``azure_tenant_id``). Every persisted record in the platform is scoped
to one ``Tenant.id`` (a separate UUID we own).

Future work (Phase 1+):
  * persistence in Azure SQL (table ``tenants``, see docs/SCHEMA_DESIGN.md § 2.1)
  * provisioning workflow on admin consent
  * per-tenant Customer-Managed Key (CMK) in Enterprise tier
  * connector secret resolution via Managed Identity → Key Vault
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import EmailStr, Field, HttpUrl

from app.models.common import AzureLensModel


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TenantStatus(str, Enum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    OFFBOARDING = "offboarding"


class TenantTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    CUSTOMER_HOSTED = "customer_hosted"


class Role(str, Enum):
    """Application roles (matrix in docs/SECURITY_MODEL.md § 4)."""

    GLOBAL_ADMIN = "GlobalAdmin"
    SECURITY_ADMIN = "SecurityAdmin"
    COMPLIANCE = "Compliance"
    CLOUD_ARCHITECT = "CloudArchitect"
    SOC_ANALYST = "SOCAnalyst"
    IT_MANAGER = "ITManager"
    AUDITOR = "Auditor"
    EXEC_VIEWER = "ExecViewer"


class ConnectorType(str, Enum):
    """External integrations the platform consumes (read-only by default)."""

    MS_GRAPH = "ms_graph"
    AZURE_ARM = "azure_arm"
    AZURE_RESOURCE_GRAPH = "azure_resource_graph"
    DEFENDER_FOR_CLOUD = "defender_for_cloud"
    DEFENDER_XDR = "defender_xdr"
    SENTINEL = "sentinel"
    INTUNE = "intune"
    PURVIEW = "purview"
    AZURE_POLICY = "azure_policy"
    # Threat intelligence sources
    DEFENDER_TI = "defender_ti"
    SENTINEL_TI = "sentinel_ti"
    CISA_KEV = "cisa_kev"
    MITRE_ATTACK = "mitre_attack"
    MISP = "misp"
    OPENCTI = "opencti"
    OTX = "otx"
    ABUSE_CH = "abuse_ch"
    VIRUSTOTAL = "virustotal"
    GHSA = "ghsa"
    NVD = "nvd"


class ConnectorStatus(str, Enum):
    CONNECTED = "connected"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"


class DataResidency(str, Enum):
    """Customer-selected residency. Data never leaves the chosen geo."""

    EU = "eu"
    UK = "uk"
    US = "us"
    AUSTRALIA = "australia"
    CANADA = "canada"
    JAPAN = "japan"
    # TODO(phase-10): sovereign clouds (gov, china) modelled separately


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TenantContact(AzureLensModel):
    """Primary administrative contact for a tenant."""

    display_name: str = Field(..., min_length=1, max_length=200)
    email: EmailStr
    role: Role = Field(default=Role.GLOBAL_ADMIN)


class Tenant(AzureLensModel):
    """An onboarded customer tenant."""

    id: UUID = Field(..., description="AzureLens internal tenant id (partition key everywhere).")
    azure_tenant_id: UUID = Field(..., description="Customer Microsoft Entra ID tenant GUID.")
    display_name: str = Field(..., min_length=1, max_length=200)
    primary_domain: str = Field(
        ..., description="Initial verified domain on the customer's Entra ID tenant."
    )

    tier: TenantTier = Field(default=TenantTier.PRO)
    status: TenantStatus = Field(default=TenantStatus.PROVISIONING)
    data_residency: DataResidency = Field(default=DataResidency.EU)

    primary_contact: TenantContact | None = Field(
        default=None, description="Primary admin contact for onboarding & incident comms."
    )

    cmk_key_uri: HttpUrl | None = Field(
        default=None,
        description=(
            "Per-tenant Customer-Managed Key URI (Azure Key Vault key version). "
            "Required for Enterprise tier; optional otherwise."
        ),
    )

    created_at: datetime
    updated_at: datetime
    onboarded_at: datetime | None = Field(default=None)
    offboarded_at: datetime | None = Field(default=None)

    # TODO(phase-1): subscription scopes selected by the admin (mgmt-group root vs subset).
    # TODO(phase-6): per-tenant SLO target, per-tenant audit retention override.


class TenantOnboardRequest(AzureLensModel):
    """Request body for ``POST /tenants/onboard``."""

    azure_tenant_id: UUID
    display_name: str = Field(..., min_length=1, max_length=200)
    primary_domain: str
    tier: TenantTier = Field(default=TenantTier.PRO)
    data_residency: DataResidency = Field(default=DataResidency.EU)
    primary_contact: TenantContact

    # TODO(phase-1): consent_state token returned by Entra ID admin-consent flow.
    # TODO(phase-1): selected_subscription_scope: list[str]


class TenantConnector(AzureLensModel):
    """Per-tenant state of one external connector."""

    tenant_id: UUID
    connector_type: ConnectorType
    status: ConnectorStatus = Field(default=ConnectorStatus.NOT_CONFIGURED)
    consented_scopes: list[str] = Field(default_factory=list)
    last_success_at: datetime | None = Field(default=None)
    last_error: str | None = Field(default=None, max_length=2000)

    # Secrets are NEVER inlined; only references to Key Vault items.
    # See docs/SECURITY_MODEL.md § 5.
    secret_ref: str | None = Field(
        default=None,
        description="Key Vault secret reference (e.g. 'kv://platform-kv/connectors/<id>'). Never a value.",
    )


class TenantSummary(AzureLensModel):
    """Compact projection for list endpoints and selectors."""

    id: UUID
    display_name: str
    tier: TenantTier
    status: TenantStatus
    data_residency: DataResidency
