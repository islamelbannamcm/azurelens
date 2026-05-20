"""Deterministic demo-mode dataset for Contoso Demo.

Everything in this module is a module-level constant — built once at
import time and never mutated. The DemoService in ``service.py`` returns
deep copies (via Pydantic ``model_copy``) for any write-shaped endpoint
so that the in-memory state remains pristine across requests.

Conventions
-----------
* All UUIDs are stable, lowercase, hand-curated.
* All timestamps are anchored to ``BASELINE_NOW`` so demo output is
  reproducible across processes.
* All domains / IPs use IETF-reserved ranges or RFC-6761 ``*.invalid``.
* No real customer identifiers, no real CVE that maps to a specific
  vendor product (``CVE-2024-00000`` is a placeholder).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.models import (
    Asset,
    AssetKind,
    Campaign,
    CloudProvider,
    ComplianceControlStatus,
    ComplianceFramework,
    ComplianceFrameworkPosture,
    CorrelationHit,
    Criticality,
    DataResidency,
    Exploitability,
    ExposureLevel,
    Finding,
    FindingStatus,
    IndicatorType,
    MitreTactic,
    ScanKind,
    ScanStatus,
    ScanSummary,
    ScanTriggerType,
    Score,
    ScoreBand,
    ScoreKind,
    Severity,
    StixObjectType,
    Tenant,
    TenantStatus,
    TenantTier,
)
from app.models.finding import CampaignLinkRef, FindingSummary, RemediationSummary
from app.models.report import (
    ApprovalRequirement as _ApprovalRequirement,
)  # noqa: F401 — kept for forward parity with remediation models
from app.models.report import (
    RemediationAction,
    RemediationStatus,
    RemediationStep,
    RemediationStepKind,
    RemediationTemplate,
)
from app.models.threat_intel import (
    CampaignExposureSummary,
    CorrelationDimension,
    Indicator,
    TISource,
    Vulnerability,
)
from app.models.tenant import TenantContact

# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------

BASELINE_NOW: datetime = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)


def _hours_ago(h: int) -> datetime:
    return BASELINE_NOW - timedelta(hours=h)


def _days_ago(d: int) -> datetime:
    return BASELINE_NOW - timedelta(days=d)


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
AZURE_TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
REQUESTER_ID = UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")

TENANT: Tenant = Tenant(
    id=TENANT_ID,
    azure_tenant_id=AZURE_TENANT_ID,
    display_name="Contoso Demo",
    primary_domain="contoso.onmicrosoft.com",
    tier=TenantTier.PRO,
    status=TenantStatus.ACTIVE,
    data_residency=DataResidency.EU,
    primary_contact=TenantContact(
        display_name="Demo CISO",
        email="ciso@contoso.invalid",
    ),
    cmk_key_uri=None,
    created_at=_days_ago(30),
    updated_at=_hours_ago(2),
    onboarded_at=_days_ago(30),
    offboarded_at=None,
)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

ASSETS: tuple[Asset, ...] = (
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-sub-prod",
        asset_uri="azure://subscriptions/00000000-0000-0000-0000-0000000000aa",
        asset_kind=AssetKind.AZURE_SUBSCRIPTION,
        provider=CloudProvider.AZURE,
        subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
        location="westeurope",
        display_name="Contoso Production Subscription",
        criticality=Criticality.HIGH,
        exposure=ExposureLevel.PUBLIC,
        properties={"workload": "production"},
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-azure (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-vm-prod-web-01",
        asset_uri=(
            "azure://subscriptions/00000000-0000-0000-0000-0000000000aa/"
            "resourceGroups/rg-prod-web/providers/Microsoft.Compute/virtualMachines/vm-prod-web-01"
        ),
        asset_kind=AssetKind.AZURE_VM,
        provider=CloudProvider.AZURE,
        subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
        resource_group="rg-prod-web",
        location="westeurope",
        display_name="vm-prod-web-01",
        tags={"env": "prod", "owner": "web"},
        criticality=Criticality.HIGH,
        exposure=ExposureLevel.PUBLIC,
        properties={
            "os": "Linux",
            "vm_size": "Standard_D2s_v5",
            "open_ports": [22, 3389, 80, 443],
            "public_ip": "203.0.113.10",
            "defender_for_servers": "off",
            "patch_state": "out-of-date",
        },
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-azure (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-vm-prod-api-02",
        asset_uri=(
            "azure://subscriptions/00000000-0000-0000-0000-0000000000aa/"
            "resourceGroups/rg-prod-api/providers/Microsoft.Compute/virtualMachines/vm-prod-api-02"
        ),
        asset_kind=AssetKind.AZURE_VM,
        provider=CloudProvider.AZURE,
        subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
        resource_group="rg-prod-api",
        location="westeurope",
        display_name="vm-prod-api-02",
        criticality=Criticality.MODERATE,
        exposure=ExposureLevel.INTERNAL,
        properties={"os": "Linux", "vm_size": "Standard_B2s", "open_ports": []},
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-azure (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-stprodassets01",
        asset_uri=(
            "azure://subscriptions/00000000-0000-0000-0000-0000000000aa/"
            "resourceGroups/rg-prod-data/providers/Microsoft.Storage/storageAccounts/stprodassets01"
        ),
        asset_kind=AssetKind.AZURE_STORAGE_ACCOUNT,
        provider=CloudProvider.AZURE,
        subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
        resource_group="rg-prod-data",
        location="westeurope",
        display_name="stprodassets01",
        criticality=Criticality.HIGH,
        exposure=ExposureLevel.PUBLIC,
        properties={
            "kind": "StorageV2",
            "allow_blob_public_access": True,
            "network_default_action": "Allow",
            "secure_transfer_required": True,
            "cmk_uri": None,
        },
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-azure (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-kv-prod-secrets",
        asset_uri=(
            "azure://subscriptions/00000000-0000-0000-0000-0000000000aa/"
            "resourceGroups/rg-prod-data/providers/Microsoft.KeyVault/vaults/kv-prod-secrets"
        ),
        asset_kind=AssetKind.AZURE_KEY_VAULT,
        provider=CloudProvider.AZURE,
        subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
        resource_group="rg-prod-data",
        location="westeurope",
        display_name="kv-prod-secrets",
        criticality=Criticality.HIGH,
        exposure=ExposureLevel.INTERNAL,
        properties={"soft_delete": True, "purge_protection": False, "rbac_mode": True},
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-azure (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-user-admin",
        asset_uri="m365://users/22222222-2222-2222-2222-222222222222",
        asset_kind=AssetKind.M365_USER,
        provider=CloudProvider.ENTRA_ID,
        display_name="Demo Admin",
        criticality=Criticality.CRITICAL,
        exposure=ExposureLevel.INTERNAL,
        properties={
            "account_enabled": True,
            "mfa_strength": "none",
            "is_privileged": True,
            "pim_eligible": False,
            "directory_roles": ["Global Administrator"],
            "risk_level": "medium",
        },
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(1),
        source="scanner-m365 (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-user-svc",
        asset_uri="m365://users/33333333-3333-3333-3333-333333333333",
        asset_kind=AssetKind.M365_SERVICE_PRINCIPAL,
        provider=CloudProvider.ENTRA_ID,
        display_name="svc-deploy-prod",
        criticality=Criticality.HIGH,
        exposure=ExposureLevel.INTERNAL,
        properties={
            "is_privileged": True,
            "mfa_strength": "none",
            "credential_age_days": 180,
        },
        discovered_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        source="scanner-m365 (demo)",
    ),
    Asset(
        tenant_id=TENANT_ID,
        id="sha256:asset-device-desktop-a1b2c3",
        asset_uri="intune://devices/44444444-4444-4444-4444-444444444444",
        asset_kind=AssetKind.INTUNE_DEVICE,
        provider=CloudProvider.INTUNE,
        display_name="DESKTOP-A1B2C3",
        criticality=Criticality.MODERATE,
        exposure=ExposureLevel.INTERNAL,
        properties={
            "os": "Windows",
            "compliance_state": "noncompliant",
            "is_encrypted": False,
            "defender_onboarded": False,
        },
        discovered_at=_days_ago(28),
        last_seen_at=_hours_ago(6),
        source="scanner-intune (demo)",
    ),
)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

# Anchor finding ids so cross-references in the rest of the dataset are stable.
F_MFA = UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_GLOBAL_ADMIN = UUID("aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_LEGACY_AUTH = UUID("aaaaaaa3-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_RDP_PUBLIC = UUID("aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_PUBLIC_STORAGE = UUID("aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_KV_NO_CMK = UUID("aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_DEFENDER_OFF = UUID("aaaaaaa7-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_INTUNE_NONCOMPLIANT = UUID("aaaaaaa8-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_DLP_MISSING = UUID("aaaaaaa9-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_AUDIT_LOG_DISABLED = UUID("aaaaaaab-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_KEV_CVE = UUID("aaaaaaac-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
F_AKIRA_CORRELATION = UUID("aaaaaaad-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


_CAMPAIGN_AKIRA_LINK = CampaignLinkRef(
    campaign_id="campaign::akira-rdp-2026q2",
    name="Akira ransomware — RDP brute-force wave",
    source="defender_ti",
    confidence=85,
)


FINDINGS: tuple[Finding, ...] = (
    Finding(
        tenant_id=TENANT_ID,
        id=F_MFA,
        finding_type="identity.mfa.privileged.missing",
        title="Privileged identity without MFA",
        description=(
            "The Global Administrator 'Demo Admin' does not have MFA enforced. "
            "This is the top initial-access vector (MITRE T1078)."
        ),
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.ACTIVE,
        asset_id="sha256:asset-user-admin",
        mitre_tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.PRIVILEGE_ESCALATION],
        mitre_techniques=["T1078", "T1078.004"],
        framework_mappings={
            "cis_azure": [{"version": "2.1.0", "controls": ["1.1.1"]}],
            "mcsb": [{"version": "1.0", "controls": ["IM-7"]}],
            "nist_csf": [{"version": "2.0", "controls": ["PR.AC-1"]}],
            "iso_27001": [{"version": "2022", "controls": ["A.5.17"]}],
            "soc2": [{"version": "2017", "controls": ["CC6.1"]}],
        },
        risk_score=92.0,
        campaign_links=[],
        remediation=RemediationSummary(
            template_id="rt.identity.enforce_mfa_privileged.v2",
            title="Enforce phishing-resistant MFA for all privileged roles",
            estimated_minutes=30,
            risk_reduction_estimate=20,
            docs_url=None,
        ),
        first_seen_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-m365 (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_GLOBAL_ADMIN,
        finding_type="identity.global_admin.permanent",
        title="Permanent Global Administrator assignment",
        description=(
            "'Demo Admin' holds Global Administrator permanently rather than "
            "via PIM JIT activation."
        ),
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.THEORETICAL,
        asset_id="sha256:asset-user-admin",
        mitre_tactics=[MitreTactic.PERSISTENCE],
        mitre_techniques=["T1098"],
        framework_mappings={
            "cis_azure": [{"version": "2.1.0", "controls": ["1.5"]}],
            "zero_trust": [{"pillars": ["identity"]}],
        },
        risk_score=74.0,
        first_seen_at=_days_ago(30),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-m365 (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_LEGACY_AUTH,
        finding_type="identity.legacy_auth.allowed",
        title="Legacy authentication protocols allowed",
        description="Conditional Access does not block legacy auth tenant-wide.",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.POC,
        asset_id="sha256:asset-user-admin",
        mitre_techniques=["T1110.003"],
        framework_mappings={"cis_azure": [{"version": "2.1.0", "controls": ["1.3"]}]},
        risk_score=48.0,
        first_seen_at=_days_ago(25),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-m365 (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_RDP_PUBLIC,
        finding_type="azure.network.rdp_public_exposed",
        title="RDP exposed to the public internet",
        description=(
            "vm-prod-web-01 has TCP/3389 reachable from 0.0.0.0/0. Active "
            "ransomware campaigns abuse this vector."
        ),
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.ACTIVE,
        asset_id="sha256:asset-vm-prod-web-01",
        mitre_tactics=[MitreTactic.INITIAL_ACCESS],
        mitre_techniques=["T1133", "T1078"],
        framework_mappings={
            "cis_azure": [{"version": "2.1.0", "controls": ["6.1", "6.2"]}],
            "mcsb": [{"version": "1.0", "controls": ["NS-1", "NS-2"]}],
            "nist_csf": [{"version": "2.0", "controls": ["PR.AC-3", "PR.AC-5"]}],
        },
        risk_score=88.0,
        campaign_links=[_CAMPAIGN_AKIRA_LINK],
        remediation=RemediationSummary(
            template_id="rt.azure.nsg.restrict_rdp.v1",
            title="Restrict RDP to Azure Bastion / corporate ranges",
            estimated_minutes=45,
            risk_reduction_estimate=18,
            docs_url=None,
        ),
        first_seen_at=_days_ago(7),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-azure (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_PUBLIC_STORAGE,
        finding_type="azure.storage.public_access",
        title="Storage account allows public blob access",
        description=(
            "stprodassets01 has `allow_blob_public_access=true` and a default "
            "network action of `Allow`."
        ),
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.POC,
        asset_id="sha256:asset-stprodassets01",
        mitre_techniques=["T1530"],
        framework_mappings={
            "cis_azure": [{"version": "2.1.0", "controls": ["3.7"]}],
            "gdpr_articles": [32],
        },
        risk_score=76.0,
        first_seen_at=_days_ago(14),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-azure (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_KV_NO_CMK,
        finding_type="azure.keyvault.purge_protection_off",
        title="Key Vault purge protection disabled",
        description="kv-prod-secrets has purge protection disabled.",
        severity=Severity.MEDIUM,
        status=FindingStatus.ACKNOWLEDGED,
        exploitability=Exploitability.THEORETICAL,
        asset_id="sha256:asset-kv-prod-secrets",
        mitre_techniques=["T1485"],
        framework_mappings={"cis_azure": [{"version": "2.1.0", "controls": ["8.1"]}]},
        risk_score=42.0,
        first_seen_at=_days_ago(20),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        acknowledged_at=_hours_ago(48),
        acknowledged_by=REQUESTER_ID,
        source_scanner="scanner-azure (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_DEFENDER_OFF,
        finding_type="device.defender.not_onboarded",
        title="Device not onboarded to Defender for Endpoint",
        description="DESKTOP-A1B2C3 is not onboarded; detection coverage is reduced.",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.POC,
        asset_id="sha256:asset-device-desktop-a1b2c3",
        mitre_techniques=["T1078"],
        framework_mappings={
            "mcsb": [{"version": "1.0", "controls": ["ES-1"]}],
            "nist_csf": [{"version": "2.0", "controls": ["DE.CM-7"]}],
        },
        risk_score=66.0,
        first_seen_at=_days_ago(10),
        last_seen_at=_hours_ago(6),
        last_evaluated_at=_hours_ago(6),
        source_scanner="scanner-intune (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_INTUNE_NONCOMPLIANT,
        finding_type="device.compliance.policy_failing",
        title="Device fails the Windows compliance policy",
        description="DESKTOP-A1B2C3 fails the baseline Windows 11 compliance policy.",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.THEORETICAL,
        asset_id="sha256:asset-device-desktop-a1b2c3",
        mitre_techniques=["T1078"],
        framework_mappings={"mcsb": [{"version": "1.0", "controls": ["ES-2"]}]},
        risk_score=51.0,
        first_seen_at=_days_ago(7),
        last_seen_at=_hours_ago(6),
        last_evaluated_at=_hours_ago(6),
        source_scanner="scanner-intune (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_DLP_MISSING,
        finding_type="m365.dlp.financial_data_missing",
        title="No DLP policy for financial data",
        description="No DLP policy covers SharePoint / OneDrive sharing for financial data.",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.THEORETICAL,
        asset_id="sha256:asset-user-admin",
        mitre_techniques=["T1567"],
        framework_mappings={
            "gdpr_articles": [5, 32],
            "soc2": [{"version": "2017", "controls": ["CC6.1"]}],
            "iso_27001": [{"version": "2022", "controls": ["A.5.34"]}],
        },
        risk_score=44.0,
        first_seen_at=_days_ago(5),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-purview (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_AUDIT_LOG_DISABLED,
        finding_type="azure.subscription.audit_log_disabled",
        title="Subscription activity log not exported to Log Analytics",
        description=(
            "The production subscription's activity log is not exported. "
            "Audit horizon for SOC 2 is within 30 days."
        ),
        severity=Severity.HIGH,
        status=FindingStatus.REMEDIATED,
        exploitability=Exploitability.NONE,
        asset_id="sha256:asset-sub-prod",
        mitre_techniques=["T1562.008"],
        framework_mappings={
            "cis_azure": [{"version": "2.1.0", "controls": ["5.1.1"]}],
            "soc2": [{"version": "2017", "controls": ["CC7.2"]}],
        },
        risk_score=18.0,
        first_seen_at=_days_ago(14),
        last_seen_at=_hours_ago(48),
        last_evaluated_at=_hours_ago(48),
        source_scanner="scanner-azure (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_KEV_CVE,
        finding_type="threat.kev_cve.affected_software",
        title="Affected by an actively exploited CVE (CISA KEV)",
        description=(
            "Inventory matches CVE-2024-00000 (placeholder), present on the "
            "CISA Known Exploited Vulnerabilities catalog."
        ),
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.ACTIVE,
        asset_id="sha256:asset-vm-prod-web-01",
        mitre_techniques=["T1190"],
        framework_mappings={
            "mcsb": [{"version": "1.0", "controls": ["PV-6"]}],
        },
        risk_score=84.0,
        first_seen_at=_days_ago(3),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="scanner-defender (demo)",
    ),
    Finding(
        tenant_id=TENANT_ID,
        id=F_AKIRA_CORRELATION,
        finding_type="threat.campaign.correlation",
        title="Active Akira ransomware campaign correlates to this tenant",
        description=(
            "Two posture findings (public RDP + missing privileged MFA) align "
            "with the TTPs Akira is currently using in the wild."
        ),
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        exploitability=Exploitability.ACTIVE,
        asset_id="sha256:asset-vm-prod-web-01",
        mitre_tactics=[MitreTactic.INITIAL_ACCESS],
        mitre_techniques=["T1133", "T1078"],
        framework_mappings={},
        risk_score=78.0,
        campaign_links=[_CAMPAIGN_AKIRA_LINK],
        first_seen_at=_days_ago(2),
        last_seen_at=_hours_ago(2),
        last_evaluated_at=_hours_ago(2),
        source_scanner="ti-correlation (demo)",
    ),
)


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------


def _score(kind: ScoreKind, value: int, band: ScoreBand, *, contrib: list[UUID]) -> Score:
    return Score(
        tenant_id=TENANT_ID,
        score_kind=kind,
        value=value,
        band=band,
        contributing_finding_ids=contrib,
        calculated_at=_hours_ago(2),
    )


CURRENT_SCORES: tuple[Score, ...] = (
    _score(
        ScoreKind.OVERALL,
        value=64,
        band=ScoreBand.MODERATE,
        contrib=[F_MFA, F_RDP_PUBLIC, F_KEV_CVE, F_GLOBAL_ADMIN, F_PUBLIC_STORAGE],
    ),
    _score(
        ScoreKind.IDENTITY,
        value=58,
        band=ScoreBand.WEAK,
        contrib=[F_MFA, F_GLOBAL_ADMIN, F_LEGACY_AUTH],
    ),
    _score(
        ScoreKind.AZURE_EXPOSURE,
        value=52,
        band=ScoreBand.WEAK,
        contrib=[F_RDP_PUBLIC, F_PUBLIC_STORAGE, F_KV_NO_CMK],
    ),
    _score(
        ScoreKind.DEVICE,
        value=71,
        band=ScoreBand.MODERATE,
        contrib=[F_DEFENDER_OFF, F_INTUNE_NONCOMPLIANT],
    ),
    _score(
        ScoreKind.THREAT_EXPOSURE,
        value=60,
        band=ScoreBand.MODERATE,
        contrib=[F_KEV_CVE, F_AKIRA_CORRELATION, F_RDP_PUBLIC],
    ),
    _score(
        ScoreKind.M365_COMPLIANCE,
        value=79,
        band=ScoreBand.STRONG,
        contrib=[F_DLP_MISSING, F_AUDIT_LOG_DISABLED],
    ),
)


# 14-day daily snapshot trending mildly upward (with one dip after a regression).
def _build_score_history() -> dict[ScoreKind, list[tuple[datetime, int]]]:
    history: dict[ScoreKind, list[tuple[datetime, int]]] = {}
    trend: dict[ScoreKind, list[int]] = {
        ScoreKind.OVERALL: [55, 56, 57, 58, 58, 59, 60, 61, 62, 62, 63, 63, 63, 64],
        ScoreKind.IDENTITY: [48, 49, 50, 50, 52, 52, 53, 53, 54, 55, 56, 57, 57, 58],
        ScoreKind.AZURE_EXPOSURE: [44, 45, 45, 46, 47, 48, 48, 49, 50, 50, 51, 51, 52, 52],
        ScoreKind.DEVICE: [60, 62, 63, 64, 66, 67, 68, 69, 69, 70, 70, 71, 71, 71],
        ScoreKind.THREAT_EXPOSURE: [50, 52, 53, 54, 55, 56, 56, 57, 58, 58, 59, 59, 60, 60],
        ScoreKind.M365_COMPLIANCE: [72, 73, 74, 74, 75, 76, 76, 77, 77, 78, 78, 78, 79, 79],
    }
    for kind, values in trend.items():
        history[kind] = [
            (_days_ago(len(values) - 1 - i), v) for i, v in enumerate(values)
        ]
    return history


SCORE_HISTORY: dict[ScoreKind, list[tuple[datetime, int]]] = _build_score_history()


# ---------------------------------------------------------------------------
# Threat Intelligence — campaigns / indicators / vulnerabilities
# ---------------------------------------------------------------------------

CAMPAIGNS: tuple[Campaign, ...] = (
    Campaign(
        id="campaign::akira-rdp-2026q2",
        tenant_id="shared",
        stix_type=StixObjectType.CAMPAIGN,
        sources=[TISource.DEFENDER_TI, TISource.MITRE_ATTACK],
        external_references=[],
        valid_from=_days_ago(60),
        valid_until=None,
        confidence=85,
        trust_score=0.9,
        labels=["ransomware", "active"],
        name="Akira ransomware — RDP brute-force wave",
        description="Active campaign abusing publicly exposed RDP for initial access.",
        aliases=["Akira-RDP-Q2-2026"],
        first_seen=_days_ago(60),
        last_seen=_hours_ago(12),
        objective="ransomware",
        target_sectors=["financial", "healthcare", "manufacturing"],
        target_geographies=["EU", "US"],
        attributed_to=[],
        techniques=["T1133", "T1078", "T1486"],
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.IMPACT],
        indicator_ids=["defender_ti::ioc-akira-001", "defender_ti::ioc-akira-002"],
        vulnerability_ids=[],
    ),
    Campaign(
        id="campaign::storm-1234-phishing-2026q2",
        tenant_id="shared",
        stix_type=StixObjectType.CAMPAIGN,
        sources=[TISource.DEFENDER_TI],
        external_references=[],
        valid_from=_days_ago(45),
        valid_until=None,
        confidence=78,
        trust_score=0.85,
        labels=["phishing", "active"],
        name="Storm-1234 — credential phishing wave",
        description="Phishing wave targeting M365 credentials with adversary-in-the-middle kits.",
        aliases=[],
        first_seen=_days_ago(45),
        last_seen=_hours_ago(24),
        objective="data-theft",
        target_sectors=["technology", "financial"],
        target_geographies=["EU"],
        attributed_to=[],
        techniques=["T1078", "T1556.006", "T1110"],
        tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.CREDENTIAL_ACCESS],
        indicator_ids=[],
        vulnerability_ids=[],
    ),
)


VULNERABILITIES: tuple[Vulnerability, ...] = (
    Vulnerability(
        id="cisa_kev::CVE-2024-00000",
        tenant_id="shared",
        stix_type=StixObjectType.VULNERABILITY,
        sources=[TISource.CISA_KEV, TISource.NVD],
        external_references=[],
        valid_from=_days_ago(10),
        valid_until=None,
        confidence=95,
        trust_score=0.95,
        labels=["kev", "active-exploitation"],
        cve_id="CVE-2024-00000",
        title="Placeholder CVE — actively exploited (demo)",
        cvss_v3=9.8,
        cvss_v4=None,
        epss_score=0.93,
        is_kev=True,
        kev_added_date=_days_ago(10),
        affected_cpes=[],
        affected_products=["Demo Product"],
        techniques=["T1190"],
        severity=Severity.CRITICAL,
    ),
)


INDICATORS: tuple[Indicator, ...] = (
    Indicator(
        id="defender_ti::ioc-akira-001",
        tenant_id="shared",
        stix_type=StixObjectType.INDICATOR,
        sources=[TISource.DEFENDER_TI],
        external_references=[],
        valid_from=_days_ago(30),
        valid_until=None,
        confidence=85,
        trust_score=0.9,
        labels=["malicious-activity", "ransomware"],
        indicator_type=IndicatorType.DOMAIN,
        value="akira-c2.invalid",
        pattern=None,
        kill_chain_phases=["command-and-control"],
    ),
)


CORRELATIONS: tuple[CorrelationHit, ...] = (
    CorrelationHit(
        tenant_id=TENANT_ID,
        id=UUID("ccccc001-cccc-cccc-cccc-cccccccccccc"),
        ti_id="campaign::akira-rdp-2026q2",
        asset_id="sha256:asset-vm-prod-web-01",
        finding_id=F_RDP_PUBLIC,
        match_dimension=CorrelationDimension.TECHNIQUE_TO_FINDING,
        confidence=82,
        evidence={"technique": "T1133", "finding_type": "azure.network.rdp_public_exposed"},
        first_observed_at=_days_ago(2),
        last_observed_at=_hours_ago(2),
    ),
    CorrelationHit(
        tenant_id=TENANT_ID,
        id=UUID("ccccc002-cccc-cccc-cccc-cccccccccccc"),
        ti_id="cisa_kev::CVE-2024-00000",
        asset_id="sha256:asset-vm-prod-web-01",
        finding_id=F_KEV_CVE,
        match_dimension=CorrelationDimension.CVE_IN_INVENTORY,
        confidence=90,
        evidence={"cve_id": "CVE-2024-00000"},
        first_observed_at=_days_ago(3),
        last_observed_at=_hours_ago(2),
    ),
)


CAMPAIGN_EXPOSURE: tuple[CampaignExposureSummary, ...] = (
    CampaignExposureSummary(
        tenant_id=TENANT_ID,
        campaign_id="campaign::akira-rdp-2026q2",
        campaign_name="Akira ransomware — RDP brute-force wave",
        affected_asset_count=1,
        highest_severity=Severity.CRITICAL,
        correlation_dimensions=[CorrelationDimension.TECHNIQUE_TO_FINDING],
        last_observed_at=_hours_ago(2),
    ),
    CampaignExposureSummary(
        tenant_id=TENANT_ID,
        campaign_id="campaign::storm-1234-phishing-2026q2",
        campaign_name="Storm-1234 — credential phishing wave",
        affected_asset_count=1,
        highest_severity=Severity.HIGH,
        correlation_dimensions=[CorrelationDimension.SECTOR_ALIGNMENT],
        last_observed_at=_hours_ago(24),
    ),
)


# ---------------------------------------------------------------------------
# Compliance posture
# ---------------------------------------------------------------------------

COMPLIANCE_POSTURE: tuple[ComplianceFrameworkPosture, ...] = (
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.CIS_AZURE,
        version="2.1.0",
        total_controls=120,
        compliant=72,
        partially_compliant=22,
        non_compliant=20,
        not_applicable=4,
        insufficient_data=2,
        score=68.0,
        last_evaluated_at=_hours_ago(2),
    ),
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.MCSB,
        version="1.0",
        total_controls=98,
        compliant=64,
        partially_compliant=18,
        non_compliant=12,
        not_applicable=3,
        insufficient_data=1,
        score=71.0,
        last_evaluated_at=_hours_ago(2),
    ),
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.NIST_CSF,
        version="2.0",
        total_controls=108,
        compliant=70,
        partially_compliant=22,
        non_compliant=12,
        not_applicable=2,
        insufficient_data=2,
        score=72.0,
        last_evaluated_at=_hours_ago(2),
    ),
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.ISO_27001,
        version="2022",
        total_controls=93,
        compliant=62,
        partially_compliant=20,
        non_compliant=8,
        not_applicable=2,
        insufficient_data=1,
        score=74.0,
        last_evaluated_at=_hours_ago(2),
    ),
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.SOC2,
        version="2017",
        total_controls=33,
        compliant=24,
        partially_compliant=6,
        non_compliant=2,
        not_applicable=1,
        insufficient_data=0,
        score=79.0,
        last_evaluated_at=_hours_ago(2),
    ),
    ComplianceFrameworkPosture(
        tenant_id=TENANT_ID,
        framework=ComplianceFramework.GDPR,
        version="2018",
        total_controls=25,
        compliant=19,
        partially_compliant=4,
        non_compliant=1,
        not_applicable=1,
        insufficient_data=0,
        score=81.0,
        last_evaluated_at=_hours_ago(2),
    ),
)


_COMPLIANCE_STATUSES: tuple[ComplianceControlStatus, ...] = (
    ComplianceControlStatus.COMPLIANT,
    ComplianceControlStatus.PARTIALLY_COMPLIANT,
    ComplianceControlStatus.NON_COMPLIANT,
    ComplianceControlStatus.INSUFFICIENT_DATA,
)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

SCAN_HISTORY: tuple[ScanSummary, ...] = (
    ScanSummary(
        tenant_id=TENANT_ID,
        id=UUID("11111111-2222-3333-4444-555555555555"),
        kinds=[ScanKind.FULL],
        trigger_type=ScanTriggerType.SCHEDULED,
        status=ScanStatus.COMPLETED,
        requested_at=_hours_ago(3),
        started_at=_hours_ago(3),
        completed_at=_hours_ago(2),
        partitions_total=12,
        partitions_completed=12,
        findings_produced=12,
        error_summary=None,
    ),
    ScanSummary(
        tenant_id=TENANT_ID,
        id=UUID("11111111-2222-3333-4444-444444444444"),
        kinds=[ScanKind.FULL],
        trigger_type=ScanTriggerType.SCHEDULED,
        status=ScanStatus.COMPLETED,
        requested_at=_days_ago(1),
        started_at=_days_ago(1),
        completed_at=_days_ago(1) + timedelta(minutes=22),
        partitions_total=12,
        partitions_completed=12,
        findings_produced=11,
        error_summary=None,
    ),
    ScanSummary(
        tenant_id=TENANT_ID,
        id=UUID("11111111-2222-3333-4444-333333333333"),
        kinds=[ScanKind.M365, ScanKind.INTUNE],
        trigger_type=ScanTriggerType.INCREMENTAL,
        status=ScanStatus.PARTIAL,
        requested_at=_days_ago(2),
        started_at=_days_ago(2),
        completed_at=_days_ago(2) + timedelta(minutes=8),
        partitions_total=6,
        partitions_completed=5,
        findings_produced=4,
        error_summary="Graph throttling on /users; partial result emitted.",
    ),
    ScanSummary(
        tenant_id=TENANT_ID,
        id=UUID("11111111-2222-3333-4444-222222222222"),
        kinds=[ScanKind.AZURE],
        trigger_type=ScanTriggerType.ON_DEMAND,
        status=ScanStatus.COMPLETED,
        requested_at=_days_ago(3),
        started_at=_days_ago(3),
        completed_at=_days_ago(3) + timedelta(minutes=12),
        partitions_total=4,
        partitions_completed=4,
        findings_produced=6,
        error_summary=None,
    ),
    ScanSummary(
        tenant_id=TENANT_ID,
        id=UUID("11111111-2222-3333-4444-111111111111"),
        kinds=[ScanKind.FULL],
        trigger_type=ScanTriggerType.BOOTSTRAP,
        status=ScanStatus.COMPLETED,
        requested_at=_days_ago(30),
        started_at=_days_ago(30),
        completed_at=_days_ago(30) + timedelta(minutes=27),
        partitions_total=12,
        partitions_completed=12,
        findings_produced=18,
        error_summary=None,
    ),
)


# ---------------------------------------------------------------------------
# Remediation templates + actions
# ---------------------------------------------------------------------------

REMEDIATION_TEMPLATES: tuple[RemediationTemplate, ...] = (
    RemediationTemplate(
        template_id="rt.identity.enforce_mfa_privileged.v2",
        title="Enforce phishing-resistant MFA for all privileged roles",
        version=2,
        applies_to_finding_types=["identity.mfa.privileged.missing"],
        steps=[
            RemediationStep(
                kind=RemediationStepKind.MS_GRAPH,
                title="Create a Conditional Access policy",
                code="# POST https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\n# body managed by the platform remediation library",
                docs_url=None,
            ),
        ],
        rollback_steps=[
            RemediationStep(
                kind=RemediationStepKind.MS_GRAPH,
                title="Disable the new Conditional Access policy",
                code=None,
                docs_url=None,
            ),
        ],
        estimated_minutes=30,
        risk_reduction_estimate=20,
    ),
    RemediationTemplate(
        template_id="rt.azure.nsg.restrict_rdp.v1",
        title="Restrict RDP to Azure Bastion / corporate ranges",
        version=1,
        applies_to_finding_types=["azure.network.rdp_public_exposed"],
        steps=[
            RemediationStep(
                kind=RemediationStepKind.AZURE_CLI,
                title="Update NSG rule to deny public RDP",
                code="az network nsg rule update -g <rg> --nsg-name <nsg> --name allow-rdp --source-address-prefixes 10.0.0.0/8 --access Deny",
                docs_url=None,
            ),
        ],
        rollback_steps=[],
        estimated_minutes=45,
        risk_reduction_estimate=18,
    ),
    RemediationTemplate(
        template_id="rt.azure.storage.disable_public.v1",
        title="Disable public access on the storage account",
        version=1,
        applies_to_finding_types=["azure.storage.public_access"],
        steps=[
            RemediationStep(
                kind=RemediationStepKind.AZURE_CLI,
                title="Set default network action to Deny",
                code="az storage account update -g <rg> -n <sa> --default-action Deny",
                docs_url=None,
            ),
        ],
        rollback_steps=[],
        estimated_minutes=20,
        risk_reduction_estimate=12,
    ),
    RemediationTemplate(
        template_id="rt.intune.defender.onboard.v1",
        title="Onboard device to Microsoft Defender for Endpoint",
        version=1,
        applies_to_finding_types=["device.defender.not_onboarded"],
        steps=[
            RemediationStep(
                kind=RemediationStepKind.MS_GRAPH,
                title="Assign Defender onboarding configuration profile",
                code=None,
                docs_url=None,
            ),
        ],
        rollback_steps=[],
        estimated_minutes=60,
        risk_reduction_estimate=15,
    ),
    RemediationTemplate(
        template_id="rt.azure.diag.enable_audit_log.v1",
        title="Export subscription activity log to Log Analytics",
        version=1,
        applies_to_finding_types=["azure.subscription.audit_log_disabled"],
        steps=[
            RemediationStep(
                kind=RemediationStepKind.AZURE_CLI,
                title="Create diagnostic setting on the subscription",
                code="az monitor diagnostic-settings subscription create ...",
                docs_url=None,
            ),
        ],
        rollback_steps=[],
        estimated_minutes=15,
        risk_reduction_estimate=8,
    ),
)


REMEDIATION_ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0001-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_MFA,
        template_id="rt.identity.enforce_mfa_privileged.v2",
        status=RemediationStatus.SUGGESTED,
        requested_by=REQUESTER_ID,
        approved_by=None,
        requested_at=_hours_ago(48),
        started_at=None,
        ended_at=None,
        diff_before={},
        diff_after={},
        error_summary=None,
    ),
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0002-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_RDP_PUBLIC,
        template_id="rt.azure.nsg.restrict_rdp.v1",
        status=RemediationStatus.REQUESTED,
        requested_by=REQUESTER_ID,
        approved_by=None,
        requested_at=_hours_ago(24),
        started_at=None,
        ended_at=None,
        diff_before={},
        diff_after={},
        error_summary=None,
    ),
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0003-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_PUBLIC_STORAGE,
        template_id="rt.azure.storage.disable_public.v1",
        status=RemediationStatus.APPROVED,
        requested_by=REQUESTER_ID,
        approved_by=REQUESTER_ID,
        requested_at=_hours_ago(20),
        started_at=None,
        ended_at=None,
        diff_before={},
        diff_after={},
        error_summary=None,
    ),
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0004-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_DEFENDER_OFF,
        template_id="rt.intune.defender.onboard.v1",
        status=RemediationStatus.NOT_STARTED,
        requested_by=REQUESTER_ID,
        approved_by=None,
        requested_at=_hours_ago(72),
        started_at=None,
        ended_at=None,
        diff_before={},
        diff_after={},
        error_summary=None,
    ),
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0005-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_AUDIT_LOG_DISABLED,
        template_id="rt.azure.diag.enable_audit_log.v1",
        status=RemediationStatus.SUCCEEDED,
        requested_by=REQUESTER_ID,
        approved_by=REQUESTER_ID,
        requested_at=_hours_ago(96),
        started_at=_hours_ago(72),
        ended_at=_hours_ago(48),
        diff_before={"diagnostic_settings": []},
        diff_after={"diagnostic_settings": ["law-prod"]},
        error_summary=None,
    ),
    RemediationAction(
        tenant_id=TENANT_ID,
        id=UUID("dddd0006-dddd-dddd-dddd-dddddddddddd"),
        finding_id=F_KEV_CVE,
        template_id="rt.intune.defender.onboard.v1",
        status=RemediationStatus.NOT_STARTED,
        requested_by=REQUESTER_ID,
        approved_by=None,
        requested_at=_hours_ago(12),
        started_at=None,
        ended_at=None,
        diff_before={},
        diff_after={},
        error_summary=None,
    ),
)


# ---------------------------------------------------------------------------
# Convenience lookups (built once)
# ---------------------------------------------------------------------------


def _build_finding_summaries() -> tuple[FindingSummary, ...]:
    return tuple(
        FindingSummary(
            id=f.id,
            tenant_id=f.tenant_id,
            title=f.title,
            finding_type=f.finding_type,
            severity=f.severity,
            status=f.status,
            risk_score=f.risk_score,
            asset_id=f.asset_id,
            last_seen_at=f.last_seen_at,
        )
        for f in FINDINGS
    )


FINDING_SUMMARIES: tuple[FindingSummary, ...] = _build_finding_summaries()


__all__ = [
    "ASSETS",
    "AZURE_TENANT_ID",
    "BASELINE_NOW",
    "CAMPAIGNS",
    "CAMPAIGN_EXPOSURE",
    "COMPLIANCE_POSTURE",
    "CORRELATIONS",
    "CURRENT_SCORES",
    "FINDINGS",
    "FINDING_SUMMARIES",
    "INDICATORS",
    "REMEDIATION_ACTIONS",
    "REMEDIATION_TEMPLATES",
    "REQUESTER_ID",
    "SCAN_HISTORY",
    "SCORE_HISTORY",
    "TENANT",
    "TENANT_ID",
    "VULNERABILITIES",
]
