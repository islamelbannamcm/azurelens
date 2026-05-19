"""/api/v1/threat-intel — threat-intelligence reads + correlations (placeholder).

Future work (Phase 2):
  * Read from Cosmos TI containers; vector + lexical search via Azure AI Search.
  * Per-tenant correlation queries: ``/threat-intel/correlations?tenant=...``.
  * Campaign exposure projections for the dashboard's Threat Exposure page.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    Campaign,
    CorrelationHit,
    Indicator,
    IndicatorType,
    Page,
    PageMeta,
    StixObjectType,
    TISource,
    Vulnerability,
)
from app.models.threat_intel import (
    CampaignExposureSummary,
    CorrelationDimension,
    Severity,
)

router = APIRouter(prefix="/threat-intel")


_NOW = datetime(2026, 5, 19, tzinfo=timezone.utc)
_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

_MOCK_CAMPAIGN = Campaign(
    id="campaign::akira-rdp-2026q2",
    tenant_id="shared",
    stix_type=StixObjectType.CAMPAIGN,
    sources=[TISource.DEFENDER_TI],
    external_references=[],
    valid_from=_NOW,
    valid_until=None,
    confidence=85,
    trust_score=0.9,
    labels=["ransomware"],
    name="Akira ransomware — RDP brute-force wave",
    description="Active campaign targeting publicly exposed RDP for initial access.",
    aliases=[],
    first_seen=_NOW,
    last_seen=_NOW,
    objective="ransomware",
    target_sectors=["financial", "healthcare"],
    target_geographies=["EU", "US"],
    attributed_to=[],
    techniques=["T1133", "T1078"],
    tactics=[],
    indicator_ids=[],
    vulnerability_ids=[],
)

_MOCK_INDICATOR = Indicator(
    id="defender_ti::ioc-12345",
    tenant_id="shared",
    stix_type=StixObjectType.INDICATOR,
    sources=[TISource.DEFENDER_TI],
    external_references=[],
    valid_from=_NOW,
    valid_until=None,
    confidence=80,
    trust_score=0.85,
    labels=["malicious-activity"],
    indicator_type=IndicatorType.DOMAIN,
    value="malicious-example.invalid",
    pattern=None,
    kill_chain_phases=["command-and-control"],
)

_MOCK_VULN = Vulnerability(
    id="cisa_kev::CVE-2024-00000",
    tenant_id="shared",
    stix_type=StixObjectType.VULNERABILITY,
    sources=[TISource.CISA_KEV, TISource.NVD],
    external_references=[],
    valid_from=_NOW,
    valid_until=None,
    confidence=95,
    trust_score=0.95,
    labels=["kev"],
    cve_id="CVE-2024-00000",
    title="Placeholder CVE for contract testing",
    cvss_v3=9.8,
    cvss_v4=None,
    epss_score=0.95,
    is_kev=True,
    kev_added_date=_NOW,
    affected_cpes=[],
    affected_products=["Example Product"],
    techniques=["T1190"],
    severity=Severity.CRITICAL,
)

_MOCK_CORRELATION = CorrelationHit(
    tenant_id=_TENANT_ID,
    id=UUID("ccccccc1-cccc-cccc-cccc-cccccccccccc"),
    ti_id=_MOCK_CAMPAIGN.id,
    asset_id="sha256:placeholder-asset-1",
    finding_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
    match_dimension=CorrelationDimension.TECHNIQUE_TO_FINDING,
    confidence=78,
    evidence={"technique": "T1133", "finding_type": "azure.network.rdp_public_exposed"},
    first_observed_at=_NOW,
    last_observed_at=_NOW,
)


# --- Campaigns ----------------------------------------------------------------


@router.get("/campaigns", response_model=Page[Campaign], summary="List threat campaigns")
async def list_campaigns(
    relevant_only: bool = Query(default=True, description="Only campaigns with correlations on this tenant."),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[Campaign]:
    _ = (relevant_only, cursor, limit)
    return Page[Campaign](items=[_MOCK_CAMPAIGN], page=PageMeta(next_cursor=None, total_estimate=1))


@router.get("/campaigns/{campaign_id}", response_model=Campaign, summary="Get one campaign")
async def get_campaign(campaign_id: str) -> Campaign:
    if campaign_id != _MOCK_CAMPAIGN.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="campaign_not_found")
    return _MOCK_CAMPAIGN


# --- Indicators ---------------------------------------------------------------


@router.get("/indicators", response_model=Page[Indicator], summary="List indicators (IOCs)")
async def list_indicators(
    indicator_type: IndicatorType | None = Query(default=None),
    source: TISource | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[Indicator]:
    _ = (indicator_type, source, cursor, limit)
    return Page[Indicator](items=[_MOCK_INDICATOR], page=PageMeta(next_cursor=None, total_estimate=1))


# --- Vulnerabilities ----------------------------------------------------------


@router.get("/vulnerabilities", response_model=Page[Vulnerability], summary="List vulnerabilities (CVEs)")
async def list_vulnerabilities(
    kev_only: bool = Query(default=False, description="Restrict to CISA KEV entries."),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[Vulnerability]:
    _ = (kev_only, cursor, limit)
    return Page[Vulnerability](items=[_MOCK_VULN], page=PageMeta(next_cursor=None, total_estimate=1))


# --- Correlations & exposure --------------------------------------------------


@router.get(
    "/correlations",
    response_model=Page[CorrelationHit],
    summary="List threat-to-environment correlations for the calling tenant",
)
async def list_correlations(
    asset_id: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[CorrelationHit]:
    _ = (asset_id, cursor, limit)
    return Page[CorrelationHit](items=[_MOCK_CORRELATION], page=PageMeta(next_cursor=None, total_estimate=1))


@router.get(
    "/exposure/campaigns",
    response_model=list[CampaignExposureSummary],
    summary="Per-tenant campaign exposure summary (drives the Threat Exposure dashboard)",
)
async def campaign_exposure_summary() -> list[CampaignExposureSummary]:
    return [
        CampaignExposureSummary(
            tenant_id=_TENANT_ID,
            campaign_id=_MOCK_CAMPAIGN.id,
            campaign_name=_MOCK_CAMPAIGN.name,
            affected_asset_count=1,
            highest_severity=Severity.HIGH,
            correlation_dimensions=[CorrelationDimension.TECHNIQUE_TO_FINDING],
            last_observed_at=_NOW,
        )
    ]
