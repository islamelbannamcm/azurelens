"""/api/v1/findings — findings reads + acknowledge (placeholder).

Future work (Phase 1+):
  * Read from Azure SQL ``findings`` with RLS keyed on tenant_id.
  * Filter by severity, status, asset_id, framework, mitre_technique, text.
  * POST /findings/{id}/acknowledge → audit-logged status transition.
  * POST /findings/{id}/suppress → suppression with reason + optional expiry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    Exploitability,
    Finding,
    FindingStatus,
    MitreTactic,
    Page,
    PageMeta,
    Severity,
)
from app.models.finding import FindingAcknowledgeRequest, FindingSummary, RemediationSummary

router = APIRouter()


_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_FINDING_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_NOW = datetime(2026, 5, 19, tzinfo=timezone.utc)

_MOCK_FINDING = Finding(
    tenant_id=_TENANT_ID,
    id=_FINDING_ID,
    finding_type="azure.network.rdp_public_exposed",
    title="RDP exposed to the public internet",
    description=(
        "An Azure VM has TCP/3389 reachable from 0.0.0.0/0 via an NSG rule. "
        "This maps to MITRE ATT&CK T1133 (External Remote Services) and is the "
        "current attack vector for multiple active ransomware campaigns."
    ),
    severity=Severity.HIGH,
    status=FindingStatus.OPEN,
    exploitability=Exploitability.ACTIVE,
    asset_id="sha256:placeholder-asset-1",
    mitre_tactics=[MitreTactic.INITIAL_ACCESS],
    mitre_techniques=["T1133", "T1078"],
    framework_mappings={
        "cis_azure": [{"version": "2.1.0", "controls": ["6.1", "6.2"]}],
        "mcsb": [{"version": "1.0", "controls": ["NS-1", "NS-2"]}],
        "nist_csf": [{"version": "2.0", "controls": ["PR.AC-3", "PR.AC-5"]}],
    },
    risk_score=82.5,
    campaign_links=[],
    remediation=RemediationSummary(
        template_id="rt.azure.nsg.restrict_rdp.v1",
        title="Restrict RDP to Azure Bastion / corporate ranges",
        estimated_minutes=30,
        risk_reduction_estimate=18,
        docs_url=None,
    ),
    first_seen_at=_NOW,
    last_seen_at=_NOW,
    last_evaluated_at=_NOW,
    evidence_blob_uri=None,
    source_scanner="scanner-azure (mock)",
)


@router.get(
    "",
    response_model=Page[FindingSummary],
    summary="List findings",
)
async def list_findings(
    severity: Severity | None = Query(default=None),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    asset_id: str | None = Query(default=None),
    mitre_technique: str | None = Query(default=None),
    framework: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[FindingSummary]:
    # TODO(phase-1): tenant-scoped SQL query with prepared filter set.
    _ = (severity, finding_status, asset_id, mitre_technique, framework, cursor, limit)
    return Page[FindingSummary](
        items=[
            FindingSummary(
                id=_MOCK_FINDING.id,
                tenant_id=_MOCK_FINDING.tenant_id,
                title=_MOCK_FINDING.title,
                finding_type=_MOCK_FINDING.finding_type,
                severity=_MOCK_FINDING.severity,
                status=_MOCK_FINDING.status,
                risk_score=_MOCK_FINDING.risk_score,
                asset_id=_MOCK_FINDING.asset_id,
                last_seen_at=_MOCK_FINDING.last_seen_at,
            )
        ],
        page=PageMeta(next_cursor=None, total_estimate=1),
    )


@router.get(
    "/{finding_id}",
    response_model=Finding,
    summary="Get one finding",
)
async def get_finding(finding_id: UUID) -> Finding:
    # TODO(phase-1): enforce tenant-context filter.
    if finding_id != _MOCK_FINDING.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
    return _MOCK_FINDING


@router.post(
    "/{finding_id}/acknowledge",
    response_model=Finding,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge or suppress a finding",
)
async def acknowledge_finding(finding_id: UUID, payload: FindingAcknowledgeRequest) -> Finding:
    # TODO(phase-1):
    #  - enforce RBAC: SecurityAdmin or higher.
    #  - record audit event (action='finding.acknowledge', resource=finding_id).
    #  - transition status and persist; idempotent.
    if finding_id != _MOCK_FINDING.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
    new_status = FindingStatus.SUPPRESSED if payload.suppress_until else FindingStatus.ACKNOWLEDGED
    return _MOCK_FINDING.model_copy(
        update={
            "status": new_status,
            "suppression_reason": payload.note,
            "acknowledged_at": datetime.now(tz=timezone.utc),
        }
    )
