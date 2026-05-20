"""/api/v1/dashboard — composite read endpoints for the home dashboard.

All responses come from ``app.demo.demo_service``; no persistence, no
Microsoft calls. See ``docs/DEMO_MODE.md``.

Future work (Phase 1):
  * Replace demo_service with the persistence-backed read service.
  * Enforce tenant context from the JWT; reject any cross-tenant request.
  * Add caching headers + ETag for the heavy ``/summary`` endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.demo import demo_service
from app.demo.service import (
    ComplianceFrameworkSummary,
    DashboardSummary,
    OverallScoreSummary,
    RecentScanSummary,
    RemediationRoadmapSummary,
    ThreatExposureSummary,
    TopRiskItem,
)

router = APIRouter()


@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Composite dashboard load — overall + per-domain + top risks + TI + compliance + recent scan + remediation",
)
async def dashboard_summary() -> DashboardSummary:
    # TODO(phase-1): cache for 30s per tenant; emit ETag.
    return demo_service.dashboard_summary()


@router.get(
    "/posture-summary",
    response_model=OverallScoreSummary,
    summary="Overall posture score + 7-day delta",
)
async def posture_summary() -> OverallScoreSummary:
    return demo_service.overall_score_summary()


@router.get(
    "/top-risks",
    response_model=list[TopRiskItem],
    summary="Top open findings by risk score",
)
async def top_risks(limit: int = 5) -> list[TopRiskItem]:
    return demo_service.top_risks(limit=max(1, min(50, limit)))


@router.get(
    "/threat-exposure-summary",
    response_model=ThreatExposureSummary,
    summary="Active campaign + KEV + technique exposure",
)
async def threat_exposure_summary() -> ThreatExposureSummary:
    return demo_service.threat_exposure_summary()


@router.get(
    "/compliance-summary",
    response_model=list[ComplianceFrameworkSummary],
    summary="Per-framework posture roll-ups",
)
async def compliance_summary() -> list[ComplianceFrameworkSummary]:
    return demo_service.compliance_summary()


@router.get(
    "/recent-scan",
    response_model=RecentScanSummary,
    summary="Most recent scan summary",
)
async def recent_scan() -> RecentScanSummary:
    return demo_service.recent_scan()


@router.get(
    "/remediation-roadmap",
    response_model=RemediationRoadmapSummary,
    summary="Status counts + top open remediation actions",
)
async def remediation_roadmap() -> RemediationRoadmapSummary:
    return demo_service.remediation_roadmap()
