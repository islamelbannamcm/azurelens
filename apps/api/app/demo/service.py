"""Demo service layer.

A thin, read-mostly facade over the constants in ``data.py``. Routers
talk to ``demo_service`` rather than the data module directly so the
swap to real persistence in Phase 1+ is a one-line change inside the
service constructor.

Every method returns deep copies of the underlying records (via Pydantic
``model_copy``) for endpoints that look mutating from the outside
(scan trigger, remediation approval); the in-memory store stays
pristine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.demo import data as demo_data
from app.models import (
    Asset,
    AssetSummary,
    Campaign,
    ComplianceFramework,
    ComplianceFrameworkPosture,
    Finding,
    ScanKind,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Score,
    ScoreKind,
    Severity,
    Tenant,
)
from app.models.finding import FindingSummary
from app.models.report import (
    RemediationAction,
    RemediationStatus,
    RemediationTemplate,
)
from app.models.threat_intel import CampaignExposureSummary, CorrelationHit


# ---------------------------------------------------------------------------
# Dashboard projection shapes (defined here, not in app.models, because they
# are demo-only convenience composites — the API documents them in
# docs/API_CONTRACTS.md once stabilized).
# ---------------------------------------------------------------------------


class OverallScoreSummary(BaseModel):
    """Posture score summary card shown at the top of the dashboard."""

    score_kind: ScoreKind = ScoreKind.OVERALL
    value: int = Field(..., ge=0, le=100)
    band: str
    calculated_at: datetime
    delta_7d: int = 0


class DomainScoreSummary(BaseModel):
    score_kind: ScoreKind
    value: int = Field(..., ge=0, le=100)
    band: str


class TopRiskItem(BaseModel):
    finding_id: UUID
    title: str
    severity: Severity
    risk_score: float
    asset_id: str
    finding_type: str


class ComplianceFrameworkSummary(BaseModel):
    framework: ComplianceFramework
    version: str
    score: float = Field(..., ge=0.0, le=100.0)
    non_compliant: int = 0
    partially_compliant: int = 0


class ThreatExposureSummary(BaseModel):
    active_campaigns: list[CampaignExposureSummary]
    kev_cve_count: int
    mitre_techniques_observed: list[str]
    correlation_count: int


class RecentScanSummary(BaseModel):
    scan_id: UUID | None = None
    kinds: list[ScanKind] = Field(default_factory=list)
    status: ScanStatus | None = None
    requested_at: datetime | None = None
    completed_at: datetime | None = None
    findings_produced: int = 0


class RemediationRoadmapSummary(BaseModel):
    open: int = 0
    suggested: int = 0
    requested: int = 0
    approved: int = 0
    in_progress: int = 0
    succeeded: int = 0
    failed: int = 0
    next_actions: list[RemediationAction] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    tenant_id: UUID
    tenant_name: str
    overall: OverallScoreSummary
    domain_scores: list[DomainScoreSummary]
    top_risks: list[TopRiskItem]
    threat_exposure: ThreatExposureSummary
    compliance_summary: list[ComplianceFrameworkSummary]
    recent_scan: RecentScanSummary
    remediation_roadmap: RemediationRoadmapSummary
    generated_at: datetime


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class DemoService:
    """Read-mostly facade over the demo dataset.

    The constructor is intentionally trivial so this class can be replaced
    by a real persistence-backed service in Phase 1 without changing the
    method signatures.
    """

    # ----------------------------------------------------------- tenant

    def get_tenant(self) -> Tenant:
        return demo_data.TENANT

    # ------------------------------------------------------------ assets

    def list_assets(self) -> list[AssetSummary]:
        return [self._asset_to_summary(a) for a in demo_data.ASSETS]

    def get_asset(self, asset_id: str) -> Asset | None:
        for a in demo_data.ASSETS:
            if a.id == asset_id:
                return a
        return None

    @staticmethod
    def _asset_to_summary(asset: Asset) -> AssetSummary:
        # Top finding severity tied to this asset (cheap O(N) demo scan).
        related = [f for f in demo_data.FINDINGS if f.asset_id == asset.id]
        related_open = [f for f in related if f.status.value not in ("remediated", "false_positive")]
        highest: str | None = None
        if related_open:
            order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            for sev in order:
                if any(f.severity is sev for f in related_open):
                    highest = sev.value
                    break
        return AssetSummary(
            id=asset.id,
            tenant_id=asset.tenant_id,
            asset_kind=asset.asset_kind,
            provider=asset.provider,
            display_name=asset.display_name,
            exposure=asset.exposure,
            criticality=asset.criticality,
            open_finding_count=len(related_open),
            highest_finding_severity=highest,
        )

    # ----------------------------------------------------------- findings

    def list_findings(
        self,
        *,
        severity: Severity | None = None,
        status: str | None = None,
        asset_id: str | None = None,
        limit: int = 50,
    ) -> list[FindingSummary]:
        out: list[FindingSummary] = []
        for fs in demo_data.FINDING_SUMMARIES:
            if severity is not None and fs.severity is not severity:
                continue
            if status is not None and fs.status.value != status:
                continue
            if asset_id is not None and fs.asset_id != asset_id:
                continue
            out.append(fs)
            if len(out) >= limit:
                break
        return out

    def get_finding(self, finding_id: UUID) -> Finding | None:
        for f in demo_data.FINDINGS:
            if f.id == finding_id:
                return f
        return None

    def top_risks(self, limit: int = 5) -> list[TopRiskItem]:
        """Top risks by ``risk_score`` over OPEN findings."""
        ranked = sorted(
            (f for f in demo_data.FINDINGS if f.status.value == "open"),
            key=lambda f: f.risk_score,
            reverse=True,
        )
        return [
            TopRiskItem(
                finding_id=f.id,
                title=f.title,
                severity=f.severity,
                risk_score=f.risk_score,
                asset_id=f.asset_id,
                finding_type=f.finding_type,
            )
            for f in ranked[:limit]
        ]

    # ------------------------------------------------------------ scores

    def list_scores(self) -> list[Score]:
        return list(demo_data.CURRENT_SCORES)

    def get_score(self, kind: ScoreKind) -> Score | None:
        for s in demo_data.CURRENT_SCORES:
            if s.score_kind is kind:
                return s
        return None

    def get_score_history(
        self, kind: ScoreKind, *, days: int = 14
    ) -> list[tuple[datetime, int]]:
        series = demo_data.SCORE_HISTORY.get(kind, [])
        return list(series)[-max(1, days):]

    def overall_score_summary(self) -> OverallScoreSummary:
        overall = self.get_score(ScoreKind.OVERALL)
        if overall is None:  # pragma: no cover — demo data ensures presence
            return OverallScoreSummary(value=0, band="critical", calculated_at=_utcnow())
        # Delta vs 7 days ago, if we have history.
        history = self.get_score_history(ScoreKind.OVERALL, days=8)
        delta = overall.value - history[0][1] if len(history) >= 2 else 0
        return OverallScoreSummary(
            value=overall.value,
            band=overall.band.value,
            calculated_at=overall.calculated_at,
            delta_7d=delta,
        )

    def domain_score_summaries(self) -> list[DomainScoreSummary]:
        return [
            DomainScoreSummary(score_kind=s.score_kind, value=s.value, band=s.band.value)
            for s in demo_data.CURRENT_SCORES
            if s.score_kind is not ScoreKind.OVERALL
        ]

    # ------------------------------------------------------------ threats

    def list_campaigns(self) -> list[Campaign]:
        return list(demo_data.CAMPAIGNS)

    def list_correlations(self) -> list[CorrelationHit]:
        return list(demo_data.CORRELATIONS)

    def threat_exposure_summary(self) -> ThreatExposureSummary:
        techniques: list[str] = []
        for f in demo_data.FINDINGS:
            for t in f.mitre_techniques:
                if t not in techniques:
                    techniques.append(t)
        return ThreatExposureSummary(
            active_campaigns=list(demo_data.CAMPAIGN_EXPOSURE),
            kev_cve_count=sum(1 for v in demo_data.VULNERABILITIES if v.is_kev),
            mitre_techniques_observed=techniques,
            correlation_count=len(demo_data.CORRELATIONS),
        )

    # --------------------------------------------------------- compliance

    def list_compliance_posture(self) -> list[ComplianceFrameworkPosture]:
        return list(demo_data.COMPLIANCE_POSTURE)

    def compliance_summary(self) -> list[ComplianceFrameworkSummary]:
        return [
            ComplianceFrameworkSummary(
                framework=p.framework,
                version=p.version,
                score=p.score,
                non_compliant=p.non_compliant,
                partially_compliant=p.partially_compliant,
            )
            for p in demo_data.COMPLIANCE_POSTURE
        ]

    # ------------------------------------------------------------- scans

    def list_scans(self) -> list[ScanSummary]:
        return list(demo_data.SCAN_HISTORY)

    def get_scan(self, scan_id: UUID) -> ScanSummary | None:
        for s in demo_data.SCAN_HISTORY:
            if s.id == scan_id:
                return s
        return None

    def recent_scan(self) -> RecentScanSummary:
        if not demo_data.SCAN_HISTORY:
            return RecentScanSummary()
        s = demo_data.SCAN_HISTORY[0]
        return RecentScanSummary(
            scan_id=s.id,
            kinds=s.kinds,
            status=s.status,
            requested_at=s.requested_at,
            completed_at=s.completed_at,
            findings_produced=s.findings_produced,
        )

    def trigger_scan(self, payload: ScanRequest) -> ScanSummary:
        """Return a deterministic "queued" scan synthesized from the request.

        No work is performed; the demo dataset is not mutated. Phase 1
        replaces this with a Service Bus emit + Cosmos write.
        """
        return ScanSummary(
            tenant_id=demo_data.TENANT_ID,
            id=uuid4(),
            kinds=payload.kinds,
            trigger_type=payload.trigger_type,
            status=ScanStatus.QUEUED,
            requested_at=_utcnow(),
            started_at=None,
            completed_at=None,
            partitions_total=None,
            partitions_completed=0,
            findings_produced=0,
            error_summary=None,
        )

    # --------------------------------------------------------- remediation

    def list_remediation_actions(
        self,
        *,
        status: RemediationStatus | None = None,
    ) -> list[RemediationAction]:
        if status is None:
            return list(demo_data.REMEDIATION_ACTIONS)
        return [a for a in demo_data.REMEDIATION_ACTIONS if a.status is status]

    def get_remediation_action(self, action_id: UUID) -> RemediationAction | None:
        for a in demo_data.REMEDIATION_ACTIONS:
            if a.id == action_id:
                return a
        return None

    def list_remediation_templates(self) -> list[RemediationTemplate]:
        return list(demo_data.REMEDIATION_TEMPLATES)

    def approve_remediation_action(self, action_id: UUID) -> RemediationAction | None:
        original = self.get_remediation_action(action_id)
        if original is None:
            return None
        # Return a copy advanced to APPROVED; the underlying store is unchanged.
        return original.model_copy(
            update={
                "status": RemediationStatus.APPROVED,
                "approved_by": demo_data.REQUESTER_ID,
            }
        )

    def remediation_roadmap(self) -> RemediationRoadmapSummary:
        by_status: dict[RemediationStatus, int] = {s: 0 for s in RemediationStatus}
        for a in demo_data.REMEDIATION_ACTIONS:
            by_status[a.status] += 1
        next_actions = [
            a
            for a in demo_data.REMEDIATION_ACTIONS
            if a.status
            in (
                RemediationStatus.SUGGESTED,
                RemediationStatus.REQUESTED,
                RemediationStatus.APPROVED,
            )
        ][:5]
        # "open" = anything not yet succeeded / failed / rolled_back.
        terminal = {
            RemediationStatus.SUCCEEDED,
            RemediationStatus.FAILED,
            RemediationStatus.ROLLED_BACK,
        }
        open_total = sum(
            v for status, v in by_status.items() if status not in terminal
        )
        return RemediationRoadmapSummary(
            open=open_total,
            suggested=by_status[RemediationStatus.SUGGESTED],
            requested=by_status[RemediationStatus.REQUESTED],
            approved=by_status[RemediationStatus.APPROVED],
            in_progress=by_status[RemediationStatus.EXECUTING],
            succeeded=by_status[RemediationStatus.SUCCEEDED],
            failed=by_status[RemediationStatus.FAILED],
            next_actions=next_actions,
        )

    # --------------------------------------------------------- dashboard

    def dashboard_summary(self) -> DashboardSummary:
        tenant = self.get_tenant()
        return DashboardSummary(
            tenant_id=tenant.id,
            tenant_name=tenant.display_name,
            overall=self.overall_score_summary(),
            domain_scores=self.domain_score_summaries(),
            top_risks=self.top_risks(limit=5),
            threat_exposure=self.threat_exposure_summary(),
            compliance_summary=self.compliance_summary(),
            recent_scan=self.recent_scan(),
            remediation_roadmap=self.remediation_roadmap(),
            generated_at=_utcnow(),
        )


# ---------------------------------------------------------------------------
# Helpers + singleton
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


#: Module-level singleton. Routers import this directly.
demo_service: DemoService = DemoService()


__all__ = [
    "ComplianceFrameworkSummary",
    "DashboardSummary",
    "DemoService",
    "DomainScoreSummary",
    "OverallScoreSummary",
    "RecentScanSummary",
    "RemediationRoadmapSummary",
    "ThreatExposureSummary",
    "TopRiskItem",
    "demo_service",
]
