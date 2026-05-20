"""Report generator.

Composes a tenant report from deterministic, evidence-derived sections.
Each section is a fully-renderable Markdown block — the report renderer
(``services/reporting`` in a later phase) takes ``ReportGenerationResult``
and produces PDF / PPTX / CSV / JSON artifacts.

Two-phase split (same pattern as ``RemediationAdvisor``):

  1. **Deterministic** (this branch) — every section's ``body`` is
     produced from the structured inputs. ``ai_enhanced=False``. This
     is what ships when AI is unavailable, and is always the audit-
     evidence path.

  2. **AI-enhanced** (Phase 5) — for executive PDFs, the AI engine
     rewrites the ``overview`` paragraph and the executive narrative
     in each section using the relevant ``GroundedEvidenceItem``s.
     Numbers, score values, and finding ids are preserved verbatim;
     the AI only changes prose. ``ai_enhanced`` flips to True per
     section that was rewritten.

No LLM, no network, no randomness in this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID, uuid4

from ai_engine.contracts import (
    ReportGenerationRequest,
    ReportGenerationResult,
    ReportGenerationStatus,
    ReportSection,
)


# ---------------------------------------------------------------------------
# Inputs the orchestrator hands to the generator
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FindingSnippet:
    """Minimal projection of one finding for report rendering."""

    finding_id: UUID
    title: str
    severity: str               # 'low' | 'medium' | 'high' | 'critical' | 'info'
    risk_score: float           # 0..100, finding-direction
    asset_id: str
    mitre_techniques: tuple[str, ...] = ()
    citation_token: str = ""


@dataclass(frozen=True, slots=True)
class ScoreSnippet:
    """Minimal projection of one posture score for report rendering."""

    score_kind: str   # 'overall' | 'identity' | 'azure_exposure' | ...
    value: int        # 0..100, posture-direction
    band: str         # 'critical' | 'weak' | 'moderate' | 'strong' | 'excellent'
    citation_token: str = ""


@dataclass(frozen=True, slots=True)
class CampaignSnippet:
    campaign_id: str
    name: str
    affected_asset_count: int
    citation_token: str = ""


@dataclass(frozen=True, slots=True)
class ReportInputs:
    """Bundle of evidence the orchestrator pre-fetched for one report.

    The orchestrator is responsible for tenant-scoping every projection;
    this dataclass intentionally has no ``tenant_id`` field per snippet —
    the report inputs as a whole belong to exactly one tenant.
    """

    overall_score: ScoreSnippet | None = None
    domain_scores: tuple[ScoreSnippet, ...] = ()
    top_findings: tuple[FindingSnippet, ...] = ()
    identity_findings: tuple[FindingSnippet, ...] = ()
    device_findings: tuple[FindingSnippet, ...] = ()
    azure_exposure_findings: tuple[FindingSnippet, ...] = ()
    compliance_findings: tuple[FindingSnippet, ...] = ()
    campaign_exposure: tuple[CampaignSnippet, ...] = ()
    prioritized_remediation_titles: tuple[str, ...] = ()
    evidence_finding_ids: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Compose deterministic report sections from structured inputs."""

    def build(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
    ) -> ReportGenerationResult:
        """Build a ``ReportGenerationResult`` for ``request`` using ``inputs``.

        The set of sections built is the intersection of
        ``request.sections_requested`` and the sections this generator
        knows how to render.
        """
        sections: list[ReportSection] = []
        builders = {
            "overview": self._build_overview,
            "posture": self._build_posture,
            "identity": self._build_identity,
            "device": self._build_device,
            "compliance": self._build_compliance,
            "threat_exposure": self._build_threat_exposure,
            "prioritized_remediations": self._build_prioritized_remediations,
            "evidence": self._build_evidence,
        }

        order_index = 0
        for section_id in request.sections_requested:
            builder = builders.get(section_id)
            if builder is None:
                continue
            section = builder(request, inputs, order=order_index)
            sections.append(section)
            order_index += 1

        title = request.title or _default_title(request)

        return ReportGenerationResult(
            result_id=uuid4(),
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            title=title,
            sections=sections,
            citations=_collect_citations(sections),
            status=(
                ReportGenerationStatus.COMPLETE
                if sections
                else ReportGenerationStatus.PARTIAL
            ),
            generated_at=_utcnow(),
        )

    # --- per-section builders --------------------------------------------

    def _build_overview(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        lines = ["# Overview", ""]
        if inputs.overall_score:
            s = inputs.overall_score
            cite = f" {s.citation_token}" if s.citation_token else ""
            lines.append(
                f"The tenant's overall posture score is **{s.value}/100** "
                f"(band: *{s.band}*).{cite}"
            )
        else:
            lines.append("No overall posture score has been computed yet.")

        if inputs.campaign_exposure:
            campaigns = ", ".join(
                f"{c.name} ({c.affected_asset_count} affected asset(s)){_token_suffix(c.citation_token)}"
                for c in inputs.campaign_exposure[:5]
            )
            lines.extend(["", f"Currently exposed to: {campaigns}."])

        return ReportSection(
            section_id="overview",
            title="Overview",
            order=order,
            body="\n".join(lines),
            ai_enhanced=False,
            citations=_citations_from(
                [inputs.overall_score]
                + list(inputs.campaign_exposure[:5])
            ),
            structured_data={
                "overall_score": (
                    {"value": inputs.overall_score.value, "band": inputs.overall_score.band}
                    if inputs.overall_score
                    else None
                ),
                "active_campaigns": [c.name for c in inputs.campaign_exposure[:5]],
            },
            generated_at=_utcnow(),
        )
        # TODO(phase-5): replace the overview paragraph with the AI-rendered
        # `exec.summary.v1` output. Numbers are kept verbatim; prose only.

    def _build_posture(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        lines = ["# Posture by domain", "", "| Domain | Score | Band |", "|---|---|---|"]
        for s in inputs.domain_scores:
            cite = f" {s.citation_token}" if s.citation_token else ""
            lines.append(f"| {s.score_kind} | {s.value} | {s.band}{cite} |")
        return ReportSection(
            section_id="posture",
            title="Posture by domain",
            order=order,
            body="\n".join(lines),
            ai_enhanced=False,
            citations=_citations_from(inputs.domain_scores),
            structured_data={
                "domain_scores": [
                    {"kind": s.score_kind, "value": s.value, "band": s.band}
                    for s in inputs.domain_scores
                ],
            },
            generated_at=_utcnow(),
        )

    def _build_identity(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        return _build_findings_section(
            section_id="identity",
            title="Identity findings",
            findings=inputs.identity_findings,
            order=order,
        )

    def _build_device(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        return _build_findings_section(
            section_id="device",
            title="Device findings",
            findings=inputs.device_findings,
            order=order,
        )

    def _build_compliance(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        return _build_findings_section(
            section_id="compliance",
            title="Compliance findings",
            findings=inputs.compliance_findings,
            order=order,
        )

    def _build_threat_exposure(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        lines = ["# Threat exposure", ""]
        if not inputs.campaign_exposure:
            lines.append("No active campaign correlations at the time of generation.")
        else:
            lines.append("| Campaign | Affected assets |")
            lines.append("|---|---|")
            for c in inputs.campaign_exposure:
                cite = f" {c.citation_token}" if c.citation_token else ""
                lines.append(f"| {c.name}{cite} | {c.affected_asset_count} |")
        return ReportSection(
            section_id="threat_exposure",
            title="Threat exposure",
            order=order,
            body="\n".join(lines),
            ai_enhanced=False,
            citations=_citations_from(inputs.campaign_exposure),
            structured_data={
                "campaigns": [
                    {"id": c.campaign_id, "name": c.name, "affected": c.affected_asset_count}
                    for c in inputs.campaign_exposure
                ],
            },
            generated_at=_utcnow(),
        )
        # TODO(phase-5): replace per-campaign blurbs with `campaign.brief.v1`
        # output rendered against the campaign's ti evidence.

    def _build_prioritized_remediations(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        lines = ["# Prioritized remediations", ""]
        if not inputs.prioritized_remediation_titles:
            lines.append("No remediations available at the time of generation.")
        else:
            for i, title in enumerate(inputs.prioritized_remediation_titles, 1):
                lines.append(f"{i}. {title}")
        return ReportSection(
            section_id="prioritized_remediations",
            title="Prioritized remediations",
            order=order,
            body="\n".join(lines),
            ai_enhanced=False,
            citations=[],
            structured_data={"titles": list(inputs.prioritized_remediation_titles)},
            generated_at=_utcnow(),
        )
        # TODO(phase-5): for each title, attach the AI-rewritten executive
        # rationale using `finding.remediate.v1` (audience=executive).

    def _build_evidence(
        self,
        request: ReportGenerationRequest,
        inputs: ReportInputs,
        *,
        order: int,
    ) -> ReportSection:
        lines = ["# Evidence", ""]
        if not inputs.evidence_finding_ids:
            lines.append("No additional evidence supplied.")
        else:
            lines.append(f"This report references {len(inputs.evidence_finding_ids)} findings.")
            for ref in inputs.evidence_finding_ids[:50]:
                lines.append(f"- `{ref}`")
            if len(inputs.evidence_finding_ids) > 50:
                lines.append(f"- … and {len(inputs.evidence_finding_ids) - 50} more.")
        if inputs.notes:
            lines.append("")
            lines.append("## Notes")
            for n in inputs.notes:
                lines.append(f"- {n}")
        return ReportSection(
            section_id="evidence",
            title="Evidence",
            order=order,
            body="\n".join(lines),
            ai_enhanced=False,
            citations=[],
            structured_data={
                "evidence_finding_ids": list(inputs.evidence_finding_ids),
                "notes": list(inputs.notes),
            },
            generated_at=_utcnow(),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_findings_section(
    *,
    section_id: str,
    title: str,
    findings: tuple[FindingSnippet, ...],
    order: int,
) -> ReportSection:
    lines = [f"# {title}", ""]
    if not findings:
        lines.append("No findings in this category.")
        structured = {}
    else:
        lines.append("| Risk | Severity | Title |")
        lines.append("|---|---|---|")
        for f in findings:
            cite = f" {f.citation_token}" if f.citation_token else ""
            lines.append(
                f"| {f.risk_score:.0f} | {f.severity} | {f.title}{cite} |"
            )
        structured = {
            "findings": [
                {
                    "id": str(f.finding_id),
                    "title": f.title,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                }
                for f in findings
            ]
        }
    return ReportSection(
        section_id=section_id,
        title=title,
        order=order,
        body="\n".join(lines),
        ai_enhanced=False,
        citations=_citations_from(findings),
        structured_data=structured,
        generated_at=_utcnow(),
    )
    # TODO(phase-5): per-finding `finding.explain.v1` paragraph attached
    # underneath the table when the finding's risk score exceeds the
    # tenant's prose threshold.


def _citations_from(items: Iterable[object | None]) -> list[str]:
    out: list[str] = []
    for it in items:
        if it is None:
            continue
        token = getattr(it, "citation_token", "")
        if token:
            out.append(token)
    return out


def _collect_citations(sections: list[ReportSection]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for s in sections:
        for c in s.citations:
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out


def _token_suffix(token: str) -> str:
    return f" {token}" if token else ""


def _default_title(request: ReportGenerationRequest) -> str:
    kind = request.report_kind.replace("_", " ").title()
    return f"AzureLens {kind}"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


__all__ = [
    "CampaignSnippet",
    "FindingSnippet",
    "ReportGenerator",
    "ReportInputs",
    "ScoreSnippet",
]
