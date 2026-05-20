"""Threat-to-environment correlator (skeleton).

Demonstrates the future flow without performing any real work:

    given per-tenant assets + findings + signals  ⨝  shared TI corpus
        for each dimension:
            * cve_in_inventory:
                CVE ⨝ {azure.vm image, azure.aks node image, intune.device patch state,
                       sw_inventory(packages, container images)}
            * ip_in_nsg / domain_in_traffic / url_in_traffic:
                Indicator ⨝ {azure.nsg flow logs, app-gateway logs, Sentinel/Defender
                             telemetry, M365 audit logs}
            * technique_to_finding:
                AttackPattern (MITRE technique) ⨝ Finding.mitre_techniques
            * sector_alignment:
                Campaign.target_sectors ⨝ Tenant.profile.sector
            * platform_match:
                Campaign.targeted_platforms ⨝ Tenant.tech_stack
            * malware_family_to_posture:
                Malware (family) ⨝ {exposed ports, missing EDR onboarding,
                                     weak backup, risky identity posture}
        emit CorrelationCandidate(s) → CorrelationResult per dimension

Real implementation lives in Phase 2 (basic) and Phase 4 (full). This
module's methods all return empty results today and are documented to
make the eventual integration points explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from threat_intel.contracts import (
    CorrelationCandidate,
    CorrelationDimension,
    CorrelationResult,
    NormalizedAttackPattern,
    NormalizedCampaign,
    NormalizedIndicator,
    NormalizedMalware,
    NormalizedVulnerability,
)
from threat_intel.errors import TIIsolationError


# ---------------------------------------------------------------------------
# Lightweight protocol-shaped inputs.
#
# The correlator does NOT import from apps/api/app/models/ — it stays
# package-independent. Callers (the correlation worker) supply minimal
# views over the persisted models. These dataclasses describe the shapes
# the correlator expects.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssetView:
    """Minimal projection of an asset the correlator needs."""

    tenant_id: UUID
    asset_id: str
    asset_kind: str               # AssetKind enum value, e.g. 'azure.vm'
    provider: str                 # CloudProvider enum value, e.g. 'azure'
    exposure: str = "unknown"     # ExposureLevel value
    public_ips: tuple[str, ...] = ()
    open_ports: tuple[int, ...] = ()
    edr_onboarded: bool | None = None
    backup_enabled: bool | None = None
    # Software inventory for CVE matching (CPE strings or product/version pairs).
    cpe_strings: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True, slots=True)
class FindingView:
    """Minimal projection of a finding for technique-to-finding correlation."""

    tenant_id: UUID
    finding_id: UUID
    asset_id: str
    finding_type: str
    mitre_techniques: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TenantProfile:
    """Per-tenant context used for sector / platform alignment."""

    tenant_id: UUID
    sectors: tuple[str, ...] = ()        # ['financial', 'healthcare', ...]
    geographies: tuple[str, ...] = ()    # ['EU', 'US', ...]
    tech_stack: tuple[str, ...] = ()     # ['azure', 'm365', 'kubernetes', ...]


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class Correlator:
    """Run correlation passes between TI and tenant context.

    All methods are async to match the future I/O profile (Cosmos reads
    for assets / findings, AI Search for IOC lookup). In this skeleton they
    do no I/O and return empty results.
    """

    # --- public API per dimension ----------------------------------------

    async def correlate_cve_to_inventory(
        self,
        *,
        tenant_id: UUID,
        correlation_id: str,
        vulnerabilities: list[NormalizedVulnerability],
        assets: list[AssetView],
    ) -> CorrelationResult:
        """Match KEV / CVE → customer inventory (image, package, OS).

        Skeleton — no matches produced.

        TODO(phase-2):
          * Build CPE index over ``assets[*].cpe_strings``.
          * For each vulnerability: intersect ``affected_cpes`` + ``affected_products``
            against the index; produce candidates with ``CVE_IN_INVENTORY``
            dimension.
          * Boost confidence when ``is_kev`` or ``epss_score >= 0.5``.
          * Persist evidence (which CPE matched which asset) for the AI
            engine's campaign-briefing template.
        """
        self._guard_inputs(tenant_id, assets=assets)
        return self._empty(tenant_id, correlation_id, CorrelationDimension.CVE_IN_INVENTORY)

    async def correlate_ioc_to_telemetry(
        self,
        *,
        tenant_id: UUID,
        correlation_id: str,
        indicators: list[NormalizedIndicator],
    ) -> CorrelationResult:
        """Match IP / domain / URL / hash indicators → tenant telemetry.

        Skeleton — no matches produced.

        TODO(phase-2):
          * Query Sentinel workspace via Log Analytics KQL for the past N days
            (network flow logs, Defender for Endpoint advanced hunting,
            M365 audit logs) using KQL ``ipv4_lookup`` / ``has`` joins.
          * Stream large indicator lists with watermark cursors.
          * Produce candidates for each match with ``IP_IN_NSG``,
            ``DOMAIN_IN_TRAFFIC``, or ``URL_IN_TRAFFIC`` dimensions.
        """
        self._guard_inputs(tenant_id)
        # Indicators may be a mix of dimensions; in Phase 2 split into
        # IP / DOMAIN / URL passes. For the skeleton, emit a single empty result.
        return self._empty(tenant_id, correlation_id, CorrelationDimension.IP_IN_NSG)

    async def correlate_technique_to_findings(
        self,
        *,
        tenant_id: UUID,
        correlation_id: str,
        techniques: list[NormalizedAttackPattern],
        findings: list[FindingView],
    ) -> CorrelationResult:
        """Match MITRE ATT&CK technique → existing posture finding.

        Skeleton — no matches produced.

        TODO(phase-2):
          * Build technique-id index over ``findings[*].mitre_techniques``.
          * For each technique, emit ``TECHNIQUE_TO_FINDING`` candidates
            joining the technique's ``technique_id`` to every finding tagged
            with it.
          * Sub-techniques propagate match to parent technique with a small
            confidence penalty.
        """
        self._guard_inputs(tenant_id, findings=findings)
        return self._empty(tenant_id, correlation_id, CorrelationDimension.TECHNIQUE_TO_FINDING)

    async def correlate_campaign_to_controls(
        self,
        *,
        tenant_id: UUID,
        correlation_id: str,
        campaigns: list[NormalizedCampaign],
        profile: TenantProfile,
        findings: list[FindingView],
    ) -> CorrelationResult:
        """Match campaign target sector / platform → exposed controls.

        Skeleton — no matches produced.

        TODO(phase-4):
          * Intersect ``campaign.target_sectors`` with ``profile.sectors`` and
            ``campaign.target_geographies`` with ``profile.geographies``
            → ``SECTOR_ALIGNMENT``.
          * Intersect campaign's underlying techniques with tenant
            findings to compute concrete exposure.
          * For Akira-style campaigns abusing exposed RDP: cross with
            ``Indicator``-driven IP/domain telemetry hits to elevate confidence.
        """
        self._guard_inputs(tenant_id, findings=findings)
        return self._empty(tenant_id, correlation_id, CorrelationDimension.SECTOR_ALIGNMENT)

    async def correlate_malware_to_posture(
        self,
        *,
        tenant_id: UUID,
        correlation_id: str,
        malware: list[NormalizedMalware],
        assets: list[AssetView],
        findings: list[FindingView],
    ) -> CorrelationResult:
        """Match malware family → posture conditions that enable it.

        Skeleton — no matches produced.

        TODO(phase-4):
          * Ransomware family ⇒ check {exposed ports, missing EDR onboarding,
            weak backup, risky identity posture (no MFA on privileged), legacy
            auth allowed, broad OAuth consent}.
          * Banking-trojan family ⇒ check {macro policy posture in M365, web
            content filtering posture, browser configuration profiles}.
          * Cloud-targeting malware family ⇒ check {public storage, public
            management endpoints, missing Defender for Servers}.
          * Emit ``MALWARE_FAMILY_TO_POSTURE`` candidates with the specific
            posture gap captured in ``evidence``.
        """
        self._guard_inputs(tenant_id, assets=assets, findings=findings)
        return self._empty(
            tenant_id, correlation_id, CorrelationDimension.MALWARE_FAMILY_TO_POSTURE
        )

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _guard_inputs(
        tenant_id: UUID,
        *,
        assets: list[AssetView] | None = None,
        findings: list[FindingView] | None = None,
    ) -> None:
        """Defense-in-depth: never let inputs from a different tenant slip in.

        Cross-tenant data here would be a P0 invariant violation — see
        docs/SCHEMA_DESIGN.md § 12 and docs/THREAT_INTEL_ARCHITECTURE.md.
        """
        for a in assets or []:
            if a.tenant_id != tenant_id:
                raise TIIsolationError(
                    "asset from a different tenant supplied to correlator",
                    context={"expected": str(tenant_id), "actual": str(a.tenant_id)},
                )
        for f in findings or []:
            if f.tenant_id != tenant_id:
                raise TIIsolationError(
                    "finding from a different tenant supplied to correlator",
                    context={"expected": str(tenant_id), "actual": str(f.tenant_id)},
                )

    @staticmethod
    def _empty(
        tenant_id: UUID, correlation_id: str, dimension: CorrelationDimension
    ) -> CorrelationResult:
        now = _utcnow()
        return CorrelationResult(
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            started_at=now,
            ended_at=now,
            dimension=dimension,
            candidates=[],
        )


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


__all__ = [
    "Correlator",
    "AssetView",
    "FindingView",
    "TenantProfile",
    # Re-exports for callers' convenience.
    "CorrelationCandidate",
    "CorrelationResult",
    "CorrelationDimension",
]
