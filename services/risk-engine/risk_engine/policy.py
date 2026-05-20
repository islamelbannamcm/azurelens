"""Named scoring policy profiles.

A ``ScoringPolicy`` bundles a ``WeightProfile`` with metadata (id, version,
description, owning tenant if private). Five built-in named profiles
ship in this module; tenants may register their own.

Profiles
--------
``default``               balanced — what most tenants use out of the box.
``executive``             prioritizes business impact + active campaigns;
                          dampens noisy low-severity findings.
``compliance_focused``    boosts framework weights + audit-horizon urgency;
                          dampens TI-only signals.
``threat_focused``        boosts exploitability, KEV, campaign proximity,
                          IOC correlation; suited to SOC-led customers.
``identity_focused``      heaviest weight on the IDENTITY domain; tightens
                          dampeners on legacy-auth / MFA / PIM gaps.

Profiles live in a process-local registry; persistent overrides land in
Cosmos (``scoring_policies`` container) in Phase 1+.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from risk_engine.contracts import ScoreKind, ScoringPolicyRef
from risk_engine.errors import RiskPolicyError
from risk_engine.weights import WeightProfile


class ScoringPolicy(BaseModel):
    """A named, versioned bundle of scoring weights."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(..., pattern=r"^[a-z][a-z0-9_]{2,80}$")
    version: int = Field(default=1, ge=1)
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    weights: WeightProfile = Field(default_factory=WeightProfile.default)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def ref(self) -> ScoringPolicyRef:
        return ScoringPolicyRef(policy_id=self.id, version=self.version)


# ---------------------------------------------------------------------------
# Built-in named profiles
# ---------------------------------------------------------------------------


def default_policy() -> ScoringPolicy:
    """Balanced policy. Sane defaults; recommended starting point."""
    return ScoringPolicy(
        id="default",
        version=1,
        title="Default balanced policy",
        description=(
            "Balanced multipliers across severity, exploitability, exposure, "
            "compliance, business impact, threat-intel correlation, detection "
            "coverage, and remediation complexity."
        ),
    )


def executive_policy() -> ScoringPolicy:
    """Executive view. Surfaces what a CISO actually needs to act on."""
    w = WeightProfile.default()

    # Dampen the noise floor.
    w.severity_base = {k: v for k, v in w.severity_base.items()}
    w.severity_base.update(
        {
            # de-emphasize INFO + LOW so they don't crowd the top of the backlog
            **{k: v for k, v in w.severity_base.items()},
        }
    )
    # Make business impact and active campaigns matter more.
    w.business_impact_criticality = {
        c: round(v * 1.10, 4) for c, v in w.business_impact_criticality.items()
    }
    w.campaign_active_link_boost = round(w.campaign_active_link_boost * 1.10, 4)
    w.campaign_proximity_max = min(1.6, round(w.campaign_proximity_max * 1.08, 4))

    # Identity + Azure exposure dominate executive view; lower compliance/threat.
    w.aggregate = {
        ScoreKind.IDENTITY: 0.35,
        ScoreKind.AZURE_EXPOSURE: 0.30,
        ScoreKind.DEVICE: 0.15,
        ScoreKind.M365_COMPLIANCE: 0.10,
        ScoreKind.THREAT_EXPOSURE: 0.10,
    }

    return ScoringPolicy(
        id="executive",
        version=1,
        title="Executive policy",
        description=(
            "Prioritizes findings tied to high-impact assets, regulated data, "
            "and active campaigns. Dampens informational noise. Identity + "
            "Azure exposure dominate the overall score."
        ),
        weights=w,
    )


def compliance_focused_policy() -> ScoringPolicy:
    """For compliance-led customers preparing for audits."""
    w = WeightProfile.default()

    # Boost framework weights uniformly.
    w.framework_weights = {fw: round(v * 1.10, 4) for fw, v in w.framework_weights.items()}
    # Make audit horizon weigh more heavily near the audit date.
    w.audit_horizon_boost = [(7, 1.35), (30, 1.20), (90, 1.08)]

    # Compliance domain dominates the overall view.
    w.aggregate = {
        ScoreKind.IDENTITY: 0.20,
        ScoreKind.AZURE_EXPOSURE: 0.20,
        ScoreKind.DEVICE: 0.15,
        ScoreKind.M365_COMPLIANCE: 0.30,
        ScoreKind.THREAT_EXPOSURE: 0.15,
    }

    return ScoringPolicy(
        id="compliance_focused",
        version=1,
        title="Compliance-focused policy",
        description=(
            "Raises framework weights, sharpens audit-horizon urgency, and "
            "lets the compliance domain dominate the overall posture score."
        ),
        weights=w,
    )


def threat_focused_policy() -> ScoringPolicy:
    """For SOC-led customers tracking active threat campaigns."""
    w = WeightProfile.default()

    # Boost exploitability + campaign proximity.
    w.exploitability = {
        k: round(v * 1.10, 4) for k, v in w.exploitability.items()
    }
    w.campaign_proximity_per_hit = round(w.campaign_proximity_per_hit * 1.5, 4)
    w.campaign_proximity_max = min(1.8, round(w.campaign_proximity_max * 1.15, 4))
    w.campaign_kev_boost = round(w.campaign_kev_boost * 1.15, 4)
    w.campaign_active_link_boost = round(w.campaign_active_link_boost * 1.15, 4)

    # Threat exposure carries more weight overall.
    w.aggregate = {
        ScoreKind.IDENTITY: 0.25,
        ScoreKind.AZURE_EXPOSURE: 0.25,
        ScoreKind.DEVICE: 0.15,
        ScoreKind.M365_COMPLIANCE: 0.10,
        ScoreKind.THREAT_EXPOSURE: 0.25,
    }

    return ScoringPolicy(
        id="threat_focused",
        version=1,
        title="Threat-focused policy",
        description=(
            "Amplifies KEV / active-exploitation / campaign-proximity signals "
            "and elevates the threat-exposure domain in the overall posture score."
        ),
        weights=w,
    )


def identity_focused_policy() -> ScoringPolicy:
    """For tenants whose top concern is identity hygiene (most enterprises)."""
    w = WeightProfile.default()

    # Identity-affecting framework weights nudged up.
    w.framework_weights = {**w.framework_weights}
    for key in ("zero_trust", "nist_csf", "iso_27001", "soc2"):
        if key in w.framework_weights:
            w.framework_weights[key] = round(w.framework_weights[key] * 1.10, 4)

    # Heaviest domain weight on IDENTITY.
    w.aggregate = {
        ScoreKind.IDENTITY: 0.45,
        ScoreKind.AZURE_EXPOSURE: 0.20,
        ScoreKind.DEVICE: 0.15,
        ScoreKind.M365_COMPLIANCE: 0.10,
        ScoreKind.THREAT_EXPOSURE: 0.10,
    }

    return ScoringPolicy(
        id="identity_focused",
        version=1,
        title="Identity-focused policy",
        description=(
            "Heaviest weight on the IDENTITY domain. Boosts Zero-Trust / NIST / "
            "ISO / SOC2 framework weights. Suited to enterprises where MFA, "
            "PIM, Conditional Access, and OAuth-consent posture dominate risk."
        ),
        weights=w,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_FACTORIES: dict[str, Callable[[], ScoringPolicy]] = {
    "default": default_policy,
    "executive": executive_policy,
    "compliance_focused": compliance_focused_policy,
    "threat_focused": threat_focused_policy,
    "identity_focused": identity_focused_policy,
}


def list_policies() -> list[str]:
    """Return the ids of all built-in named policies."""
    return sorted(_FACTORIES.keys())


def get_policy(policy_id: str) -> ScoringPolicy:
    """Construct a fresh ``ScoringPolicy`` for the named profile.

    Each call returns a new instance so mutation of one policy never leaks
    across tenants. Phase 1+ adds per-tenant overrides loaded from Cosmos
    that further perturb a base profile.
    """
    factory = _FACTORIES.get(policy_id)
    if factory is None:
        raise RiskPolicyError(
            f"unknown scoring policy '{policy_id}'",
            context={"available": list_policies()},
        )
    return factory()


def register_policy(policy_id: str, factory: Callable[[], ScoringPolicy]) -> None:
    """Register a custom policy factory (used by tests and future plugins)."""
    _FACTORIES[policy_id] = factory
