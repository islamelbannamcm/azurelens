"""Compliance framework & mapping models.

Each finding is tagged against multiple frameworks. The crosswalks
(MITRE ↔ MCSB ↔ CIS ↔ NIST ↔ ISO ↔ SOC 2 ↔ GDPR ↔ Zero Trust ↔ M365 baseline ↔
Azure WAF) are persisted as versioned reference packs and surfaced as the
``FrameworkMappings`` shape embedded on a Finding.

Future work (Phase 1+ then Phase 3 expansion):
  * Persist framework reference packs in ``packages/frameworks/`` and load via
    a signed, versioned loader.
  * Compute per-tenant ``ComplianceFrameworkPosture`` projections in the
    compliance engine.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import Field

from app.models.common import AzureLensModel, TenantScoped


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ComplianceFramework(str, Enum):
    """Frameworks AzureLens maps findings against."""

    CIS_AZURE = "cis_azure"
    MCSB = "mcsb"                          # Microsoft Cloud Security Benchmark
    NIST_CSF = "nist_csf"                  # NIST Cybersecurity Framework 2.0
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    GDPR = "gdpr"
    ZERO_TRUST = "zero_trust"
    AZURE_WAF = "azure_waf"                # Azure Well-Architected Framework (Security)
    M365_BASELINE = "m365_baseline"
    CIS_M365 = "cis_m365"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"


class ComplianceControlStatus(str, Enum):
    """Per-control posture state for a tenant."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    INSUFFICIENT_DATA = "insufficient_data"


# ---------------------------------------------------------------------------
# Reference data (packs)
# ---------------------------------------------------------------------------


class FrameworkControl(AzureLensModel):
    """One control entry inside a framework reference pack."""

    control_id: str = Field(..., description="Framework-native control id, e.g. '1.1.1' or 'PR.AC-1'.")
    title: str
    category: str | None = Field(default=None)
    severity_hint: str | None = Field(
        default=None, description="Suggested severity for findings violating this control."
    )
    # Crosswalks to other frameworks (sparse).
    mappings: dict[str, list[str]] = Field(
        default_factory=dict,
        description="e.g. {'mcsb': ['IM-7'], 'nist_csf': ['PR.AC-1'], 'mitre_techniques': ['T1078']}.",
    )


class FrameworkPack(AzureLensModel):
    """Versioned reference pack for one framework."""

    framework: ComplianceFramework
    version: str = Field(..., description="Semantic version of the pack, e.g. '2.1.0'.")
    title: str
    controls: list[FrameworkControl] = Field(default_factory=list)
    published_at: datetime
    source_url: str | None = Field(default=None)


# ---------------------------------------------------------------------------
# Finding-side mapping shape
# ---------------------------------------------------------------------------


class FrameworkControlRef(AzureLensModel):
    """Pointer to a framework + version + one or more control ids."""

    version: str
    controls: list[str] = Field(default_factory=list)


class FrameworkMappings(AzureLensModel):
    """Strict shape of the ``framework_mappings`` field embedded on a Finding."""

    cis_azure: list[FrameworkControlRef] = Field(default_factory=list)
    mcsb: list[FrameworkControlRef] = Field(default_factory=list)
    nist_csf: list[FrameworkControlRef] = Field(default_factory=list)
    nist_800_53: list[FrameworkControlRef] = Field(default_factory=list)
    iso_27001: list[FrameworkControlRef] = Field(default_factory=list)
    soc2: list[FrameworkControlRef] = Field(default_factory=list)
    gdpr_articles: list[int] = Field(default_factory=list, description="e.g. [5, 25, 32].")
    zero_trust_pillars: list[str] = Field(default_factory=list)
    azure_waf_pillars: list[str] = Field(default_factory=list)
    m365_baseline: list[FrameworkControlRef] = Field(default_factory=list)
    cis_m365: list[FrameworkControlRef] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Per-tenant posture projections
# ---------------------------------------------------------------------------


class ComplianceControlState(TenantScoped):
    """One control's posture state for one tenant."""

    framework: ComplianceFramework
    version: str
    control_id: str
    status: ComplianceControlStatus = Field(default=ComplianceControlStatus.INSUFFICIENT_DATA)
    open_finding_count: int = Field(default=0, ge=0)
    evidence_finding_ids: list[UUID] = Field(default_factory=list)
    last_evaluated_at: datetime


class ComplianceFrameworkPosture(TenantScoped):
    """Roll-up of a single framework's posture for one tenant."""

    framework: ComplianceFramework
    version: str
    total_controls: int = Field(..., ge=0)
    compliant: int = Field(default=0, ge=0)
    partially_compliant: int = Field(default=0, ge=0)
    non_compliant: int = Field(default=0, ge=0)
    not_applicable: int = Field(default=0, ge=0)
    insufficient_data: int = Field(default=0, ge=0)
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    last_evaluated_at: datetime
