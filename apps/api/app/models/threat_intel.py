"""Threat-intelligence models (STIX-aligned).

Shapes are intentionally close to STIX 2.1 SDOs so that ingestion connectors
(Defender TI, Sentinel TI, CISA KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch,
GHSA, NVD) can map cleanly. See docs/SCHEMA_DESIGN.md § 5.

Future work (Phase 2):
  * Persist in Cosmos DB containers ``ti_indicators``, ``ti_campaigns``,
    ``ti_vulnerabilities``, ``ti_threat_actors``, ``ti_malware``,
    ``ti_tools``, ``ti_attack_patterns``, ``ti_relationships``,
    ``ti_correlations``.
  * Index searchable fields in Azure AI Search for RAG retrieval.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import Field, HttpUrl

from app.models.common import AzureLensModel, TenantScoped
from app.models.finding import MitreTactic, Severity


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TISource(str, Enum):
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
    TENANT_PRIVATE = "tenant_private"


class StixObjectType(str, Enum):
    """STIX 2.1 SDO types we model directly."""

    INDICATOR = "indicator"
    CAMPAIGN = "campaign"
    THREAT_ACTOR = "threat-actor"
    MALWARE = "malware"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
    ATTACK_PATTERN = "attack-pattern"
    MITIGATION = "course-of-action"
    RELATIONSHIP = "relationship"


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    REGKEY = "regkey"
    FILENAME = "filename"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    JA3 = "ja3"


class Confidence(str, Enum):
    """Three-band confidence used across TI; numeric 0-100 stored separately."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CorrelationDimension(str, Enum):
    """What dimension matched a TI object to a tenant asset."""

    CVE_IN_INVENTORY = "cve_in_inventory"
    IP_IN_NSG = "ip_in_nsg"
    DOMAIN_IN_TRAFFIC = "domain_in_traffic"
    URL_IN_TRAFFIC = "url_in_traffic"
    TECHNIQUE_TO_FINDING = "technique_to_finding"
    SECTOR_ALIGNMENT = "sector_alignment"
    PLATFORM_MATCH = "platform_match"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TIBase(AzureLensModel):
    """Common envelope around STIX-aligned objects.

    Shared TI lives in a global corpus (``tenant_id = 'shared'``); tenant-private
    TI is partitioned by the customer tenant id. The ``tenant_id`` field is
    represented as a string here because the global corpus uses the literal
    ``'shared'``; the Cosmos partition-key serializer handles this in Phase 2.
    """

    id: str = Field(..., description="Source-qualified id, e.g. 'misp::1234' or 'cisa_kev::CVE-2024-...'.")
    tenant_id: str = Field(default="shared", description="'shared' or tenant UUID string.")
    stix_type: StixObjectType
    sources: list[TISource] = Field(default_factory=list)
    external_references: list[HttpUrl] = Field(default_factory=list)
    valid_from: datetime
    valid_until: datetime | None = Field(default=None)
    confidence: int = Field(default=50, ge=0, le=100)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    labels: list[str] = Field(default_factory=list)
    schema_version: int = Field(default=1, ge=1)


class Indicator(TIBase):
    """STIX Indicator (IOC)."""

    indicator_type: IndicatorType
    value: str = Field(..., min_length=1, max_length=2048)
    pattern: str | None = Field(
        default=None,
        description="STIX pattern expression; optional if `value`+`indicator_type` are sufficient.",
    )
    kill_chain_phases: list[str] = Field(default_factory=list)


class Campaign(TIBase):
    """STIX Campaign."""

    name: str = Field(..., min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    aliases: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    objective: str | None = Field(
        default=None,
        description="ransomware | espionage | hacktivism | data-theft | unknown",
    )
    target_sectors: list[str] = Field(default_factory=list)
    target_geographies: list[str] = Field(default_factory=list)
    attributed_to: list[str] = Field(default_factory=list, description="ThreatActor STIX ids.")
    techniques: list[str] = Field(default_factory=list, description="MITRE technique ids.")
    tactics: list[MitreTactic] = Field(default_factory=list)
    indicator_ids: list[str] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)


class Vulnerability(TIBase):
    """STIX Vulnerability with CVE / KEV / EPSS extensions."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str | None = Field(default=None, max_length=400)
    cvss_v3: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v4: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    is_kev: bool = Field(default=False, description="Listed in CISA KEV catalog.")
    kev_added_date: datetime | None = Field(default=None)
    affected_cpes: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    severity: Severity = Field(default=Severity.HIGH)


class ThreatActor(TIBase):
    """STIX Threat Actor."""

    name: str
    description: str | None = Field(default=None, max_length=5000)
    aliases: list[str] = Field(default_factory=list)
    sophistication: str | None = Field(default=None)
    primary_motivation: str | None = Field(default=None)
    sectors: list[str] = Field(default_factory=list)


class Malware(TIBase):
    """STIX Malware."""

    name: str
    description: str | None = Field(default=None, max_length=5000)
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = Field(default=False)


class Tool(TIBase):
    """STIX Tool (dual-use software)."""

    name: str
    description: str | None = Field(default=None, max_length=5000)
    tool_types: list[str] = Field(default_factory=list)


class AttackPattern(TIBase):
    """STIX Attack Pattern (MITRE ATT&CK technique)."""

    technique_id: str = Field(..., description="MITRE technique id, e.g. 'T1078' or 'T1078.004'.")
    name: str
    description: str | None = Field(default=None, max_length=5000)
    tactics: list[MitreTactic] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)


class TIRelationship(TIBase):
    """STIX Relationship edge."""

    source_ref: str
    target_ref: str
    relationship_type: str = Field(
        ...,
        description="STIX relationship type, e.g. uses | targets | mitigates | indicates | exploits | attributed-to.",
    )


class CorrelationHit(TenantScoped):
    """A match between a TI object and a tenant asset/finding."""

    id: UUID
    ti_id: str = Field(..., description="Id of the matched TI object (indicator/campaign/vulnerability/...).")
    asset_id: str | None = Field(default=None)
    finding_id: UUID | None = Field(default=None)
    match_dimension: CorrelationDimension
    confidence: int = Field(..., ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    first_observed_at: datetime
    last_observed_at: datetime
    schema_version: int = Field(default=1, ge=1)


class CampaignExposureSummary(AzureLensModel):
    """Per-tenant summary of a campaign's exposure (drives dashboards)."""

    tenant_id: UUID
    campaign_id: str
    campaign_name: str
    affected_asset_count: int = Field(..., ge=0)
    highest_severity: Severity
    correlation_dimensions: list[CorrelationDimension] = Field(default_factory=list)
    last_observed_at: datetime
