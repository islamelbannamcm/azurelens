"""Threat-intelligence wire contracts (Pydantic v2).

These shapes describe everything that crosses a connector boundary:

  * what a connector DECLARES about itself (metadata + capabilities + creds + SLA),
  * what the orchestrator REQUESTS (IngestionRequest),
  * what a connector EMITS (RawIntelItem envelopes + normalized objects),
  * what the orchestrator AGGREGATES (IngestionResult + IngestionSummary),
  * what the correlator EMITS (CorrelationCandidate + CorrelationResult).

Normalized intel objects mirror the canonical wire shapes in
``apps/api/app/models/threat_intel.py`` so emitted records flow into the
persistence layer (Cosmos TI containers + Azure AI Search index) without
translation. When ``packages/shared-types`` lands, these local enums will
be replaced by re-exports; keep the string values in sync in the meantime.

Multi-tenant invariant: every normalized intel object carries
``tenant_scope`` (either the literal ``"shared"`` or a tenant UUID string).
The orchestrator validates emitted objects against
``IngestionContext.destination_scope``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ---------------------------------------------------------------------------
# Base config
# ---------------------------------------------------------------------------


_MODEL_CONFIG = ConfigDict(
    extra="forbid",
    str_strip_whitespace=True,
    validate_assignment=True,
    populate_by_name=True,
    use_enum_values=False,
)


class _Model(BaseModel):
    """Local strict base mirroring the API's ``AzureLensModel`` config."""

    model_config = _MODEL_CONFIG


# ---------------------------------------------------------------------------
# Mirrored enums (must match apps/api/app/models/threat_intel.py)
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


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CorrelationDimension(str, Enum):
    CVE_IN_INVENTORY = "cve_in_inventory"
    IP_IN_NSG = "ip_in_nsg"
    DOMAIN_IN_TRAFFIC = "domain_in_traffic"
    URL_IN_TRAFFIC = "url_in_traffic"
    TECHNIQUE_TO_FINDING = "technique_to_finding"
    SECTOR_ALIGNMENT = "sector_alignment"
    PLATFORM_MATCH = "platform_match"
    MALWARE_FAMILY_TO_POSTURE = "malware_family_to_posture"


# ---------------------------------------------------------------------------
# Capability + credential + SLA contracts
# ---------------------------------------------------------------------------


class ConnectorCapability(str, Enum):
    """Coarse-grained capabilities a TI connector advertises.

    The orchestrator and correlator use these to pick eligible connectors
    per scheduled window and to know which connectors can be queried for
    on-demand lookups. New capabilities may be added in MINOR versions;
    consumers MUST tolerate unknown values.
    """

    INDICATORS = "indicators"
    CAMPAIGNS = "campaigns"
    THREAT_ACTORS = "threat_actors"
    MALWARE_FAMILIES = "malware_families"
    TOOLS = "tools"
    ATTACK_PATTERNS_MITRE = "attack_patterns_mitre"
    MITIGATIONS = "mitigations"
    RELATIONSHIPS = "relationships"
    VULNERABILITIES_CVE = "vulnerabilities_cve"
    VULNERABILITIES_KEV = "vulnerabilities_kev"
    VULNERABILITIES_EPSS = "vulnerabilities_epss"
    SECTOR_INTEL = "sector_intel"
    GEOGRAPHIC_INTEL = "geographic_intel"
    ON_DEMAND_LOOKUP = "on_demand_lookup"   # supports point lookups, not just bulk pull
    TAXII_COLLECTIONS = "taxii_collections"  # exposes one or more TAXII 2.1 collections


class FreshnessTier(str, Enum):
    """Expected upstream refresh cadence; drives the connector's schedule."""

    REALTIME = "realtime"        # streaming push (rare; e.g., webhook)
    HOURLY = "hourly"
    SIX_HOURLY = "six_hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    ON_DEMAND = "on_demand"      # never scheduled; called explicitly


class FreshnessSLA(_Model):
    """Operational target the platform tracks per connector."""

    tier: FreshnessTier
    max_staleness_minutes: int = Field(
        ...,
        ge=1,
        description="P95 staleness budget; breaches raise a freshness SLO incident.",
    )


class RequiredCredential(_Model):
    """A credential the connector needs to function."""

    mode: str = Field(..., description="CredentialMode enum value (see context.CredentialMode).")
    secret_ref: str | None = Field(
        default=None,
        description=(
            "Key Vault secret reference template, e.g. 'kv://platform-kv/ti/misp-api-key'. "
            "Never inline a secret value."
        ),
        max_length=400,
    )
    optional: bool = Field(default=False)
    notes: str | None = Field(default=None, max_length=500)


# ---------------------------------------------------------------------------
# Connector metadata
# ---------------------------------------------------------------------------


class TIConnectorMetadata(_Model):
    """Static descriptor each connector publishes about itself."""

    id: str = Field(
        ...,
        description="Stable connector id (snake_case), e.g. 'cisa_kev'.",
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
    )
    name: str = Field(..., min_length=1, max_length=200)
    version: str
    source: TISource
    capabilities: list[ConnectorCapability] = Field(default_factory=list)
    supported_object_types: list[StixObjectType] = Field(default_factory=list)
    required_credentials: list[RequiredCredential] = Field(default_factory=list)
    freshness: FreshnessSLA
    base_url: HttpUrl | None = Field(
        default=None,
        description="Upstream endpoint for documentation; not used at runtime.",
    )
    documentation_url: HttpUrl | None = Field(default=None)
    description: str = Field(default="", max_length=2000)


# ---------------------------------------------------------------------------
# Ingestion request / outputs
# ---------------------------------------------------------------------------


class IngestionStatus(str, Enum):
    REQUESTED = "requested"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IngestionRequest(_Model):
    """One scheduled or ad-hoc TI ingestion."""

    request_id: UUID
    correlation_id: str = Field(..., min_length=1)
    sources: list[TISource] = Field(default_factory=list)
    # Empty means "all enabled connectors that match `sources`".
    connector_ids: list[str] = Field(default_factory=list)
    destination_scope: str = Field(default="shared")
    requested_at: datetime
    overrides: dict[str, Any] = Field(default_factory=dict)


class RawIntelItem(_Model):
    """Pre-normalization envelope emitted by a connector.

    Used when a connector wants to hand the raw upstream payload to the
    normalizer (e.g. STIX JSON, MISP event, KEV row). The normalizer is the
    single place that knows how to convert each ``raw_format`` into the
    normalized model below.
    """

    source: TISource
    connector_id: str
    raw_format: str = Field(
        ...,
        description="'stix2.1', 'misp_event', 'kev_row', 'nvd_v2', 'ghsa_v1', 'vendor_json', ...",
        max_length=80,
    )
    upstream_id: str = Field(..., max_length=400)
    payload: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime
    schema_version: int = Field(default=1, ge=1)


# ---------------------------------------------------------------------------
# Normalized intel objects (mirror app.models.threat_intel)
# ---------------------------------------------------------------------------


class NormalizedIntelBase(_Model):
    """Common envelope around STIX-aligned objects.

    Shared TI lives in the global corpus (``tenant_scope = "shared"``);
    tenant-private TI is partitioned by the customer tenant UUID string.
    """

    id: str = Field(
        ...,
        description="Source-qualified id, e.g. 'misp::1234' or 'cisa_kev::CVE-2024-...'.",
        max_length=200,
    )
    tenant_scope: str = Field(default="shared")
    stix_type: StixObjectType
    sources: list[TISource] = Field(default_factory=list)
    external_references: list[HttpUrl] = Field(default_factory=list)
    valid_from: datetime
    valid_until: datetime | None = Field(default=None)
    confidence: int = Field(default=50, ge=0, le=100)
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    labels: list[str] = Field(default_factory=list)
    schema_version: int = Field(default=1, ge=1)


class NormalizedIndicator(NormalizedIntelBase):
    indicator_type: IndicatorType
    value: str = Field(..., min_length=1, max_length=2048)
    pattern: str | None = Field(default=None, max_length=2048)
    kill_chain_phases: list[str] = Field(default_factory=list)


class NormalizedCampaign(NormalizedIntelBase):
    name: str = Field(..., min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    aliases: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    objective: str | None = Field(default=None, max_length=200)
    target_sectors: list[str] = Field(default_factory=list)
    target_geographies: list[str] = Field(default_factory=list)
    attributed_to: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    indicator_ids: list[str] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)


class NormalizedVulnerability(NormalizedIntelBase):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str | None = Field(default=None, max_length=400)
    cvss_v3: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v4: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    is_kev: bool = Field(default=False)
    kev_added_date: datetime | None = Field(default=None)
    affected_cpes: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    severity: Severity = Field(default=Severity.HIGH)


class NormalizedThreatActor(NormalizedIntelBase):
    name: str
    description: str | None = Field(default=None, max_length=5000)
    aliases: list[str] = Field(default_factory=list)
    sophistication: str | None = Field(default=None, max_length=80)
    primary_motivation: str | None = Field(default=None, max_length=80)
    sectors: list[str] = Field(default_factory=list)


class NormalizedMalware(NormalizedIntelBase):
    name: str
    description: str | None = Field(default=None, max_length=5000)
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = Field(default=False)


class NormalizedTool(NormalizedIntelBase):
    name: str
    description: str | None = Field(default=None, max_length=5000)
    tool_types: list[str] = Field(default_factory=list)


class NormalizedAttackPattern(NormalizedIntelBase):
    """ATT&CK technique mapping (STIX ``attack-pattern``)."""

    technique_id: str = Field(..., description="MITRE technique id, e.g. 'T1078' or 'T1078.004'.")
    name: str
    description: str | None = Field(default=None, max_length=5000)
    tactics: list[str] = Field(
        default_factory=list,
        description="MITRE tactic ids (e.g. 'TA0001'); kept as strings for forward-compat.",
    )
    kill_chain_phases: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


class NormalizedRelationship(NormalizedIntelBase):
    source_ref: str
    target_ref: str
    relationship_type: str = Field(
        ...,
        description="STIX type: uses | targets | mitigates | indicates | exploits | attributed-to | ...",
        max_length=80,
    )


# ---------------------------------------------------------------------------
# Connector outputs
# ---------------------------------------------------------------------------


class TIErrorEntry(_Model):
    """One error captured during a connector run; recorded on ``IngestionResult.errors``."""

    code: str
    message: str
    permanent: bool = Field(default=False)
    context: dict[str, Any] = Field(default_factory=dict)


class IngestionResult(_Model):
    """Per-connector outcome handed back to the orchestrator."""

    connector_id: str
    source: TISource
    destination_scope: str = Field(default="shared")
    correlation_id: str
    started_at: datetime
    ended_at: datetime
    status: IngestionStatus

    # Connectors may emit raw envelopes (for the normalizer to process) and/or
    # already-normalized objects (when the upstream is itself STIX-clean).
    raw_items: list[RawIntelItem] = Field(default_factory=list)
    indicators: list[NormalizedIndicator] = Field(default_factory=list)
    campaigns: list[NormalizedCampaign] = Field(default_factory=list)
    vulnerabilities: list[NormalizedVulnerability] = Field(default_factory=list)
    threat_actors: list[NormalizedThreatActor] = Field(default_factory=list)
    malware: list[NormalizedMalware] = Field(default_factory=list)
    tools: list[NormalizedTool] = Field(default_factory=list)
    attack_patterns: list[NormalizedAttackPattern] = Field(default_factory=list)
    relationships: list[NormalizedRelationship] = Field(default_factory=list)

    next_cursor_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Opaque cursor state to hand to the next invocation.",
    )
    errors: list[TIErrorEntry] = Field(default_factory=list)

    @property
    def total_objects(self) -> int:
        return (
            len(self.raw_items)
            + len(self.indicators)
            + len(self.campaigns)
            + len(self.vulnerabilities)
            + len(self.threat_actors)
            + len(self.malware)
            + len(self.tools)
            + len(self.attack_patterns)
            + len(self.relationships)
        )


class IngestionSummary(_Model):
    """Aggregate result for a whole ``IngestionRequest`` across connectors."""

    request_id: UUID
    correlation_id: str
    status: IngestionStatus
    started_at: datetime
    ended_at: datetime
    connectors_attempted: list[str] = Field(default_factory=list)
    connectors_succeeded: list[str] = Field(default_factory=list)
    connectors_partial: list[str] = Field(default_factory=list)
    connectors_failed: list[str] = Field(default_factory=list)
    total_objects: int = Field(default=0, ge=0)
    errors: list[TIErrorEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Correlation contracts
# ---------------------------------------------------------------------------


class CorrelationCandidate(_Model):
    """One match between a TI object and a tenant asset / finding / signal.

    Persisted by the correlation worker as ``ti_correlations`` rows; mirrors
    ``app.models.threat_intel.CorrelationHit``.
    """

    id: UUID
    tenant_id: UUID
    ti_id: str = Field(
        ...,
        description="Id of the matched normalized TI object (indicator/campaign/vuln/...).",
        max_length=200,
    )
    asset_id: str | None = Field(default=None)
    finding_id: UUID | None = Field(default=None)
    match_dimension: CorrelationDimension
    confidence: int = Field(..., ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    first_observed_at: datetime
    last_observed_at: datetime
    schema_version: int = Field(default=1, ge=1)


class CorrelationResult(_Model):
    """Outcome of one correlation pass for one tenant."""

    tenant_id: UUID
    correlation_id: str
    started_at: datetime
    ended_at: datetime
    dimension: CorrelationDimension
    candidates: list[CorrelationCandidate] = Field(default_factory=list)
    errors: list[TIErrorEntry] = Field(default_factory=list)

    @property
    def hit_count(self) -> int:
        return len(self.candidates)
