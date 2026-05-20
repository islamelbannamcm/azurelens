"""CISA Known Exploited Vulnerabilities (KEV) connector (STUB).

In Phase 2 this connector will pull the CISA KEV catalog (open, public,
no API key) and emit ``NormalizedVulnerability`` entries with the
``is_kev`` flag and ``kev_added_date`` populated. KEV is one of the highest-
signal sources we ingest because it indicates *active exploitation* in the
wild — the risk engine boosts ``exploitability_factor`` by ×1.5 when a
finding maps to a KEV CVE.

NO HTTP calls happen here today.
"""

from __future__ import annotations

from threat_intel.base import TIConnector
from threat_intel.context import IngestionContext
from threat_intel.contracts import (
    ConnectorCapability,
    FreshnessSLA,
    FreshnessTier,
    IngestionResult,
    IngestionStatus,
    StixObjectType,
    TIConnectorMetadata,
    TISource,
)
from threat_intel.registry import default_registry


class CisaKevConnector(TIConnector):
    """Pulls the CISA Known Exploited Vulnerabilities catalog (open feed)."""

    metadata = TIConnectorMetadata(
        id="cisa_kev",
        name="CISA Known Exploited Vulnerabilities",
        version="0.0.0",
        source=TISource.CISA_KEV,
        capabilities=[
            ConnectorCapability.VULNERABILITIES_CVE,
            ConnectorCapability.VULNERABILITIES_KEV,
        ],
        supported_object_types=[StixObjectType.VULNERABILITY],
        required_credentials=[],  # public, unauthenticated
        freshness=FreshnessSLA(tier=FreshnessTier.SIX_HOURLY, max_staleness_minutes=360),
        description=(
            "CISA-curated catalog of CVEs known to be actively exploited in the "
            "wild. Public feed, no API key required."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * GET the KEV JSON catalog (public, unauthenticated, < 5 MB).
          * Honor ETag / If-Modified-Since to skip unchanged refreshes.
          * For each row emit ``RawIntelItem(raw_format='kev_row')``.
          * Normalizer handler produces ``NormalizedVulnerability`` with
            ``is_kev=True`` and ``kev_added_date`` populated; ``severity``
            defaults to HIGH and is upgraded to CRITICAL when joined with
            NVD/EPSS data downstream.
        """
        now = IngestionContext.now()
        return IngestionResult(
            connector_id=self.metadata.id,
            source=self.metadata.source,
            destination_scope=ctx.destination_scope,
            correlation_id=ctx.correlation_id,
            started_at=now,
            ended_at=now,
            status=IngestionStatus.COMPLETED,
        )


default_registry.register(CisaKevConnector)
