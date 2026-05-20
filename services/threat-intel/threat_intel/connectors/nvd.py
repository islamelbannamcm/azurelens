"""NVD (CVE / NVD JSON 2.0) connector (STUB).

In Phase 2 this connector will pull NVD JSON 2.0 feeds — the canonical
public CVE corpus. NVD provides CVSS v3 / v4 scoring, references, CPE
configurations, and (separately) the EPSS exploit-probability feed.

NO NVD / HTTP calls happen here today.
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
    RequiredCredential,
    StixObjectType,
    TIConnectorMetadata,
    TISource,
)
from threat_intel.registry import default_registry


class NvdConnector(TIConnector):
    """Pulls NVD JSON 2.0 + EPSS feeds (canonical CVE source)."""

    metadata = TIConnectorMetadata(
        id="nvd",
        name="NVD (CVE / NVD JSON 2.0)",
        version="0.0.0",
        source=TISource.NVD,
        capabilities=[
            ConnectorCapability.VULNERABILITIES_CVE,
            ConnectorCapability.VULNERABILITIES_EPSS,
        ],
        supported_object_types=[StixObjectType.VULNERABILITY],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/nvd-api-key",
                optional=True,
                notes=(
                    "NVD-issued API key (header ``apiKey``) substantially raises "
                    "the rate limit. Public access works without one at lower rates."
                ),
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.SIX_HOURLY, max_staleness_minutes=360),
        description=(
            "Canonical CVE / NVD JSON 2.0 + EPSS exploit-probability feeds. "
            "Drives the cve_in_inventory correlation dimension together with GHSA."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * GET ``/rest/json/cves/2.0`` with ``lastModStartDate`` cursor from
            ``ctx.cursor.since`` (NVD requires <= 120-day windows; chunk if needed).
          * Emit ``RawIntelItem(raw_format='nvd_v2')``.
          * Normalizer produces ``NormalizedVulnerability`` with CVSS v3/v4,
            CPE configurations, and references; later join with EPSS to fill
            ``epss_score`` and with KEV to set ``is_kev``.
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


default_registry.register(NvdConnector)
