"""Normalizer.

Connectors emit either ``RawIntelItem`` envelopes (carrying the upstream
payload) or already-normalized objects (when the upstream is itself STIX-
clean — e.g. MITRE ATT&CK). The normalizer is the single place that knows
how to convert each ``raw_format`` into the platform's normalized model
(see ``threat_intel.contracts.NormalizedIntelBase`` and subclasses).

The normalizer is also responsible for:

  * **schema validation**: rejecting payloads that violate the upstream
    contract (raises ``TIParseError`` so the orchestrator can dead-letter).
  * **deduplication**: hashing the canonical form and dropping records the
    corpus already has (per-tenant for tenant-private; global for shared).
  * **id minting**: producing a stable, source-qualified id
    (``<source>::<external_id>``) for cross-source joins.
  * **enrichment**: filling derived fields (e.g. mapping a feed's tags to
    MITRE technique ids, propagating CISA-KEV onto a vulnerability).
  * **trust aggregation**: combining per-source trust scores when multiple
    sources report the same object.

This branch contains the skeleton only. Real format handlers land in
Phase 2.
"""

from __future__ import annotations

from typing import Callable, Mapping

from threat_intel.contracts import (
    NormalizedAttackPattern,
    NormalizedCampaign,
    NormalizedIndicator,
    NormalizedIntelBase,
    NormalizedMalware,
    NormalizedRelationship,
    NormalizedThreatActor,
    NormalizedTool,
    NormalizedVulnerability,
    RawIntelItem,
)
from threat_intel.errors import TIParseError


# Type alias for "normalize one raw payload into a list of normalized objects".
RawHandler = Callable[[RawIntelItem], list[NormalizedIntelBase]]


class Normalizer:
    """Convert raw connector payloads into normalized intel objects.

    Construct with a mapping of ``raw_format`` → handler. The default
    instance ships with no handlers — Phase 2 wires in handlers for:

      * ``stix2.1``       — STIX 2.1 JSON (MITRE ATT&CK, Sentinel TI TAXII,
                            OpenCTI, Defender TI export, ...)
      * ``misp_event``    — MISP attribute + galaxy + tags
      * ``kev_row``       — CISA KEV catalog row
      * ``nvd_v2``        — NVD JSON 2.0
      * ``ghsa_v1``       — GitHub Security Advisory GraphQL response
      * ``otx_pulse``     — AlienVault OTX pulse
      * ``abuse_ch_v1``   — URLhaus / MalwareBazaar / ThreatFox JSON
      * ``vendor_json``   — vendor-specific JSON (per-connector adapters)
    """

    def __init__(self, handlers: Mapping[str, RawHandler] | None = None) -> None:
        self._handlers: dict[str, RawHandler] = dict(handlers or {})

    # ------------------------------------------------------------------ registry

    def register_handler(self, raw_format: str, handler: RawHandler) -> None:
        """Register / replace a handler for a given ``raw_format`` tag."""
        self._handlers[raw_format] = handler

    def supports(self, raw_format: str) -> bool:
        return raw_format in self._handlers

    def supported_formats(self) -> list[str]:
        return sorted(self._handlers)

    # ------------------------------------------------------------------ normalize

    def normalize(self, raw: RawIntelItem) -> list[NormalizedIntelBase]:
        """Convert one ``RawIntelItem`` into zero-or-more normalized objects.

        Raises ``TIParseError`` if the raw_format is unknown or if the
        handler rejects the payload as malformed.
        """
        handler = self._handlers.get(raw.raw_format)
        if handler is None:
            raise TIParseError(
                f"no normalizer handler registered for raw_format='{raw.raw_format}'",
                context={
                    "source": raw.source.value,
                    "connector_id": raw.connector_id,
                    "upstream_id": raw.upstream_id,
                },
            )
        return handler(raw)

    def normalize_batch(self, raws: list[RawIntelItem]) -> list[NormalizedIntelBase]:
        """Normalize a batch. Errors on individual items are re-raised; the
        orchestrator decides whether to dead-letter or quarantine the batch.
        """
        out: list[NormalizedIntelBase] = []
        for raw in raws:
            out.extend(self.normalize(raw))
        return out


# ---------------------------------------------------------------------------
# Module-level helpers used by future handlers (kept here as forward contracts)
# ---------------------------------------------------------------------------

# TODO(phase-2): implement and register format handlers. Each handler:
#   * takes a RawIntelItem,
#   * returns a list[NormalizedIntelBase],
#   * raises TIParseError on schema violation,
#   * mints a stable id of the form '<source>::<external_id>',
#   * propagates `sources` + `external_references` + `confidence` + `trust_score`.
#
# Example signatures (kept commented as a forward contract):
#   def handle_stix_2_1(raw: RawIntelItem) -> list[NormalizedIntelBase]: ...
#   def handle_misp_event(raw: RawIntelItem) -> list[NormalizedIntelBase]: ...
#   def handle_kev_row(raw: RawIntelItem) -> list[NormalizedVulnerability]: ...
#   def handle_nvd_v2(raw: RawIntelItem) -> list[NormalizedVulnerability]: ...
#   def handle_ghsa_v1(raw: RawIntelItem) -> list[NormalizedVulnerability]: ...
#   def handle_otx_pulse(raw: RawIntelItem) -> list[NormalizedIntelBase]: ...
#   def handle_abuse_ch_v1(raw: RawIntelItem) -> list[NormalizedIndicator]: ...


__all__ = [
    "Normalizer",
    "RawHandler",
    # Re-export normalized types for handler authors' convenience.
    "NormalizedIntelBase",
    "NormalizedIndicator",
    "NormalizedCampaign",
    "NormalizedVulnerability",
    "NormalizedThreatActor",
    "NormalizedMalware",
    "NormalizedTool",
    "NormalizedAttackPattern",
    "NormalizedRelationship",
]
