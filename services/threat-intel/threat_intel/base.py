"""Threat-intelligence connector abstract base class.

Every concrete TI source inherits from ``TIConnector`` and implements the
async ``fetch(ctx)`` method. The class is intentionally narrow: metadata
+ one entry point. Cross-cutting concerns (credential acquisition, retry,
circuit breaker, rate limiting, dedupe, evidence upload, Service Bus
emission, OpenTelemetry spans) live in helpers wired by the ingestion
orchestrator in Phase 2, not inside connectors.

Connector contract
------------------
Subclasses MUST:
  * declare a class-level ``metadata: TIConnectorMetadata``.
  * implement async ``fetch(self, ctx)`` returning an ``IngestionResult``.

Subclasses MUST NOT:
  * read secrets directly. The orchestrator hands them an opaque credential
    provider (Phase 2) bound to ``ctx.credential_cache_key``.
  * mutate global state across calls — connectors are stateless; resumability
    is achieved by reading and writing ``ctx.cursor`` / ``result.next_cursor_payload``.
  * emit normalized intel objects whose ``tenant_scope`` differs from
    ``ctx.destination_scope`` (orchestrator validates and raises
    ``TIIsolationError``).
"""

from __future__ import annotations

import abc

from threat_intel.context import IngestionContext
from threat_intel.contracts import IngestionResult, TIConnectorMetadata


class TIConnector(abc.ABC):
    """Abstract base class for every TI connector."""

    #: Subclasses set this as a class-level attribute.
    metadata: TIConnectorMetadata

    @classmethod
    def connector_id(cls) -> str:
        meta = cls.__dict__.get("metadata") or getattr(cls, "metadata", None)
        if meta is None:
            raise NotImplementedError(
                f"{cls.__name__} must define a class-level 'metadata' attribute."
            )
        return meta.id

    @abc.abstractmethod
    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Pull a batch of intel from the upstream feed.

        Implementations should:
          * be **idempotent** — re-running against the same cursor yields no new
            normalized objects (the orchestrator/normalizer dedupes by id + sha256
            of the canonical form).
          * be **cancellation-aware** — respect ``asyncio.CancelledError`` and
            ``ctx.deadline``.
          * **handle transient errors internally** with backoff + jitter; raise
            ``TIError`` subclasses only on permanent failure so the
            orchestrator can convert them into ``TIErrorEntry`` records.
          * **advance the cursor**: write the new cursor state to
            ``IngestionResult.next_cursor_payload`` so the next invocation
            can resume without re-pulling.
        """
        raise NotImplementedError
