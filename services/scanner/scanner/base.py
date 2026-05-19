"""Scanner plugin abstract base class.

Every concrete scanner inherits from ``ScannerPlugin`` and implements an
async ``scan(ctx)`` method returning a ``ScanResult``.

The class is intentionally narrow: one entry point + one metadata class
attribute. Cross-cutting concerns — credential acquisition, retry, circuit
breaker, rate limiting, idempotency keys, OpenTelemetry spans, evidence
upload to ADLS, Service Bus emission — live in helpers wired by the
orchestrator in Phase 1, not inside plugins.

Plugin contract
---------------
Subclasses MUST:
  * declare a class-level ``metadata: ScannerMetadata``.
  * implement async ``scan(self, ctx)`` returning a ``ScanResult``.

Subclasses MUST NOT:
  * read secrets directly. The orchestrator hands them an opaque token
    provider (Phase 1) bound to ``ctx.tenant_id``.
  * mutate global state across invocations — plugins are stateless.
  * emit ScanAssetSnapshot / ScanFinding records for a tenant other than
    ``ctx.tenant_id``. The orchestrator validates and raises
    ``TenantIsolationError`` on violation (P0).
"""

from __future__ import annotations

import abc

from scanner.context import ScanContext
from scanner.contracts import ScanResult, ScannerMetadata


class ScannerPlugin(abc.ABC):
    """Abstract base class for every scanner plugin."""

    #: Subclasses set this as a class-level attribute.
    metadata: ScannerMetadata

    @classmethod
    def plugin_id(cls) -> str:
        meta = cls.__dict__.get("metadata") or getattr(cls, "metadata", None)
        if meta is None:
            raise NotImplementedError(
                f"{cls.__name__} must define a class-level 'metadata' attribute."
            )
        return meta.id

    @abc.abstractmethod
    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Execute the scan and return a ``ScanResult``.

        Implementations should:
          * be **idempotent** — re-running against unchanged state yields no findings.
          * be **cancellation-aware** — respect ``asyncio.CancelledError`` and
            ``ctx.deadline``.
          * **handle transient errors internally** with backoff + jitter;
            raise ``ScannerError`` subclasses only on permanent failure so
            the orchestrator can convert to ``ScanErrorEntry`` records.
        """
        raise NotImplementedError
