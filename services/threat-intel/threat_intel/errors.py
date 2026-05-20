"""Threat-intelligence exception hierarchy.

Connectors raise these; the ingestion orchestrator catches them at the
connector boundary and converts to ``TIErrorEntry`` records on
``IngestionResult``. Exceptions must never propagate past a connector
invocation.

Categories
----------
TIConfigError           : connector configuration is missing or invalid
TIAuthError             : API key / OAuth token rejected by the upstream feed
TIRateLimitError        : 429 / Retry-After from an upstream feed
TITransientError        : retryable failure (network, 5xx, parse jitter)
TIPermanentError        : non-retryable failure (contract violation)
TIFeedUnavailableError  : upstream is unreachable or returned a hard outage signal
TIParseError            : payload could not be parsed against the expected schema
ConnectorNotFoundError  : registry has no connector under the requested id
DependencyMissingError  : a runtime extra (SDK / parser library) is not installed
TIIsolationError        : tenant-private intel attempted to leak across tenants (P0)
TIQuotaExceededError    : per-tenant or platform-wide TI budget exceeded
"""

from __future__ import annotations

from typing import Any


class TIError(Exception):
    """Base class for all threat-intelligence errors."""

    code: str = "ti_error"

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.context: dict[str, Any] = context or {}


class TIConfigError(TIError):
    code = "ti_config_error"


class TIAuthError(TIError):
    """API key / OAuth credential rejected by the upstream feed.

    Surfaced to operations as an actionable "rotate or re-provision the
    secret" alert; never exposed to tenants.
    """

    code = "ti_auth_error"


class TIRateLimitError(TIError):
    """Upstream returned 429 / Retry-After.

    The ingestion orchestrator backs off with jitter and retries; carries
    the suggested delay in ``retry_after`` (seconds).
    """

    code = "ti_rate_limited"

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.retry_after = retry_after


class TITransientError(TIError):
    """Likely-transient failure (network blip, 5xx, dependency timeout)."""

    code = "ti_transient_error"


class TIPermanentError(TIError):
    """Non-retryable (contract violation, malformed envelope, bad cursor)."""

    code = "ti_permanent_error"


class TIFeedUnavailableError(TIError):
    """Upstream feed is unreachable or has declared a hard outage.

    Differs from ``TITransientError`` in that the orchestrator will:
      * stop retrying for the rest of this scheduled window,
      * mark the connector status as ``degraded`` until the next probe,
      * raise the feed-freshness SLO incident immediately.
    """

    code = "ti_feed_unavailable"


class TIParseError(TIError):
    """Payload could not be parsed against the expected schema (STIX, MISP, JSON)."""

    code = "ti_parse_error"


class ConnectorNotFoundError(TIError):
    code = "ti_connector_not_found"


class DependencyMissingError(TIError):
    """Connector needs a runtime extra that is not installed (stix2, taxii2-client, pymisp, ...)."""

    code = "ti_dependency_missing"


class TIIsolationError(TIError):
    """Tenant-private intelligence attempted to leak across tenants (P0).

    Most TI lives in the shared corpus (``tenant_id = "shared"``). Tenants
    can also push their own private indicators; the orchestrator MUST ensure
    a tenant-private indicator is never written to the shared corpus or to
    another tenant's partition. See docs/SCHEMA_DESIGN.md § 12.
    """

    code = "ti_isolation_error"


class TIQuotaExceededError(TIError):
    """Per-tenant or platform-wide TI ingestion / lookup quota exceeded."""

    code = "ti_quota_exceeded"
