"""Scanner exception hierarchy.

Plugin code raises these; the orchestrator catches them at the plugin
boundary and converts to ``ScanErrorEntry`` records on ``ScanResult``.
Exceptions should never propagate past a plugin invocation.

Categories
----------
ScannerConfigError     : missing / invalid plugin configuration
ScannerAuthError       : token acquisition or audience mismatch
ScannerPermissionError : the platform Entra ID app lacks a required scope
ScannerThrottledError  : 429 / Retry-After from an external API
ScannerTransientError  : transient failure; retryable with backoff
ScannerPermanentError  : non-retryable failure (contract / bad input / parse)
PluginNotFoundError    : registry has no plugin under the requested id
DependencyMissingError : a runtime extra (e.g. SDK package) is not installed
TenantIsolationError   : a plugin attempted to emit cross-tenant data (P0)
"""

from __future__ import annotations

from typing import Any


class ScannerError(Exception):
    """Base class for all scanner errors."""

    code: str = "scanner_error"

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.context: dict[str, Any] = context or {}


class ScannerConfigError(ScannerError):
    code = "scanner_config_error"


class ScannerAuthError(ScannerError):
    """Authentication or authorization failed at the external system.

    Distinct from AzureLens-side RBAC denials (those happen at the API layer).
    """

    code = "scanner_auth_error"


class ScannerPermissionError(ScannerError):
    """The platform's Entra ID app lacks the required permission.

    Surfaced to the tenant admin as an actionable "re-consent" prompt rather
    than a platform incident.
    """

    code = "scanner_permission_error"


class ScannerThrottledError(ScannerError):
    """An external API returned 429 / Retry-After.

    The orchestrator backs off with jitter and retries; ``retry_after``
    carries the suggested delay in seconds.
    """

    code = "scanner_throttled"

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.retry_after = retry_after


class ScannerTransientError(ScannerError):
    """Likely-transient failure (network blip, 5xx, dependency timeout).

    Retryable with exponential backoff + jitter.
    """

    code = "scanner_transient_error"


class ScannerPermanentError(ScannerError):
    """Non-retryable (bad input, contract violation, malformed response)."""

    code = "scanner_permanent_error"


class PluginNotFoundError(ScannerError):
    code = "scanner_plugin_not_found"


class DependencyMissingError(ScannerError):
    """Plugin needs a runtime extra (SDK package) that is not installed.

    The orchestrator skips the plugin and surfaces this as a config warning.
    """

    code = "scanner_dependency_missing"


class TenantIsolationError(ScannerError):
    """A plugin attempted to emit a finding/asset bound to a different tenant.

    This is a P0 invariant violation: the orchestrator MUST drop the
    offending output and alert. See docs/SCHEMA_DESIGN.md § 12.
    """

    code = "scanner_tenant_isolation_error"
