"""Security primitives.

Skeleton only. Real implementations land in Phase 1.

This module is the single place that resolves:
  * the authenticated user (Entra ID JWT validation),
  * the tenant context (multi-tenant isolation invariant),
  * role/scope checks (RBAC matrix in docs/SECURITY_MODEL.md § 4),
  * On-Behalf-Of token exchange for delegated Graph calls.

CRITICAL: Tenant isolation is enforced at multiple layers (API filter,
SQL row-level security, Cosmos partition key, AI Search filter, Blob path,
event subscription filters). This module owns the API-layer enforcement.
See docs/SCHEMA_DESIGN.md § 12 for the multi-tenant invariants.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    """Application roles surfaced via Entra ID app roles.

    The full capability matrix lives in docs/SECURITY_MODEL.md § 4.
    """

    GLOBAL_ADMIN = "GlobalAdmin"
    SECURITY_ADMIN = "SecurityAdmin"
    COMPLIANCE = "Compliance"
    CLOUD_ARCHITECT = "CloudArchitect"
    SOC_ANALYST = "SOCAnalyst"
    IT_MANAGER = "ITManager"
    AUDITOR = "Auditor"
    EXEC_VIEWER = "ExecViewer"


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Resolved per-request tenant + actor context.

    Populated by `TenantContextMiddleware` (Phase 1) from validated JWT claims.
    Every data-access call MUST receive this object; cross-tenant access is a
    P0 security defect.
    """

    tenant_id: str
    user_oid: str
    roles: frozenset[Role]
    correlation_id: str


class AuthError(Exception):
    """Raised by the auth layer; mapped to 401/403 by exception handlers."""


# ---------------------------------------------------------------------------
# TODO(phase-1): implementation checklist
# ---------------------------------------------------------------------------
#  - validate_access_token(token) -> Claims
#      * JWKS fetch + cache with rotation
#      * issuer/audience/expiry/signing-key checks
#      * reject tokens missing tenant_id or oid
#  - exchange_obo(user_token, target_scope) -> on-behalf-of token
#  - resolve_tenant_context(claims, request) -> TenantContext
#      * enforce that tenant_id in path/query matches token claim
#  - require_roles(*roles: Role) -> FastAPI dependency
#  - require_scope(scope: str)   -> FastAPI dependency for fine-grained checks
#  - audit_emit(action, resource, outcome)
#      * structured event to audit pipeline (Blob immutable + LAW mirror)
# ---------------------------------------------------------------------------
