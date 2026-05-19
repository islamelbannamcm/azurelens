# OpenAPI Contract Notes

Design rules and conventions for the AzureLens HTTP API surface. The canonical OpenAPI document is generated from the FastAPI app in `apps/api/`; this document explains the *rules* the document must satisfy.

---

## 1. Versioning

- **Path versioning.** Every endpoint lives under `/api/v{N}/...`. The current version is `v1`.
- **Major version bump** when a breaking change is needed (field removed/renamed, type change, behavior change).
- **No deprecated fields silently kept around.** Either keep with a `deprecated: true` flag in the OpenAPI document for at least one minor cycle, or move to v(N+1).

---

## 2. Resource Naming

- Plural, lowercase nouns: `/tenants`, `/assets`, `/findings`, `/reports`, `/threat-intel/campaigns`.
- Sub-resources nested at most one level: `/findings/{id}/acknowledge`, `/assets/{id}/related`.
- Verbs only at the **action** suffix on a resource (`/findings/{id}/acknowledge`, `/scans` POST). Never in path segments otherwise.

---

## 3. HTTP Semantics

| Method | Use |
|---|---|
| `GET` | Read only; safe & idempotent; no body |
| `POST` | Create a new resource OR trigger an asynchronous side effect |
| `PUT` | Full replace of a resource (rare in this API; prefer PATCH) |
| `PATCH` | Partial update; JSON Merge Patch (RFC 7396) by default |
| `DELETE` | Soft-delete; cascade hard-delete is a tenant-offboarding admin job, not a public endpoint |

### Status codes used

- `200 OK` — synchronous success with body.
- `201 Created` — synchronous create with body and `Location` header.
- `202 Accepted` — work enqueued (scan triggered, report queued, tenant onboard kicked off).
- `204 No Content` — successful state mutation with no body.
- `400 Bad Request` — malformed input.
- `401 Unauthorized` — missing/invalid token.
- `403 Forbidden` — authenticated but not allowed (RBAC denial, cross-tenant attempt).
- `404 Not Found` — resource does not exist *for the caller's tenant scope*.
- `409 Conflict` — idempotency mismatch or state-transition conflict.
- `422 Unprocessable Entity` — validation failure on a well-formed request.
- `429 Too Many Requests` — quota / throttle hit.
- `5xx` — server errors; never leak stack traces or internal identifiers.

---

## 4. Error Model

All non-2xx responses use a single, stable error envelope (RFC 7807 *Problem Details* compatible).

```json
{
  "type": "https://errors.azurelens.example/invalid_request",
  "title": "Invalid request",
  "status": 400,
  "detail": "field 'severity' is required",
  "instance": "urn:azurelens:trace:00-1234abcd...-01",
  "code": "invalid_request",
  "correlation_id": "00-1234abcd...-01"
}
```

Rules:

- `code` is a stable, machine-readable identifier; never localize.
- `correlation_id` MUST be the W3C `traceparent` value from the request (or generated server-side and echoed back).
- `detail` is human-readable; safe to surface to operators but never to end users without product review.
- Stack traces, SQL errors, internal hostnames, and file paths are NEVER included.

---

## 5. Pagination

- Cursor-based, opaque tokens.
- Request: `?cursor=<opaque>&limit=<1..500>`.
- Response: `page.next_cursor` (null when end-of-stream) and optional `page.total_estimate`.
- Cursors are signed (HMAC) server-side so clients cannot tamper.
- `Cache-Control: no-store` on paginated list endpoints to avoid stale cursors in intermediaries.

---

## 6. Filtering & Sorting

- Filters as flat query params: `?severity=high&status=open&framework=cis_azure`.
- Repeated values are AND on different keys, OR on the same key (`?severity=high&severity=critical`).
- Sort: `?sort=<field>:<asc|desc>`, default sort documented per endpoint.
- Free-text search: `?q=<term>` where supported; backed by Azure AI Search.

---

## 7. Idempotency

State-mutating POSTs accept `Idempotency-Key` header (UUID).

- Same key + same body within 24h → identical response (cached server-side).
- Same key + different body → `409 Conflict`.
- Required for: `/scans`, `/reports`, `/tenants/onboard`, future remediation execution.

---

## 8. Multi-Tenancy

The tenant identity is **always** carried by the JWT `tid` claim (mapped to the AzureLens internal `tenant_id` via a lookup table). It is **never** a query parameter except for cross-tenant admin endpoints (Phase 8) which are protected by explicit elevated scopes.

- A request that addresses a resource outside the caller's tenant returns `404` (not `403`) to avoid information disclosure.
- Every response includes the `tenant_id` of the resource where applicable, so clients can detect drift in their own state machines.

---

## 9. Authentication & Authorization

- Bearer JWT (Entra ID v2.0). Audience: `api://azurelens-api`.
- Required scopes documented per operation in the OpenAPI document under `security` entries.
- App roles map to AzureLens `Role`s (see `app/core/security.py` and `docs/SECURITY_MODEL.md` § 4).

---

## 10. Long-Running Operations

Endpoints that enqueue background work return `202 Accepted` with the in-progress resource:

```json
{ "id": "...", "status": "queued", ... }
```

Client polls `GET /<resource>/{id}` until the resource reaches a terminal `status`. We will optionally emit completion events via Event Grid Webhooks (Phase 1) for clients that prefer push.

---

## 11. Versioned Reference Data

Endpoints that reference framework controls, MITRE techniques, or scoring policies accept an optional `?version=<x.y.z>` query parameter. When omitted, the server resolves the "latest published" version and includes the resolved version in the response body.

---

## 12. Enums & Forward Compatibility

- Enum members are **lowercase, dotted or snake_case**, stable across versions.
- New enum values may be added in MINOR releases. Clients MUST be tolerant of unknown values (fall back to the `UNKNOWN` sentinel where defined, e.g. `AssetKind.UNKNOWN`).

---

## 13. Examples & Mock Data

- All example bodies use synthetic data:
  - tenant id `00000000-0000-0000-0000-000000000001`
  - domain suffix `.invalid` (reserved per RFC 6761)
  - "Contoso Demo" as the display name
- No real customer data, no real IPs, no real CVEs unless explicitly noting they are public reference fixtures.

---

## 14. Content Types

- `application/json; charset=utf-8` for everything except report downloads.
- Report downloads return their native content type (`application/pdf`, etc.) via short-lived signed SAS URLs from Blob Storage; the API itself does not stream binary content.

---

## 15. Rate Limiting

- Token-bucket per tenant + per user, surfaced at the APIM layer.
- Standard headers: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`.
- `429` responses include `Retry-After` (seconds).

---

## 16. Deprecation Process

When a field or endpoint is being deprecated:

1. Mark `deprecated: true` in OpenAPI; add `Sunset` header on responses (RFC 8594).
2. Announce in `docs/ROADMAP.md` and release notes.
3. Retain for at least one MINOR cycle (target: 90 days).
4. Move to next API version when sunset elapses.

---

## 17. Contract Testing

Phase 1 introduces:

- Snapshot of `openapi.json` committed under `packages/contracts/openapi/` and checked in PRs.
- A PR-blocking job that runs **breaking-change detection** (e.g. `oasdiff`) against `main`.
- Consumer-driven contract tests for `apps/frontend` against the snapshot.
