# packages/contracts

Cross-language API contracts for AzureLens.

## Purpose

`apps/api/app/models/` is the **canonical source of truth** for AzureLens schemas (Pydantic v2). This package will, in later phases, generate the **language-agnostic distributables** other parts of the platform consume:

| Artifact | Consumer |
|---|---|
| `openapi.json` | Frontend (`apps/frontend`), partner SDKs, postman/insomnia, contract testing |
| TypeScript types (`@azurelens/contracts`) | Frontend type-safe API client |
| Python types (re-export of `app.models`) | Worker services (`services/*`) |
| C# / Java / Go SDKs (later) | Marketplace partners (Phase 9) |
| JSON Schemas (`/schemas/*.json`) | Event payload validation in workers; SBOM/contract registries |

## Status

This branch ships only documentation. Code generation, publishing, and CI gates land in subsequent phases.

## Contract Principles

1. **Backward-compatible by default.** Once a model is published, fields are added — not removed or renamed. Breaking changes require a new API version (`/api/v2`).
2. **`schema_version` carried on every persisted model.** Consumers tolerate at least one minor version difference.
3. **Strict on input, lenient on output.** API requests use `extra="forbid"`; clients reading responses must ignore unknown fields.
4. **Enums are closed in the API but extensible via reserved sentinel values.** When uncertain, use the explicit `UNKNOWN` member (e.g. `AssetKind.UNKNOWN`) instead of inventing client-side values.
5. **No PII in examples or fixtures.** All sample data uses synthetic identifiers (`example.invalid`, `Contoso Demo`, all-zero UUIDs).
6. **No secrets in any contract.** Secret material is referenced (`secret_ref`, `evidence_blob_uri`) but never inlined.

## Versioning

- API path version: `/api/v1`, `/api/v2`, ...
- Model `schema_version` integer on persisted shapes.
- Contracts package follows SemVer once published: MAJOR for breaking, MINOR for additions, PATCH for docs/example/typo fixes.

## Generation Pipeline (planned)

```
apps/api/app/models/*.py          (canonical Pydantic models)
        │
        │  FastAPI app introspection
        ▼
        openapi.json              (generated; committed under packages/contracts/openapi/)
        │
        ├──► openapi-typescript ──► packages/contracts/typescript/ (npm)
        ├──► datamodel-codegen ──► packages/contracts/python/      (sdist)
        └──► openapi-generator ──► partner SDKs (C#, Java, Go)
```

The generator runs in CI on every change to `apps/api/app/models/` or any `apps/api/app/api/**/*.py`. PRs with breaking diff fail the contract gate unless the API version is bumped.

## Local Development (planned)

```bash
# Regenerate openapi.json from the running FastAPI app
cd apps/api
uvicorn app.main:app --port 8000 &
curl -s http://localhost:8000/openapi.json > ../../packages/contracts/openapi/openapi.json

# Validate against the committed snapshot
cd packages/contracts
npx @redocly/cli lint openapi/openapi.json
npx openapi-typescript openapi/openapi.json --output typescript/src/index.ts
```

## Files in this package

- `README.md` — this file.
- `openapi-contract-notes.md` — design rules for the OpenAPI surface, error model, pagination, idempotency, and tenant scoping.
- `openapi/` *(planned)* — generated `openapi.json` snapshot per API version.
- `typescript/` *(planned)* — generated TypeScript types.
- `python/` *(planned)* — generated Python types (or re-export of `app.models`).
- `schemas/` *(planned)* — JSON Schemas for event payloads on Service Bus / Event Grid.

## Related docs

- `docs/API_CONTRACTS.md` — the API surface in business terms.
- `docs/DATA_MODEL.md` — the entity model behind the API.
- `docs/SCHEMA_DESIGN.md` — persistence-side data model details.
- `docs/ARCHITECTURE.md` § 4.2 — backend API responsibilities.
