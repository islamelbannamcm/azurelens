# apps/api

FastAPI backend skeleton for AzureLens. Health endpoint only — no business logic.

## Purpose

The single ingress for the AzureLens platform API. Owns:

- Tenant resolution & isolation (every request carries a `tenant_id` claim).
- Entra ID JWT validation and On-Behalf-Of (OBO) token exchange for delegated Graph calls.
- Read APIs for findings, scores, frameworks, threats, reports.
- Write APIs for tenant onboarding, scan triggers, remediation acknowledgement.
- Webhook receivers for Event Grid / Defender / Sentinel callbacks.

Anything that takes longer than a few seconds is **queued to Service Bus** and handled by a worker service (`services/scanner`, `services/threat-intel`, `services/risk-engine`, `services/ai-engine`). The API itself stays stateless and request-bound.

## Future Responsibilities

- `GET /api/v1/health` — liveness/readiness (implemented in this skeleton).
- `POST /api/v1/tenants/onboard` — admin-consent callback handler.
- `GET /api/v1/findings` / `GET /api/v1/findings/{id}` — list + detail.
- `POST /api/v1/findings/{id}/acknowledge` — RBAC-gated.
- `GET /api/v1/scores/overview` — score bands per tenant.
- `GET /api/v1/frameworks/{framework_id}/posture` — per-framework heatmap.
- `GET /api/v1/threats/correlations` — campaign-to-asset matches.
- `POST /api/v1/scans` — trigger scan (enqueues to Service Bus).
- `GET /api/v1/reports` / `POST /api/v1/reports` — list + generate.
- `POST /api/v1/copilot/messages` — AI copilot streaming endpoint.

## Local Development (planned)

```bash
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # editable install with dev extras
uvicorn app.main:app --reload      # http://localhost:8000
curl http://localhost:8000/api/v1/health
```

Required environment (use `.env`, gitignored; never commit):

| Variable | Purpose |
|---|---|
| `AZURELENS_ENV` | `local` / `dev` / `staging` / `prod` |
| `AZURELENS_ENTRA_TENANT_ID` | Platform tenant (for token validation in dev only) |
| `AZURELENS_ENTRA_AUDIENCE` | Expected JWT `aud`, e.g. `api://azurelens-api` |
| `AZURELENS_KEYVAULT_URI` | Key Vault URI for secret resolution at runtime |
| `AZURELENS_SQL_CONNECTION` | Azure SQL connection (Managed Identity in cloud; local string in dev) |
| `AZURELENS_COSMOS_ENDPOINT` | Cosmos DB endpoint URI |
| `AZURELENS_SERVICEBUS_FQNS` | Service Bus fully qualified namespace |

In Azure environments secrets are **never** read from env vars directly — they are resolved via Managed Identity from Azure Key Vault references mounted by Container Apps. See `docs/SECURITY_MODEL.md` § 5.

## Status

Skeleton only. Real auth, persistence, eventing, and tenant isolation arrive in Phase 1 (see `docs/ROADMAP.md`).
