# AzureLens — Demo Mode

How AzureLens can be run, demoed, and integrated against **today** — before any Microsoft Graph, Azure Resource Graph, Defender, Sentinel, Intune, Purview, Azure OpenAI, or external threat-feed connectivity has been wired up.

> Goal: hand the frontend, partner integrators, and contract test suites a fully populated, deterministic API surface for a fictional tenant called **Contoso Demo**. The wire shapes match the canonical models in `apps/api/app/models/*`, so every endpoint flips to real persistence in Phase 1 without contract changes.

---

## 1. What demo mode is (and isn't)

| | Demo mode (this branch) | Real mode (Phase 1+) |
|---|---|---|
| Tenant | Single, fictional, immutable | Multi-tenant, persisted in Azure SQL |
| Data source | In-memory Python constants (`app/demo/data.py`) | Azure SQL + Cosmos DB + ADLS + AI Search |
| Auth | Not enforced (locally) | Entra ID JWT + tenant-context middleware |
| Microsoft API calls | None | Graph, ARG, Defender, Sentinel, Intune, Purview |
| Threat intel calls | None | Defender TI, Sentinel TI, CISA KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch, GHSA, NVD, VT |
| AI inference | None | Azure OpenAI behind grounding + safety + audit pipeline |
| Persistence | None | Per-tenant, CMK, tenant-isolated |
| Mutations | Synthesized in-memory; not retained | Auditable, persisted, idempotent |

Demo mode is **read-mostly**. The two state-changing endpoints (`POST /scans` and `POST /remediations/{id}/approve`) return synthesized "queued" / "approved" representations but never mutate the underlying dataset. Each request returns the same deterministic answer.

---

## 2. The Contoso Demo tenant

Everything ships pre-loaded:

- **Tenant** — `Contoso Demo`, `contoso.onmicrosoft.com`, tier `pro`, residency `eu`, status `active`.
- **8 assets** — a subscription, two VMs (one with public RDP), a storage account with public access, a key vault, two identities (a Global Admin without MFA + a service principal), and one non-compliant Intune device.
- **12 findings** spanning identity / Azure exposure / device / compliance / threat — including the highlight cases the dashboard is designed around (privileged identity without MFA, public RDP linked to an active Akira ransomware campaign, KEV CVE active-exploitation, missing Defender onboarding, missing DLP, remediated audit-log gap).
- **6 scores** (overall + 5 domains) plus a 14-day score history per domain.
- **2 active campaigns** (Akira ransomware — RDP brute-force wave, Storm-1234 — credential phishing wave) with 2 tenant-side correlation hits.
- **1 KEV-flagged CVE** with active exploitation.
- **6 compliance frameworks** with realistic compliant / partial / non-compliant counts (CIS Azure, MCSB, NIST CSF, ISO 27001, SOC 2, GDPR).
- **5 scan history entries** — bootstrap + scheduled daily + one partial run hit by Graph throttling.
- **6 remediation actions** at every status from `suggested` → `succeeded`, mapped to **5 remediation templates** with deterministic CLI / Graph / Policy snippets.

All identifiers are stable, hand-curated UUIDs anchored to a `BASELINE_NOW = 2026-05-20T12:00:00Z` so demo output is **reproducible across processes**.

---

## 3. Running it locally

```bash
# 1. Backend (in apps/api/)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000

# 2. Frontend (in apps/frontend/)
nvm use 20
npm install
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev   # → http://localhost:3000

# 3. Sanity checks
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/dashboard/summary | jq .
```

CORS is enabled **only** when `AZURELENS_ENV=local` (the default). Origins are pinned to `http://localhost:3000` and `http://127.0.0.1:3000`; credentials are not allowed (no cookies leave the API). See `apps/api/app/main.py`. In any non-local environment the CORS block is bypassed and the production CORS policy is owned by APIM (Phase 1, see `docs/SECURITY_MODEL.md` § 7).

---

## 4. Endpoint map

| Endpoint | Purpose | Returns |
|---|---|---|
| `GET /api/v1/health` | Liveness | `{ status: "ok" }` |
| `GET /api/v1/dashboard/summary` | Composite home dashboard | overall + domain scores + top risks + threat exposure + compliance + recent scan + remediation roadmap |
| `GET /api/v1/dashboard/posture-summary` | Overall score + 7d delta | `OverallScoreSummary` |
| `GET /api/v1/dashboard/top-risks?limit=N` | Top N open findings by risk | `TopRiskItem[]` |
| `GET /api/v1/dashboard/threat-exposure-summary` | Active campaigns + KEV + techniques | `ThreatExposureSummary` |
| `GET /api/v1/dashboard/compliance-summary` | Per-framework score roll-ups | `ComplianceFrameworkSummary[]` |
| `GET /api/v1/dashboard/recent-scan` | Most recent scan | `RecentScanSummary` |
| `GET /api/v1/dashboard/remediation-roadmap` | Status counts + next actions | `RemediationRoadmapSummary` |
| `GET /api/v1/scores` | All current scores | `Score[]` |
| `GET /api/v1/scores/overview` | Overall + domains | `ScoreOverview` |
| `GET /api/v1/scores/{kind}` | Single domain score | `Score` |
| `GET /api/v1/scores/{kind}/history?days=N` | Daily snapshots | `ScoreHistory` |
| `GET /api/v1/scans` | Scan history | `ScanSummary[]` |
| `GET /api/v1/scans/recent` | Most recent scan | `RecentScanSummary` |
| `GET /api/v1/scans/{id}` | Single scan | `ScanSummary` |
| `POST /api/v1/scans` | Trigger scan (synthesized queued) | `ScanSummary (queued)` |
| `GET /api/v1/remediations?status=...` | List actions | `RemediationAction[]` |
| `GET /api/v1/remediations/templates` | List templates | `RemediationTemplate[]` |
| `GET /api/v1/remediations/roadmap` | Status counts + next actions | `RemediationRoadmapSummary` |
| `GET /api/v1/remediations/{id}` | Single action | `RemediationAction` |
| `POST /api/v1/remediations/{id}/approve` | Approve action (synthesized) | `RemediationAction (approved)` |
| `GET /api/v1/findings(/...)` | Existing Phase 2 placeholders | `FindingSummary[]` / `Finding` |
| `GET /api/v1/assets(/...)` | Existing Phase 2 placeholders | `AssetSummary[]` / `Asset` |
| `GET /api/v1/threat-intel/*` | Existing Phase 2 placeholders | TI shapes |
| `GET /api/v1/compliance/*` | Existing Phase 2 placeholders | compliance shapes |
| `GET /api/v1/reports(/...)` | Existing Phase 2 placeholders | report shapes |
| `GET /api/v1/tenants(/...)` | Existing Phase 2 placeholders | tenant shapes |

OpenAPI is exposed only when `AZURELENS_ENV=local` (at `/openapi.json` and `/docs`). Phase 1 restricts this to authenticated requests behind APIM.

---

## 5. Architecture

```
apps/frontend (Next.js)
  └─► apps/frontend/lib/api.ts        (typed fetch wrapper, NEXT_PUBLIC_API_BASE_URL)
        │
        ▼
apps/api  (FastAPI)
  ├─ app/main.py                       (CORS for local dev only)
  ├─ app/api/v1/router.py              (mounts dashboard/scores/scans/remediations + Phase 2 placeholders)
  ├─ app/api/v1/dashboard.py           (composite read endpoints)
  ├─ app/api/v1/scores.py              (current + history + overview)
  ├─ app/api/v1/scans.py               (history + trigger)
  ├─ app/api/v1/remediations.py        (actions + templates + approve)
  └─ app/demo/
       ├─ data.py                      (deterministic immutable constants)
       └─ service.py                   (DemoService facade; module-level singleton)
```

The routers depend on **only** `app.demo.demo_service` — the same call sites become persistence-backed when `DemoService` is replaced by a real service class in Phase 1.

---

## 6. Limitations

| Limitation | Replaced in |
|---|---|
| No auth (local CORS is sufficient) | Phase 1 — Entra ID JWT + tenant-context middleware + RBAC |
| No persistence | Phase 1 — Azure SQL + Cosmos DB + ADLS + AI Search |
| No multi-tenant; only "Contoso Demo" | Phase 1 — tenant onboarding + admin consent |
| `POST /scans` and `/approve` are synthesized | Phase 1 — Service Bus emit + persisted state |
| No idempotency-key cache | Phase 1 — `Idempotency-Key` middleware + 24h dedupe |
| No rate limiting | Phase 1 — APIM quota policies |
| No streaming for long-running ops | Phase 1 — Event Grid webhooks + (optionally) SSE |
| No tenant-residency enforcement on the demo dataset | Phase 1 — per-region routing through Front Door |
| No PII or secret-redaction middleware (none needed; demo data has none) | Phase 1 — structured logging with redaction |
| No score recalculation on data change | Phase 1+ — Service Bus `finding.normalized` → `services/risk-engine` |

---

## 7. Migrating off demo mode

The transition is intentionally one-line at the call site. Routers depend on the `DemoService` interface; the persistence-backed `TenantDataService` (Phase 1) will implement the same methods.

```python
# Phase 7 (now)
from app.demo import demo_service

@router.get("/summary")
async def dashboard_summary() -> DashboardSummary:
    return demo_service.dashboard_summary()

# Phase 1+ (drop-in)
from app.services.tenant_data import get_tenant_data_service

@router.get("/summary")
async def dashboard_summary(
    ctx: TenantContext = Depends(resolve_tenant_context),
) -> DashboardSummary:
    return await get_tenant_data_service(ctx).dashboard_summary()
```

The wire shapes — every Pydantic model, every enum value, every field name — stay identical. Frontend code, contract tests, and downstream integrators don't change. The only delta is auth + tenancy plumbing in front of the call.

---

## 8. What is explicitly NOT in demo mode

- ❌ No Microsoft Graph calls (Entra ID / EXO / SPO / Teams / OneDrive / Intune / Purview).
- ❌ No Azure Resource Graph or ARM REST calls.
- ❌ No Defender for Cloud / Defender XDR API calls.
- ❌ No Sentinel / Log Analytics workspace queries.
- ❌ No TI feed pulls (Defender TI, Sentinel TI, KEV, MITRE, MISP, OpenCTI, OTX, abuse.ch, GHSA, NVD, VirusTotal).
- ❌ No Azure OpenAI inference.
- ❌ No persistence — every API process restart yields the same state.
- ❌ No secrets read from anywhere. No Key Vault access. No `.env` reads with secret values.
- ❌ No outbound network from the API process.

These are all wired up in subsequent phases per `docs/ROADMAP.md`.

---

## 9. Safety properties (still applicable to demo data)

Even though demo data is synthetic:

- Domain suffix is `*.invalid` (RFC 6761 reserved).
- All UUIDs are non-overlapping with any real organization's hand-chosen identifiers (`00000000-…`, `aaaaaaa1-…`, `dddd0001-…` patterns).
- No real CVE that maps to a specific vendor product — `CVE-2024-00000` is a clearly fake placeholder.
- No real customer names, no real IPs from public allocations (only `203.0.113.0/24` documentation range per RFC 5737).
- No PII anywhere; no email recipients beyond `ciso@contoso.invalid`.

Demo data must remain free of these things even when extended.

---

## 10. Roadmap pointer

Demo mode is **Phase 7** in `docs/ROADMAP.md`. Phase 1 wires real persistence + auth + tenant onboarding behind the same wire contract. Phase 2 lights up scanners and threat-intel; Phase 5 lights up the AI engine. The dashboards built against demo mode continue to render unchanged at every step.
