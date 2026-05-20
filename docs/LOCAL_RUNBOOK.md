# AzureLens — Local Runbook (Phase 9)

How to run the demo MVP on a developer laptop. Three supported paths:

1. **Native** — `uvicorn` for the API, `next dev` for the frontend.
2. **Docker Compose** — `docker compose up --build` (one command, both services).
3. **Frontend-only** — render the dashboard against the static fallback dataset, no backend required.

All three produce the same Contoso Demo dashboard. None require any Azure subscription, Microsoft Graph access, or external API keys.

---

## 1. Prerequisites

| Tool | Version | Used by |
|---|---|---|
| Python | 3.11.x | `apps/api/` |
| Node.js | 20 LTS | `apps/frontend/` |
| Docker Engine + Compose v2 | latest | `docker compose` path |
| Git | 2.40+ | working with the repo |

Optional: `direnv` for `.envrc`-driven env loading; `pre-commit` once we ship a config in a later phase.

---

## 2. Native (recommended for active development)

### 2.1 Backend — FastAPI on `:8000`

```bash
cd apps/api
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

uvicorn app.main:app --reload --port 8000
```

Smoke checks:

```bash
curl http://localhost:8000/api/v1/health
curl -s http://localhost:8000/api/v1/dashboard/summary | head -c 400
```

CORS is enabled **only** when `AZURELENS_ENV=local` (the default). Allowed origins are `http://localhost:3000` and `http://127.0.0.1:3000`. See `apps/api/app/main.py`.

### 2.2 Frontend — Next.js dev server on `:3000`

```bash
cd apps/frontend
nvm use 20            # or: any Node 20.x
npm install
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
```

Open `http://localhost:3000`.

If the API isn't running, the page falls back to the embedded static demo dataset and shows a yellow banner indicating the API is unreachable.

### 2.3 Stopping

Hit `Ctrl-C` in each terminal. No background workers, no databases, nothing to clean up.

---

## 3. Docker Compose (one command, both services)

Bring everything up:

```bash
cp .env.example .env       # only contains safe placeholders
docker compose up --build
```

Tear down:

```bash
docker compose down
```

What you get:

| Service | Host port | Container image | Healthcheck |
|---|---|---|---|
| `api` | `${API_HOST_PORT:-8000}` | `azurelens/api:demo` | `GET /api/v1/health` |
| `frontend` | `${FRONTEND_HOST_PORT:-3000}` | `azurelens/frontend:demo` | `GET /` |

`NEXT_PUBLIC_API_BASE_URL` is baked into the Next.js build at compose-build time. The default (`http://localhost:8000`) works because the browser reaches the API on the host's mapped port, not via the container DNS name.

### 3.1 Customizing ports

```bash
API_HOST_PORT=8080 FRONTEND_HOST_PORT=4000 \
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080 \
docker compose up --build
```

### 3.2 Rebuilding after frontend changes

`NEXT_PUBLIC_*` is baked at build time, so frontend code or env changes need a rebuild:

```bash
docker compose build frontend && docker compose up -d frontend
```

---

## 4. Frontend-only (no backend, no dependencies)

If you just want to look at the dashboard:

```bash
cd apps/frontend
nvm use 20
npm install
npm run dev
```

Don't set `NEXT_PUBLIC_API_BASE_URL`, or set it to a deliberately unreachable host. The page server-fetches with a 2.5 s timeout, fails fast, and renders the embedded static `FALLBACK_DASHBOARD` from `apps/frontend/app/page.tsx`. A yellow banner explains the fallback.

This path is what CI uses for visual regression / Storybook-like previews until those workflows ship.

---

## 5. Verifying you're really in demo mode

Open the API at `http://localhost:8000/docs` (Swagger UI). All `/api/v1/dashboard/*`, `/api/v1/scores/*`, `/api/v1/scans/*`, and `/api/v1/remediations/*` endpoints respond with deterministic data anchored to `BASELINE_NOW = 2026-05-20T12:00:00Z`. There are no outbound network calls. The OS process has no Microsoft credentials.

```bash
# Quick health + summary check
curl -s http://localhost:8000/api/v1/health | jq .
curl -s http://localhost:8000/api/v1/dashboard/summary | jq '.overall, .recent_scan'
```

The same tenant id (`00000000-0000-0000-0000-000000000001`) and the same numbers (overall 64, identity 58, etc.) appear on every fresh process — see `apps/api/app/demo/data.py`.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ECONNREFUSED` from the frontend | API not running | `uvicorn app.main:app --reload --port 8000` or `docker compose up api` |
| Frontend shows the yellow fallback banner | API fetch timed out / failed | Start the backend or set `NEXT_PUBLIC_API_BASE_URL` to a reachable host |
| `CORS error` in the browser | API is running in a non-`local` env | Set `AZURELENS_ENV=local` (or stop importing the API client from a foreign origin) |
| `docker compose build` fails on `npm install` | Network or registry blocked | Check corporate proxy; or run `npm install` outside Docker first |
| Healthcheck never goes healthy | Port collision with another service | Re-map via `${API_HOST_PORT}` / `${FRONTEND_HOST_PORT}` |
| OpenAPI `/docs` returns 404 | `AZURELENS_ENV` is not `local` | Demo mode only exposes Swagger when `is_local` is true |

---

## 7. What is intentionally NOT here

- **No database, no migrations, no seed scripts.** Demo data lives in Python constants. Phase 1 brings Azure SQL + Cosmos.
- **No authentication.** No MSAL, no JWT validation. Phase 1 wires Entra ID.
- **No outbound calls to Microsoft Graph / ARG / Defender / Sentinel / Intune / Purview / Azure OpenAI / TI feeds.** Demo mode never touches an external service.
- **No state retained between runs.** Every process start replays the same anchored dataset.

For the deployment side of the same MVP, see `docs/AZURE_DEPLOYMENT_GUIDE.md`.
