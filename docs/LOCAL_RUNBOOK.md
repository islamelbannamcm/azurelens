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

## 7. Phase 12 — Known runtime issues and fixes

These are the recurring local-stack failures we hit while stabilising the
demo. Each row is the exact error string and the verified fix.

### 7.1 API — `ImportError: email-validator is not installed`

**Symptom** — `uvicorn app.main:app` (or any `pytest` run) aborts at import
time with:

```
ImportError: email-validator is not installed, run `pip install pydantic[email]`
```

…or the first request that touches a schema with `EmailStr` 500s with the
same message.

**Cause** — Pydantic 2.x makes `EmailStr` validation an optional extra. The
package only loads it if `email-validator` is installed, which it isn't in
a plain `pip install .`.

**Fix** — `apps/api/pyproject.toml` now declares `email-validator>=2.1,<3.0`
in `[project].dependencies`. Re-install in your venv:

```bash
cd apps/api
pip install -e ".[dev]"
# or, in the running container:
docker compose build api && docker compose up -d api
```

### 7.2 API Docker build — `KeyError: 'readme'` or hatchling complaining about README.md

**Symptom** — `docker compose build api` fails with one of:

```
KeyError: 'readme'
ValueError: Readme file does not exist: README.md
```

**Cause** — `apps/api/pyproject.toml` declares `readme = "README.md"`, so
hatchling reads the file during `pip install .`. Two regressions cause it
to be missing inside the builder stage:

1. The `Dockerfile`'s `COPY pyproject.toml README.md ./` line gets reordered
   or split so `pip install .` runs before README.md is in the working dir.
2. The `.dockerignore` starts excluding `*.md` (e.g. someone adds a generic
   "drop docs from images" line) and no explicit `!README.md` allow exists.

**Fix** — both are guaranteed in this repo:

- `apps/api/Dockerfile` builder stage already copies README.md **before**
  `pip install .`:
  ```Dockerfile
  COPY pyproject.toml README.md ./
  COPY app ./app
  RUN pip install --upgrade pip && pip install .
  ```
- `apps/api/.dockerignore` carries an explicit `!README.md` rule with a
  comment explaining why. Do not remove it.

If you fork and add docs exclusions, keep the explicit allow.

### 7.3 Frontend Docker build — `failed to compute cache key: "/app/public" not found`

**Symptom** — `docker compose build frontend` fails in the runner stage:

```
failed to compute cache key: failed to calculate checksum of ref ...:
  "/app/public": not found
```

**Cause** — `apps/frontend/Dockerfile` runner stage copies the public
folder verbatim:

```Dockerfile
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
```

If the directory is empty, git won't track it, the build context omits it,
and the `COPY` fails — even though Next.js itself doesn't require any
static assets to be present.

**Fix** — `apps/frontend/public/.gitkeep` is committed for exactly this
reason. If you delete or rename the file, restore it with any non-empty
content. (The committed file is a small comment explaining the contract;
the bytes don't matter to Next.js.)

### 7.4 Frontend port conflict — `Error: listen EADDRINUSE: address already in use 0.0.0.0:3000`

**Symptom** — `npm run dev` reports the address-in-use error, or Next.js
auto-falls-back to `:3001` and prints:

```
⚠ Port 3000 is in use, using available port 3001 instead.
```

This breaks the API CORS allow-list (`localhost:3000` only) and any
hard-coded links you copied from earlier sessions.

**Cause** — another process owns `:3000`, most often a stale `next dev`
from a previous shell, a Storybook instance, or a Docker container left
running.

**Fix**, in order of escalation:

1. **Find and kill the holder** (do not just live with `:3001`, it will
   keep CORS-failing):
   ```bash
   # macOS / Linux
   lsof -nP -iTCP:3000 -sTCP:LISTEN
   kill <pid>
   # If a previous compose stack still has it:
   docker compose down
   ```
2. **Run on a different port and update CORS + the API base URL** so the
   whole stack agrees. The API's local CORS allow-list lives in
   `apps/api/app/main.py`; add the new origin temporarily, or:
   ```bash
   PORT=3100 NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
   # then in apps/api venv, before launching uvicorn:
   export AZURELENS_EXTRA_CORS_ORIGINS=http://localhost:3100
   ```
   (`AZURELENS_EXTRA_CORS_ORIGINS` is reserved for this; if it's not yet
   wired up in your branch, prefer option 1 — freeing `:3000` is the
   supported path.)
3. **For Docker Compose**, remap host ports via env vars (see §3.1):
   ```bash
   FRONTEND_HOST_PORT=3100 NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 \
   docker compose up --build
   ```

If Next.js auto-bumped to `:3001` and you can't free `:3000`, treat it as
an error, not a workaround: nothing in this repo allow-lists `:3001`.

---

## 8. What is intentionally NOT here

- **No database, no migrations, no seed scripts.** Demo data lives in Python constants. Phase 1 brings Azure SQL + Cosmos.
- **No authentication.** No MSAL, no JWT validation. Phase 1 wires Entra ID.
- **No outbound calls to Microsoft Graph / ARG / Defender / Sentinel / Intune / Purview / Azure OpenAI / TI feeds.** Demo mode never touches an external service.
- **No state retained between runs.** Every process start replays the same anchored dataset.

For the deployment side of the same MVP, see `docs/AZURE_DEPLOYMENT_GUIDE.md`.
