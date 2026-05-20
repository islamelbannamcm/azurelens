# AzureLens — Azure Deployment Guide (Phase 9 → 1)

Two supported paths to take the demo MVP onto Azure:

1. **Simple App Service path** — quickest to get a public demo up; ideal for executive walkthroughs and design partner previews.
2. **Container Apps path** — the long-term, Azure-native production architecture documented in `docs/ARCHITECTURE.md`.

Both paths share the same Managed Identity, Key Vault, Storage account, Log Analytics workspace, Application Insights instance, and Virtual Network — the divergence is only in the compute tier.

> Phase 9 status: Terraform files in `infra/terraform/` are **production-oriented placeholders**, not fully deployable. They declare the shared platform resources (RG, identity, KV, Storage, observability, networking) plus *both* compute options as commented forward contracts. Real deploys land in Phase 1.

---

## 1. Architecture diff (both paths share this base)

```
                              Front Door + WAF (phase-1)
                                          │
                                          ▼
            ┌───────────────────────────────────────────────────┐
            │  Path A: App Service plan + 2 Web Apps             │
            │            (api + web)                              │
            │  Path B: Container Apps environment + N apps        │
            │            (api, scanner, ti, risk, ai, reporting)  │
            └───────────────────────────────────────────────────┘
                                          │
            ┌─────────────────────────────┴─────────────────────────────┐
            │                Shared platform resources                    │
            │  user-assigned MI · Key Vault (Premium) · Storage (ADLS    │
            │  Gen2) · Log Analytics · App Insights · VNet (PE subnet)   │
            │                                                              │
            │  Phase 1+: Azure SQL, Cosmos DB, Service Bus, AI Search,    │
            │  Azure OpenAI, ACR, APIM, Front Door, Sentinel             │
            └────────────────────────────────────────────────────────────┘
```

The Terraform file map under `infra/terraform/`:

| File | Owns |
|---|---|
| `providers.tf` | `terraform {}` + provider blocks (OIDC) |
| `locals.tf` | naming convention, tag composition, random suffix |
| `main.tf` | composition root + the resource group |
| `identity.tf` | shared user-assigned managed identity |
| `key_vault.tf` | Key Vault Premium (HSM-backed) + MI role binding |
| `storage.tf` | Storage account (ADLS Gen2) + MI role binding |
| `monitoring.tf` | Log Analytics workspace + Application Insights + MI binding |
| `networking.tf` | VNet, Container Apps subnet, PE subnet, NSG |
| `app_service.tf` | **Path A** — App Service plan + 2 Web Apps |
| `container_apps.tf` | **Path B** — Container Apps environment + planned workloads |
| `variables.tf` | input variables (environment, location, tenant/subscription ids, owner) |
| `outputs.tf` | outputs (Phase 1+) |

---

## 2. Prerequisites (both paths)

| | Purpose |
|---|---|
| Azure subscription with `Contributor` at the deploy scope | for `terraform apply` |
| GitHub OIDC federated credential on the subscription's deployment service principal | passwordless CI auth (`use_oidc = true` in providers.tf) |
| Terraform 1.7+ | local apply or CI runs |
| Azure CLI 2.60+ | `az login --tenant <platform-tenant>` for local applies |
| A bootstrap Storage account + container | remote state backend (planned; backend block in `providers.tf` is commented until Phase 1) |
| `tfvars` file per environment under `infra/terraform/envs/` | per-env inputs; **never** commit values for prod |

> Never commit a `tfvars` file with a value for any non-example environment. Secrets live in Key Vault; Terraform reads URIs and resource ids only.

---

## 3. Path A — Simple App Service (recommended for demo)

This path uses the resources defined in `infra/terraform/app_service.tf`. The API and frontend run as Linux Web Apps on a single P1v3 plan, share the platform Managed Identity, and emit telemetry into the shared Log Analytics workspace.

### 3.1 Apply

```bash
cd infra/terraform
terraform init -backend=false           # remote backend enabled in phase-1
terraform plan  -var-file=envs/dev.tfvars
terraform apply -var-file=envs/dev.tfvars
```

Expected resources after apply: resource group, user-assigned identity, Key Vault, Storage account, Log Analytics workspace, Application Insights, VNet + 2 subnets + NSG, App Service plan, **two Web Apps** (`app-azlens-api-<env>-<suffix>`, `app-azlens-web-<env>-<suffix>`), Container Apps environment.

### 3.2 Publish the images

Phase 1 wires Azure Container Registry. Until then, two manual options:

- **Image-from-GHCR**: tag images with `ghcr.io/<owner>/azurelens-api:<sha>` and switch the Web App's `application_stack` to `docker_image_name` in a follow-up apply.
- **Code zip-deploy**: deploy `apps/api` and `apps/frontend` source via `az webapp deploy --src-path` — only useful for short-lived demos.

### 3.3 Wire the frontend → API URL

`NEXT_PUBLIC_API_BASE_URL` is baked at **build time** (Next.js semantics). The deployment pipeline must:

1. Build the frontend image with `--build-arg NEXT_PUBLIC_API_BASE_URL=https://app-azlens-api-<env>-<suffix>.azurewebsites.net`.
2. Push the image to ACR (Phase 1) or GHCR.
3. Update the frontend Web App to reference that tag.

This is *not* an app setting — changing it without rebuilding does nothing.

### 3.4 Smoke checks

```bash
API=app-azlens-api-dev-<suffix>.azurewebsites.net
WEB=app-azlens-web-dev-<suffix>.azurewebsites.net

curl -s https://${API}/api/v1/health
curl -s https://${API}/api/v1/dashboard/summary | jq '.overall'
open https://${WEB}
```

### 3.5 Limitations of Path A (intentional)

- One App Service plan; you scale the whole tier together.
- No queue-based workers — the scanner / TI / risk / AI engines won't run here.
- Public ingress on both Web Apps; production posture needs Front Door + Private Endpoints (Phase 1).
- No Service Bus, no Cosmos, no SQL, no AI Search wired in. The API runs against demo data (`app.demo.demo_service`).

If you need workers, queues, or per-workload scaling, move to Path B.

---

## 4. Path B — Azure Container Apps (long-term target)

This path uses the resources defined in `infra/terraform/container_apps.tf` plus the planned per-workload `azurerm_container_app` resources commented inside that file. It targets the architecture in `docs/ARCHITECTURE.md` § 2.

### 4.1 What changes vs Path A

| | Path A (App Service) | Path B (Container Apps) |
|---|---|---|
| Compute | 1 App Service plan, 2 Web Apps | 1 Container Apps env, 5+ apps |
| Scaling | tier-level | per-app via KEDA scalers |
| Workers (scanner / TI / risk / AI) | not supported | first-class |
| Ingress | direct Web App URL | APIM Internal → Container Apps internal LB |
| Deploys | image swap | revisions (blue/green) |
| AI inference | not supported | Dedicated workload profile |
| Cost floor | always-on plan | scale-to-zero per app |

### 4.2 Pre-conditions before flipping to Path B

1. **Azure Container Registry** with the platform MI granted `AcrPull`.
2. **Service Bus Premium** namespace + topics from `docs/ARCHITECTURE.md` § 6.1.
3. **Azure SQL Hyperscale** + **Cosmos DB** + **Azure AI Search** + **Azure OpenAI** (per data residency).
4. **APIM Internal** as the ingress for the Container Apps internal LB.
5. **Front Door Premium + WAF** in front of APIM.
6. **Private Endpoints** for every PaaS surface (KV, Storage, SQL, Cosmos, Service Bus, AI Search, OpenAI, ACR).

All of these arrive in Phase 1; Phase 9 ships only the environment scaffolding.

### 4.3 Apply (Phase 1+)

Same `terraform init / plan / apply` cycle as Path A. The `container_apps.tf` file already declares the environment + the Consumption workload profile + the dedicated subnet + the LAW link.

### 4.4 Per-workload Container Apps (planned)

See the commented `TODO(phase-1+)` block in `container_apps.tf`:

| App | Scaler | Profile |
|---|---|---|
| `api` | HTTP-concurrency | Consumption |
| `scanner` | Service Bus message-count | Consumption |
| `threat-intel` | timer + Service Bus | Consumption |
| `risk-engine` | Service Bus | Consumption |
| `ai-engine` | HTTP + Service Bus | Dedicated (D4) |
| `reporting` | HTTP (triggers) + Jobs (long-running renders) | Consumption + Jobs |

Each app uses the shared user-assigned MI, pulls from ACR, mounts Key Vault references for any secret env value, and emits OpenTelemetry to App Insights.

---

## 5. CI/CD (Phase 1+)

Pipelines run via GitHub Actions with **OIDC federation** to Azure — no PATs or client secrets stored in GitHub:

| Pipeline | Trigger | Steps |
|---|---|---|
| `pr-validate` | PR / push to feature branch | terraform fmt/validate, container build (no push), unit tests |
| `build-and-publish` | merge to `main` | build container images, sign (Cosign), push to ACR |
| `deploy-dev` | post-build | `terraform plan` + `terraform apply -var-file=envs/dev.tfvars` |
| `deploy-staging` | manual approval | revision swap / Web App image swap to staging tag |
| `deploy-prod` | manual approval + change ticket | progressive rollout (10 / 50 / 100), automatic rollback on SLO burn |
| `release-customer-hosted` | tag `chx-*` | publish signed Bicep bundle (parity path) |

Auth flow:

```
GitHub Actions runner
   └─► OIDC token request to GitHub OIDC issuer
         └─► Federated credential exchange at Entra ID
               └─► Short-lived Azure ARM token (no secrets stored)
                     └─► terraform / az / docker push run
```

---

## 6. Cost notes (rough order of magnitude per environment)

| Resource | Default SKU | Approx. monthly |
|---|---|---|
| App Service plan | P1v3 Linux | ~$135 |
| Container Apps environment | Consumption | scale-to-zero (cents at idle) |
| Key Vault Premium | HSM-backed | ~$5 + per-op |
| Storage account | Standard ZRS | < $5 at demo volume |
| Log Analytics workspace | 90d / PerGB2018 | < $5 at demo volume |
| Application Insights | workspace-based | included in LAW cost |
| VNet + NSGs | — | free |
| **Phase 1 additions** | | |
| Azure SQL Business Critical | Gen5 8 vCore | ~$1,500 |
| Cosmos DB autoscale | 4k RU baseline | ~$250 |
| Azure OpenAI (PAYG, Pro tier) | model-dependent | $50–$500 |
| Front Door + WAF Premium | — | ~$330 |
| APIM Premium 1 unit | — | ~$2,800 |

These are illustrative; real numbers depend on traffic, retention, and AI usage.

---

## 7. Safety properties of Phase 9 IaC

- **No `Owner` role anywhere.** The deploy SP uses `Contributor` (Phase 9) and least-privilege custom roles per pipeline stage (Phase 1+).
- **No inline secrets.** Every Phase 9 resource that *could* take a secret either takes none (Key Vault) or references the platform MI for runtime resolution.
- **No public data plane.** Storage, Key Vault, and (Phase 1+) SQL / Cosmos / AI Search all set `public_network_access_enabled = false` or `network_acls.default_action = "Deny"`. Where Private Endpoints don't exist yet, the resources remain unreachable until they do.
- **Soft-delete + purge protection** on Key Vault (90 d) and Storage (30 d).
- **Tag every resource** with `azurelens.environment / owner / cost_center / managed_by / phase` for FinOps + SLO breakdown.

---

## 8. Moving from Phase 9 demo to Phase 1 production

| Action | Phase 9 (demo) | Phase 1 (prod) |
|---|---|---|
| Identity | shared user-assigned MI | per-workload MIs |
| Auth | none | Entra ID JWT + tenant context middleware + RBAC matrix |
| Persistence | demo constants | Azure SQL (Hyperscale) + Cosmos DB + ADLS Gen2 |
| Eventing | none | Service Bus Premium + Event Grid + Event Hubs |
| AI | none | Azure OpenAI (PAYG / PTU) + AI Search + Content Safety |
| Connectors | none | scanner workers + TI connectors per `docs/SCANNER_ARCHITECTURE.md` / `docs/THREAT_INTEL_ARCHITECTURE.md` |
| Network | public VNet shell | hub-spoke + Azure Firewall + Private Endpoints everywhere |
| Ingress | direct Web App / Container Apps URL | Front Door Premium + WAF + APIM Internal + Private Link |
| Observability | LAW + App Insights only | + Sentinel + Workbooks + action groups + Defender for Cloud Plans P2 |
| Compliance | platform defaults | Defender for Cloud regulatory standards + Azure Policy initiative |
| Release | local terraform apply | GitHub Actions OIDC → ACR → revision swap |

Every Phase 9 resource stays — Phase 1 *adds* to it, never replaces, so the upgrade is incremental and reversible.

For the local side of the same MVP, see `docs/LOCAL_RUNBOOK.md`.
