# infra/terraform

Terraform placeholder for AzureLens infrastructure-as-code. No real resources defined yet.

## Why Terraform here

`docs/ARCHITECTURE.md` § 5 specifies **Bicep as primary IaC** with **Terraform parity modules** for the ISV / customer-hosted deployment mode (where customers prefer Terraform). This directory is the Terraform half of that strategy.

The Bicep tree will live under `infra/bicep/` and is introduced in Phase 1 of the roadmap.

## Future Responsibilities

- One `main.tf` per environment composing reusable modules.
- Module set mirroring the Bicep modules:
  - `network/` (hub-spoke VNet, private endpoints, private DNS zones, Azure Firewall)
  - `identity/` (user-assigned managed identities, RBAC role assignments)
  - `data/` (Azure SQL, Cosmos DB, ADLS Gen2 + Blob, Azure AI Search)
  - `compute/` (Container Apps environment, Functions, Static Web Apps)
  - `eventing/` (Service Bus, Event Grid, Event Hubs)
  - `ai/` (Azure OpenAI, Prompt Flow)
  - `frontdoor/` (Front Door + WAF)
  - `apim/` (API Management Internal)
  - `keyvault/` (Key Vault Premium + HSM-backed keys)
  - `observability/` (Log Analytics Workspace, Application Insights, Workbooks)
  - `security/` (Defender for Cloud plans, Microsoft Sentinel, Azure Policy initiative)
  - `powerbi/` (Embedded workspace)

## Backend & State (planned)

- Remote state in an **Azure Storage account** with:
  - **CMK** encryption,
  - **Private Endpoint** only,
  - per-environment containers + state-file locking via blob lease,
  - immutability + soft-delete + versioning.
- One state file per `(environment, region)` tuple.

```hcl
# Example (will be added in Phase 1):
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "rg-tfstate"
#     storage_account_name = "stazurelens<env>tfstate"
#     container_name       = "tfstate"
#     key                  = "azurelens.<env>.tfstate"
#     use_oidc             = true   # OIDC from GitHub Actions, no PATs
#   }
# }
```

## Authentication (planned)

- **GitHub Actions OIDC** federation to Azure (`use_oidc = true`); no client secrets.
- **Managed Identity** for any in-Azure invocations.
- No subscription-scope `Owner`; least-privilege custom roles per pipeline stage.

## Local Development (planned)

```bash
cd infra/terraform
az login --tenant <platform-tenant>
terraform init -backend-config=envs/dev.backend.tfvars
terraform plan  -var-file=envs/dev.tfvars
terraform apply -var-file=envs/dev.tfvars   # gated; never run against prod locally
```

Never commit `.tfvars` for non-example environments. They are gitignored. Secrets must come from Azure Key Vault, not Terraform variables.

## Status

Empty placeholders only. Real modules introduced in Phase 1 (`docs/ROADMAP.md`).
