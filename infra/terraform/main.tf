###############################################################################
# AzureLens — Terraform root composition
#
# This file is the composition root only. Concerns are split:
#
#   providers.tf      required providers + provider configurations
#   variables.tf      input variables
#   outputs.tf        output values
#   locals.tf         naming convention + tag composition + random suffix
#   identity.tf       shared user-assigned managed identity
#   key_vault.tf      platform Key Vault (Premium HSM)
#   storage.tf        platform Storage account (ADLS Gen2)
#   monitoring.tf     Log Analytics workspace + Application Insights
#   networking.tf    VNet + Container Apps subnet + PE subnet placeholder
#   app_service.tf   App Service plan + API web app + frontend web app
#   container_apps.tf Container Apps environment (long-term target)
#
# This file owns the resource group that anchors every other resource.
# Real module composition (./modules/*) is introduced in Phase 1 as each
# module is fleshed out — until then resources live at the root for
# readability.
###############################################################################

resource "azurerm_resource_group" "main" {
  name     = local.resource_group_name
  location = var.location

  tags = local.common_tags
}

# --- Composition placeholder (uncomment as modules come online) -----------
# module "identity"        { source = "./modules/identity"        ... }
# module "key_vault"       { source = "./modules/key_vault"       ... }
# module "storage"         { source = "./modules/storage"         ... }
# module "monitoring"      { source = "./modules/monitoring"      ... }
# module "networking"      { source = "./modules/networking"      ... }
# module "app_service"     { source = "./modules/app_service"     ... }
# module "container_apps"  { source = "./modules/container_apps"  ... }
