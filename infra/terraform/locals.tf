###############################################################################
# AzureLens — Local values
#
# Centralize naming conventions, tag composition, and a stable per-environment
# random suffix used for global-scoped resources (Storage, Key Vault). One
# source of truth so every module reads the same identifiers.
###############################################################################

locals {
  # Naming convention: <prefix>-<workload>-<environment>-<region-suffix>
  prefix        = "azlens"
  workload      = "platform"
  region_suffix = substr(replace(var.location, " ", ""), 0, 6)

  resource_group_name = "rg-${local.prefix}-${var.environment}-${local.region_suffix}"

  # Tags applied to every resource. Operator-supplied `common_tags` is merged
  # on top so per-environment overrides win. Cost attribution via
  # ``azurelens.cost_center`` — see docs/AZURE_SERVICES.md § 12.
  common_tags = merge(
    {
      "azurelens.platform"    = "azurelens"
      "azurelens.environment" = var.environment
      "azurelens.owner"       = var.owner
      "azurelens.cost_center" = var.cost_center
      "azurelens.managed_by"  = "terraform"
      "azurelens.phase"       = "9"
    },
    var.common_tags,
  )

  # Stable per-environment random suffix (recomputed only when ``environment``
  # changes). Used to make globally-scoped names unique without leaking the
  # subscription id.
  suffix = random_string.suffix.result

  # Names — kept here so every module reads the same string.
  storage_account_name = lower(replace(
    "st${local.prefix}${var.environment}${local.suffix}",
    "-",
    "",
  ))
  key_vault_name               = "kv-${local.prefix}-${var.environment}-${local.suffix}"
  log_analytics_workspace_name = "law-${local.prefix}-${var.environment}-${local.region_suffix}"
  application_insights_name    = "appi-${local.prefix}-${var.environment}-${local.region_suffix}"
  app_service_plan_name        = "asp-${local.prefix}-${var.environment}-${local.region_suffix}"
  container_apps_env_name      = "cae-${local.prefix}-${var.environment}-${local.region_suffix}"
  managed_identity_name        = "id-${local.prefix}-${var.environment}-${local.region_suffix}"
  vnet_name                    = "vnet-${local.prefix}-${var.environment}-${local.region_suffix}"
}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  lower   = true
  numeric = true
  special = false

  keepers = {
    environment = var.environment
  }
}
