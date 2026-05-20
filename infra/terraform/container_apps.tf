###############################################################################
# AzureLens — Azure Container Apps (long-term deployment path)
#
# Phase 9 ships the Container Apps environment wired to:
#   * the platform Log Analytics workspace (for stdout / stderr + APM),
#   * the dedicated VNet subnet from networking.tf,
#   * a Consumption workload profile (a Dedicated profile is added for AI
#     inference / heavy workers in Phase 1+).
#
# Actual Container App resources (API + workers) come online in Phase 1
# alongside Service Bus + KEDA scalers + APIM ingress + revisions for
# blue/green deployment. See docs/AZURE_DEPLOYMENT_GUIDE.md.
###############################################################################

resource "azurerm_container_app_environment" "platform" {
  name                = local.container_apps_env_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  log_analytics_workspace_id = azurerm_log_analytics_workspace.platform.id

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  infrastructure_subnet_id       = azurerm_subnet.container_apps.id
  internal_load_balancer_enabled = false # phase-1: true; ingress via APIM Internal
  zone_redundancy_enabled        = false # phase-1: true on Pro / Enterprise tiers

  tags = local.common_tags
}

# TODO(phase-1): add a Dedicated workload profile for AI inference + heavy
# workers (one D4 node):
#
# workload_profile {
#   name                  = "ai-d4"
#   workload_profile_type = "D4"
#   minimum_count         = 1
#   maximum_count         = 3
# }

# TODO(phase-1+): add azurerm_container_app resources per workload:
#
#   * api               — HTTP ingress; KEDA HTTP-concurrency scaler;
#                          uses the Consumption profile.
#   * scanner           — Service Bus message-count scaler;
#                          uses the Consumption profile.
#   * threat-intel      — timer-driven; uses the Consumption profile.
#   * risk-engine       — Service Bus scaler; uses the Consumption profile.
#   * ai-engine         — HTTP + Service Bus; uses the Dedicated profile.
#   * reporting         — HTTP for short triggers; Container Apps Jobs for
#                          long-running PDF renders.
#
# Each Container App will:
#   * use the platform user-assigned managed identity,
#   * pull from ACR via AcrPull on the identity,
#   * mount Key Vault references for env values that resolve to secrets,
#   * emit OpenTelemetry to App Insights,
#   * use revisions for blue/green deploys.
