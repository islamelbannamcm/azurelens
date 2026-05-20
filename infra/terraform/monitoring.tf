###############################################################################
# AzureLens — Observability (Log Analytics + Application Insights)
#
# Every platform service emits traces, logs, and metrics into one Log
# Analytics workspace per environment. Application Insights is workspace-
# based (no classic CC) and inherits the workspace's retention + CMK
# posture.
#
# Phase 9 ships the workspace + App Insights + the platform identity's
# "Monitoring Metrics Publisher" role on App Insights so workloads can
# push custom metrics. Sentinel onboarding + workbooks + action groups
# arrive in Phase 1.
###############################################################################

resource "azurerm_log_analytics_workspace" "platform" {
  name                = local.log_analytics_workspace_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  sku               = "PerGB2018"
  retention_in_days = 90

  # Operators query via private link only; ingestion happens from internal
  # workloads + APIM diagnostics so internet ingestion stays enabled.
  internet_ingestion_enabled = true
  internet_query_enabled     = false

  tags = local.common_tags

  # TODO(phase-1):
  #   * Daily ingestion cap to avoid runaway cost on chatty connectors.
  #   * Customer-managed key encryption (CMK in azurerm_key_vault.platform).
  #   * Microsoft Sentinel solution enable (separate resource).
  #   * Diagnostic settings on every platform resource → this workspace.
}

resource "azurerm_application_insights" "platform" {
  name                = local.application_insights_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  workspace_id     = azurerm_log_analytics_workspace.platform.id
  application_type = "web"

  # Telemetry sampling is configured per-workload via APPLICATIONINSIGHTS_*
  # env vars in app_service.tf / container_apps.tf.

  tags = local.common_tags
}

resource "azurerm_role_assignment" "platform_metrics_publisher" {
  scope                = azurerm_application_insights.platform.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_user_assigned_identity.platform.principal_id
}

# TODO(phase-1):
#   * Action groups → PagerDuty / Teams.
#   * Smart Detection rules for the API workload.
#   * Workbooks for per-tenant scan latency + TI freshness + AI cost SLOs.
#   * Defender for Cloud onboarding at the subscription scope.
#   * Sentinel analytics rules: cross-tenant attempts, KV anomalies,
#     mass-export events, AI prompt-injection signals.
