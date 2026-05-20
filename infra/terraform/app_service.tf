###############################################################################
# AzureLens — App Service (simple deployment path)
#
# Phase 9 ships:
#   * a Linux App Service Plan (P1v3),
#   * a Linux Web App for the API (api),
#   * a Linux Web App for the frontend (web),
#   * both wired to the platform Managed Identity + Application Insights.
#
# This is the "simple deployment path" — easier to demo than full Container
# Apps. The Container Apps path in container_apps.tf is the long-term
# Azure-native target. See docs/AZURE_DEPLOYMENT_GUIDE.md.
#
# Container images are published in Phase 1 (via GitHub Actions OIDC →
# Azure Container Registry). The image references are commented out below
# until ACR exists.
###############################################################################

resource "azurerm_service_plan" "platform" {
  name                = local.app_service_plan_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  os_type  = "Linux"
  sku_name = "P1v3"

  tags = local.common_tags
}

# --- API web app -----------------------------------------------------------

resource "azurerm_linux_web_app" "api" {
  name                = "app-${local.prefix}-api-${var.environment}-${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_service_plan.platform.location
  service_plan_id     = azurerm_service_plan.platform.id

  https_only                    = true
  public_network_access_enabled = true # phase-1: false + Private Endpoint + Front Door

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.platform.id]
  }

  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
    http2_enabled       = true
    use_32_bit_worker   = false
    health_check_path   = "/api/v1/health"

    application_stack {
      # In Phase 1 we switch to a docker_image reference once ACR is wired.
      # docker_image_name = "<acr-loginserver>/azurelens/api:<sha>"
      python_version = "3.11"
    }
  }

  app_settings = {
    AZURELENS_ENV                         = var.environment
    WEBSITES_PORT                         = "8000"
    AZURE_CLIENT_ID                       = azurerm_user_assigned_identity.platform.client_id
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.platform.connection_string
    # Phase 1 wires these via Key Vault references (no inline secrets):
    #   AZURELENS_KEYVAULT_URI       = azurerm_key_vault.platform.vault_uri
    #   AZURELENS_SQL_CONNECTION_REF = "@Microsoft.KeyVault(SecretUri=...)"
    #   AZURELENS_COSMOS_ENDPOINT    = azurerm_cosmosdb_account.platform.endpoint
    #   AZURELENS_SERVICEBUS_FQNS    = "<ns>.servicebus.windows.net"
  }

  tags = local.common_tags

  # TODO(phase-1):
  #   * virtual_network_subnet_id pointing to a dedicated outbound subnet.
  #   * public_network_access_enabled = false; ingress only via Front Door + APIM.
  #   * Diagnostic settings → Log Analytics workspace.
  #   * App Configuration reference for feature flags.
}

# --- Frontend web app ------------------------------------------------------

resource "azurerm_linux_web_app" "frontend" {
  name                = "app-${local.prefix}-web-${var.environment}-${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_service_plan.platform.location
  service_plan_id     = azurerm_service_plan.platform.id

  https_only                    = true
  public_network_access_enabled = true # phase-1: behind Front Door

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.platform.id]
  }

  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
    http2_enabled       = true
    health_check_path   = "/"

    application_stack {
      node_version = "20-lts"
    }
  }

  app_settings = {
    NODE_ENV                              = "production"
    WEBSITES_PORT                         = "3000"
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.platform.connection_string
    # NEXT_PUBLIC_API_BASE_URL is baked at BUILD time, not as an app setting.
    # See docs/AZURE_DEPLOYMENT_GUIDE.md for the build-arg wiring.
  }

  tags = local.common_tags

  # TODO(phase-1):
  #   * Static Web Apps as an alternative for the SPA-only frontend variant.
  #   * SSR via container image deploy once ACR is online.
  #   * Diagnostic settings → Log Analytics workspace.
}
