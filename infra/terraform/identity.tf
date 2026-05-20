###############################################################################
# AzureLens — User-assigned Managed Identity
#
# A single user-assigned managed identity that the API + frontend Container
# Apps / App Services share for outbound calls to Azure data-plane resources
# (Key Vault, SQL via AAD, Storage, Service Bus, Cosmos, App Insights).
#
# Phase 1+ may split this into per-workload identities (e.g. one for the
# scanner workers, one for the AI engine) so RBAC stays minimal-blast-radius.
###############################################################################

resource "azurerm_user_assigned_identity" "platform" {
  name                = local.managed_identity_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = local.common_tags
}

# Per-resource role assignments live next to the resources they bind to so
# the relationship is reviewable in one place — see ``key_vault.tf``,
# ``storage.tf``, ``monitoring.tf``.
#
# Planned bindings (created as their target resources come online):
#
#   * Key Vault Secrets User on the platform Key Vault                  (key_vault.tf)
#   * Storage Blob Data Reader on the platform Storage account           (storage.tf)
#   * Monitoring Metrics Publisher on Application Insights               (monitoring.tf)
#   * SQL Server AAD admin / db-level role                  (phase-1; data.tf)
#   * Cosmos DB Built-in Data Reader on platform Cosmos     (phase-1; data.tf)
#   * Service Bus Data Receiver / Sender on platform ns     (phase-1; eventing.tf)
#   * AcrPull on the platform Azure Container Registry      (phase-1; acr.tf)
#   * Cognitive Services User on Azure OpenAI               (phase-5; ai.tf)
