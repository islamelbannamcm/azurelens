###############################################################################
# AzureLens — Key Vault (Premium / HSM-backed)
#
# Houses platform secrets, customer connector credentials (Phase 1+), and
# Customer-Managed Keys for SQL / Storage / Cosmos / Backup. See
# docs/SECURITY_MODEL.md § 5.
#
# Phase 9 ships the vault + the platform Managed Identity's "Key Vault
# Secrets User" role assignment. Per-tenant CMK rotation and customer
# connector secrets arrive in Phase 1.
###############################################################################

resource "azurerm_key_vault" "platform" {
  name                = local.key_vault_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = var.tenant_id

  sku_name = "premium" # HSM-backed; required for CMK in Enterprise tier

  # RBAC mode only — legacy access policies are forbidden by platform policy.
  enable_rbac_authorization = true

  # Recoverability + tamper resistance.
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  # Public access denied at the data plane. Private Endpoints wired up in
  # networking.tf once private DNS zones exist (Phase 1+).
  public_network_access_enabled = false

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
  }

  tags = local.common_tags
}

# Platform identity reads secrets at runtime via Managed Identity.
resource "azurerm_role_assignment" "platform_kv_secrets_user" {
  scope                = azurerm_key_vault.platform.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.platform.principal_id
}

# TODO(phase-1):
#   * Add 'Key Vault Crypto User' for the SQL / Storage / Cosmos service
#     principals so they can use CMK at the storage layer.
#   * Wire up Private Endpoint + private DNS zone link from networking.tf.
#   * Diagnostic settings → Log Analytics workspace.
#   * Per-tenant CMK keys + version rotation drills.
#   * Sentinel analytics rules tuned to KV anomalies (mass getSecret, etc.).
