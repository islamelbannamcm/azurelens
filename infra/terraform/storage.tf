###############################################################################
# AzureLens — Storage account
#
# In production this account anchors:
#   * ADLS Gen2 for raw scan evidence (immutable retention, CMK)
#   * Blob containers for generated reports
#   * Immutable containers for audit logs
#
# Phase 9 ships the account + the platform identity's "Blob Data Reader"
# role assignment. CMK, Private Endpoints, immutable retention policies,
# and lifecycle management arrive in Phase 1.
###############################################################################

resource "azurerm_storage_account" "platform" {
  name                = local.storage_account_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  account_tier             = "Standard"
  account_replication_type = "ZRS"
  account_kind             = "StorageV2"

  is_hns_enabled = true # ADLS Gen2 hierarchical namespace

  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false # MI / OAuth only — no SAS account keys
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  tags = local.common_tags

  # TODO(phase-1):
  #   * Customer-Managed Key encryption (link CMK in azurerm_key_vault.platform).
  #   * Immutable retention policy on audit containers (time-based + legal hold).
  #   * Private Endpoints + private DNS zone link.
  #   * Lifecycle management (cool → archive transitions for old evidence).
  #   * Defender for Storage enabled at the subscription scope (see security.tf in phase-1).
}

# Platform identity reads blob metadata + content via Managed Identity.
resource "azurerm_role_assignment" "platform_blob_reader" {
  scope                = azurerm_storage_account.platform.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.platform.principal_id
}

# TODO(phase-1): add 'Storage Blob Data Contributor' on a NARROW container
# scope for the report-writer worker — never at account level.
