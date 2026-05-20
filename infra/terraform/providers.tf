###############################################################################
# AzureLens — Terraform required providers + provider configurations
#
# Phase 9 splits providers out of main.tf into this file so the composition
# root stays focused on module wiring. Remote-state backend values are
# supplied via `-backend-config` in CI; never hard-coded here. See
# docs/AZURE_DEPLOYMENT_GUIDE.md.
###############################################################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # TODO(phase-1): enable remote state once the bootstrap storage account
  # exists. Backend params injected via `-backend-config` in CI.
  # backend "azurerm" {
  #   # values supplied via -backend-config
  # }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy          = false
      recover_soft_deleted_key_vaults       = true
      purge_soft_deleted_secrets_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }

  # GitHub OIDC federation — no client secrets in CI.
  use_oidc = true
}

provider "azapi" {
  use_oidc = true
}

provider "random" {}
