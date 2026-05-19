###############################################################################
# AzureLens — Terraform root composition (PLACEHOLDER)
#
# Skeleton only. No resources are declared in this branch.
#
# In Phase 1 this file will compose the module set described in README.md:
#   network, identity, data, compute, eventing, ai, frontdoor, apim,
#   keyvault, observability, security, powerbi.
#
# Authentication target: GitHub Actions OIDC federation to Azure
# (no client secrets). Remote state backend will live in an Azure Storage
# account with CMK + Private Endpoint + soft-delete + versioning.
#
# See:
#   - docs/ARCHITECTURE.md  § 5  (Azure-native patterns)
#   - docs/AZURE_SERVICES.md     (service catalog & SKUs)
#   - docs/SECURITY_MODEL.md § 7 (network) and § 5 (secrets)
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

  # TODO(phase-1): enable remote state backend.
  # backend "azurerm" {
  #   # values supplied via -backend-config in CI; never hard-coded here
  # }
}

provider "azurerm" {
  features {}
  # OIDC for GitHub Actions, no secrets:
  use_oidc = true
}

provider "azapi" {
  use_oidc = true
}

# --- Composition placeholder -------------------------------------------------
# module "network"      { source = "./modules/network"      ... }
# module "identity"     { source = "./modules/identity"     ... }
# module "keyvault"     { source = "./modules/keyvault"     ... }
# module "data"         { source = "./modules/data"         ... }
# module "eventing"     { source = "./modules/eventing"     ... }
# module "compute"      { source = "./modules/compute"      ... }
# module "ai"           { source = "./modules/ai"           ... }
# module "apim"         { source = "./modules/apim"         ... }
# module "frontdoor"    { source = "./modules/frontdoor"    ... }
# module "observability"{ source = "./modules/observability"... }
# module "security"     { source = "./modules/security"     ... }
# module "powerbi"      { source = "./modules/powerbi"      ... }
