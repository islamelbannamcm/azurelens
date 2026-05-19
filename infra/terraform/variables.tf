###############################################################################
# AzureLens — Terraform input variables (PLACEHOLDER)
#
# Skeleton only. No variables are consumed yet. Phase 1 introduces the full
# input surface for every module (sensitive values come from Key Vault, never
# from .tfvars files).
###############################################################################

variable "environment" {
  description = "Deployment environment. Must match an envs/<env>.tfvars file."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod", "customer_hosted"], var.environment)
    error_message = "environment must be one of: dev, staging, prod, customer_hosted"
  }
}

variable "location" {
  description = "Primary Azure region (e.g. westeurope, northeurope, eastus2)."
  type        = string
}

variable "secondary_location" {
  description = "Paired region for multi-region deployments (Pro/Enterprise)."
  type        = string
  default     = null
}

variable "subscription_id" {
  description = "Target Azure subscription id."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant id hosting the deployment subscription."
  type        = string
}

variable "owner" {
  description = "Owner tag applied to every resource (team or business unit)."
  type        = string
  default     = "platform"
}

variable "cost_center" {
  description = "Cost-center tag applied to every resource for FinOps attribution."
  type        = string
  default     = "platform"
}

variable "common_tags" {
  description = "Additional tags merged onto every resource."
  type        = map(string)
  default     = {}
}

# TODO(phase-1): add per-module variable groups, e.g.:
#  - network: address_space, subnet_cidrs, allowed_egress_fqdns
#  - data:    sql_sku, cosmos_autoscale_max_ru, storage_replication
#  - compute: container_apps_workload_profile, functions_plan_sku
#  - ai:      openai_deployments[]
#  - apim:    sku_name, capacity
#  - frontdoor: sku, waf_mode
