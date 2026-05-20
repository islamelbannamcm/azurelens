###############################################################################
# AzureLens — Networking (placeholder shape for Private Endpoints)
#
# Phase 9 ships:
#   * a VNet shell (/22),
#   * a delegated subnet for Container Apps,
#   * a subnet reserved for Private Endpoints,
#   * an empty NSG bound to the Container Apps subnet.
#
# The hub VNet, Azure Firewall, Private DNS Resolver, and Private DNS
# zones (privatelink.*) arrive in Phase 1 as a shared "hub" RG. See
# docs/AZURE_SERVICES.md § 3.3 and docs/SECURITY_MODEL.md § 7.
#
# Address space is intentionally narrow; production environments allocate
# from the customer's RFC-1918 IPAM.
###############################################################################

resource "azurerm_virtual_network" "platform" {
  name                = local.vnet_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.42.0.0/22"]

  tags = local.common_tags
}

resource "azurerm_subnet" "container_apps" {
  name                 = "snet-container-apps"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.platform.name
  address_prefixes     = ["10.42.0.0/23"]

  delegation {
    name = "Microsoft.App/environments"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-pe"
  resource_group_name               = azurerm_resource_group.main.name
  virtual_network_name              = azurerm_virtual_network.platform.name
  address_prefixes                  = ["10.42.2.0/24"]
  private_endpoint_network_policies = "Enabled"
}

resource "azurerm_network_security_group" "container_apps" {
  name                = "nsg-snet-container-apps"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "container_apps" {
  subnet_id                 = azurerm_subnet.container_apps.id
  network_security_group_id = azurerm_network_security_group.container_apps.id
}

# TODO(phase-1):
#   * Hub VNet + Azure Firewall Premium + Private DNS Resolver in a shared hub RG.
#   * Private Endpoints for SQL / Cosmos / Storage / KV / Service Bus /
#     AI Search / OpenAI / ACR / App Configuration.
#   * Private DNS zones (privatelink.vaultcore.azure.net,
#     privatelink.blob.core.windows.net, etc.) with VNet links.
#   * Front Door Premium → APIM Internal via Private Link.
#   * Azure DDoS Protection Standard on the hub VNet.
#   * Route table sending egress through the hub firewall (deny-by-default).
