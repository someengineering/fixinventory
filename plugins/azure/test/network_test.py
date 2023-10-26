from conftest import roundtrip_check
from resoto_plugin_azure.resource.base import GraphBuilder
from resoto_plugin_azure.resource.network import *


def test_azure_application_gateway_available_waf_rule_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureApplicationGatewayFirewallRuleSet, builder)
    assert len(collected) == 1


def test_azure_application_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureApplicationGateway, builder)
    assert len(collected) == 1


def test_azure_application_gateway_web_application_firewall_policy(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebApplicationFirewallPolicy, builder)
    assert len(collected) == 1


def test_azure_auto_approved_private_link_service(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAutoApprovedPrivateLinkService, builder)
    assert len(collected) == 3


def test_azure_available_service_alias(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAvailableServiceAlias, builder)
    assert len(collected) == 2


def test_azure_azure_firewall_fqdn_tag(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFirewallFqdnTag, builder)
    assert len(collected) == 1


def test_azure_azure_firewall(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFirewall, builder)
    assert len(collected) == 1


def test_azure_azure_web_category(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebCategory, builder)
    assert len(collected) == 1


def test_azure_bastion_host(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureBastionHost, builder)
    assert len(collected) == 2


def test_azure_custom_ip_prefix(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCustomIpPrefix, builder)
    assert len(collected) == 12


def test_azure_ddos_protection_plan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDdosProtectionPlan, builder)
    assert len(collected) == 2


def test_azure_dscp_configuration(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDscpConfiguration, builder)
    assert len(collected) == 2


def test_azure_express_route_circuit(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureExpressRouteCircuit, builder)
    assert len(collected) == 2


def test_azure_express_route_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureExpressRouteGateway, builder)
    assert len(collected) == 1


def test_azure_express_route_port(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureExpressRoutePort, builder)
    assert len(collected) == 1


def test_azure_express_route_port_location(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureExpressRoutePortsLocation, builder)
    assert len(collected) == 1


def test_azure_firewall_policy(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureFirewallPolicy, builder)
    assert len(collected) == 1


def test_azure_ip_allocation(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureIpAllocation, builder)
    assert len(collected) == 2


def test_azure_ip_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureIpGroup, builder)
    assert len(collected) == 2


def test_azure_load_balancer(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureLoadBalancer, builder)
    assert len(collected) == 2


def test_azure_network_profile(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkProfile, builder)
    assert len(collected) == 2


def test_azure_network_virtual_appliance(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualAppliance, builder)
    assert len(collected) == 1


def test_azure_network_virtual_appliance_sku(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualApplianceSku, builder)
    assert len(collected) == 1


def test_azure_network_watcher(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkWatcher, builder)
    assert len(collected) == 2


def test_azure_p2s_vpn_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureP2SVpnGateway, builder)
    assert len(collected) == 2


def test_azure_public_ip_prefix(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzurePublicIPPrefix, builder)
    assert len(collected) == 3


def test_azure_route_filter(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureRouteFilter, builder)
    assert len(collected) == 1


def test_azure_security_partner_provider(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureSecurityPartnerProvider, builder)
    assert len(collected) == 1


def test_azure_usage(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureUsage, builder)
    assert len(collected) == 25


def test_azure_virtual_hub(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualHub, builder)
    assert len(collected) == 2


def test_azure_virtual_network(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualNetwork, builder)
    assert len(collected) == 2


def test_azure_virtual_router(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualRouter, builder)
    assert len(collected) == 1


def test_azure_virtual_wan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVirtualWAN, builder)
    assert len(collected) == 2


def test_azure_vpn_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVpnGateway, builder)
    assert len(collected) == 2


def test_azure_vpn_server_configuration(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVpnServerConfiguration, builder)
    assert len(collected) == 2


def test_azure_vpn_site(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureVpnSite, builder)
    assert len(collected) == 2
