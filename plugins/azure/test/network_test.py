from conftest import roundtrip_check, connect_resources
from fix_plugin_azure.resource.base import GraphBuilder, MicrosoftResource
from fix_plugin_azure.resource.containerservice import AzureContainerServiceManagedCluster
from fix_plugin_azure.resource.network import *

from typing import List, Type


def test_application_gateway_available_waf_rule_set(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkApplicationGatewayFirewallRuleSet, builder)
    assert len(collected) == 1


def test_application_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkApplicationGateway, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkWebApplicationFirewallPolicy]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkApplicationGateway, AzureNetworkWebApplicationFirewallPolicy)) == 1


def test_application_gateway_web_application_firewall_policy(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkWebApplicationFirewallPolicy, builder)
    assert len(collected) == 1


def test_azure_firewall(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkFirewall, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkFirewallPolicy, AzureNetworkVirtualHub]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkFirewall, AzureNetworkFirewallPolicy)) == 1
    assert len(builder.edges_of(AzureNetworkFirewall, AzureNetworkVirtualHub)) == 1


def test_bastion_host(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkBastionHost, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualNetwork, AzureNetworkPublicIPAddress]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualNetwork, AzureNetworkBastionHost)) == 1
    assert len(builder.edges_of(AzureNetworkBastionHost, AzureNetworkPublicIPAddress)) == 1


def test_custom_ip_prefix(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkCustomIpPrefix, builder)
    assert len(collected) == 12


def test_ddos_protection_plan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkDdosProtectionPlan, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualNetwork, AzureNetworkPublicIPAddress]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkDdosProtectionPlan, AzureNetworkVirtualNetwork)) == 1
    assert len(builder.edges_of(AzureNetworkDdosProtectionPlan, AzureNetworkPublicIPAddress)) == 1


def test_dscp_configuration(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkDscpConfiguration, builder)
    assert len(collected) == 2


def test_express_route_circuit(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkExpressRouteCircuit, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkExpressRoutePort,
        AzureNetworkExpressRoutePortsLocation,
    ]
    roundtrip_check(AzureNetworkExpressRoutePortsLocation, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkExpressRouteCircuit, AzureNetworkExpressRoutePort)) == 1
    assert len(builder.edges_of(AzureNetworkExpressRouteCircuit, AzureNetworkExpressRoutePortsLocation)) == 1


def test_express_route_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkExpressRouteGateway, builder)
    assert len(collected) == 1


def test_express_route_port(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkExpressRoutePort, builder)
    assert len(collected) == 1


def test_express_route_port_location(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkExpressRoutePortsLocation, builder)
    assert len(collected) == 1


def test_firewall_policy(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkFirewallPolicy, builder)
    assert len(collected) == 1


def test_ip_allocation(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkIpAllocation, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualNetwork]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualNetwork, AzureNetworkIpAllocation)) == 1


def test_ip_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkIpGroup, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualNetwork]
    roundtrip_check(AzureNetworkVirtualNetwork, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualNetwork, AzureNetworkIpGroup)) == 1


def test_load_balancer(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkLoadBalancer, builder)
    assert collected[0].lb_type == "Microsoft.Network/loadBalancers"
    assert collected[0].backends == [
        "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
        "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet2",
    ]
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkVirtualNetwork,
        AzureContainerServiceManagedCluster,
        AzureNetworkLoadBalancerProbe,
    ]
    roundtrip_check(AzureNetworkPublicIPAddress, builder)
    connect_resources(builder, resource_types)

    assert collected[0].aks_public_ip_address == "41.85.154.247"
    assert len(builder.edges_of(AzureNetworkVirtualNetwork, AzureNetworkLoadBalancer)) == 1
    assert len(builder.edges_of(AzureContainerServiceManagedCluster, AzureNetworkLoadBalancer)) == 1
    assert len(builder.edges_of(AzureNetworkLoadBalancer, AzureNetworkLoadBalancerProbe)) == 2


def test_network_profile(builder: GraphBuilder) -> None:
    from fix_plugin_azure.resource.compute import AzureComputeVirtualMachine  # pylint: disable=import-outside-toplevel

    collected = roundtrip_check(AzureNetworkProfile, builder)

    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureComputeVirtualMachine]
    roundtrip_check(AzureNetworkInterface, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkProfile, AzureComputeVirtualMachine)) == 1


def test_network_virtual_appliance(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualAppliance, builder)
    assert len(collected) == 1

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualApplianceSku]
    roundtrip_check(AzureNetworkVirtualApplianceSku, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualAppliance, AzureNetworkVirtualApplianceSku)) == 1


def test_network_virtual_appliance_sku(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualApplianceSku, builder)
    assert len(collected) == 1


def test_network_watcher(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkWatcher, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualNetwork]
    roundtrip_check(AzureNetworkVirtualNetwork, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualNetwork, AzureNetworkWatcher)) == 2


def test_p2s_vpn_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkP2SVpnGateway, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualHub]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkP2SVpnGateway, AzureNetworkVirtualHub)) == 2


def test_public_ip_prefix(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkPublicIPPrefix, builder)
    assert len(collected) == 3


def test_route_filter(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkRouteFilter, builder)
    assert len(collected) == 1


def test_security_partner_provider(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkSecurityPartnerProvider, builder)
    assert len(collected) == 1


def test_usage(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkUsage, builder)
    assert len(collected) == 25


def test_virtual_hub(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualHub, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkExpressRouteGateway,
        AzureNetworkVirtualWANVpnGateway,
        AzureNetworkVirtualWAN,
        AzureNetworkPublicIPAddress,
    ]
    roundtrip_check(AzureNetworkInterface, builder)
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkExpressRouteGateway, AzureNetworkVirtualHub)) == 1
    assert len(builder.edges_of(AzureNetworkVirtualWANVpnGateway, AzureNetworkVirtualHub)) == 1
    assert len(builder.edges_of(AzureNetworkVirtualWAN, AzureNetworkVirtualHub)) == 1
    assert len(builder.edges_of(AzureNetworkVirtualHub, AzureNetworkPublicIPAddress)) == 1


def test_virtual_network(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualNetwork, builder)
    assert len(collected) == 2


def test_virtual_router(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualRouter, builder)
    assert len(collected) == 1


def test_virtual_wan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualWAN, builder)
    assert len(collected) == 2


def test_vpn_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualWANVpnGateway, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkVirtualWANVpnConnection,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualWANVpnGateway, AzureNetworkVirtualWANVpnConnection)) == 2


def test_vpn_server_configuration(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVpnServerConfiguration, builder)
    assert len(collected) == 2


def test_vpn_site(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVpnSite, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkVirtualWAN]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualWAN, AzureNetworkVpnSite)) == 1


def test_nat_gateway(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkNatGateway, builder)
    assert len(collected) == 2


def test_network_interface(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkInterface, builder)
    assert len(collected) == 2

    resource_types: List[Type[MicrosoftResource]] = [
        AzureNetworkVirtualNetworkTap,
        AzureNetworkDscpConfiguration,
        AzureNetworkSecurityGroup,
        AzureNetworkPrivateLinkService,
    ]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkVirtualNetworkTap, AzureNetworkInterface)) == 1
    assert len(builder.edges_of(AzureNetworkPrivateLinkService, AzureNetworkInterface)) == 1
    assert len(builder.edges_of(AzureNetworkSecurityGroup, AzureNetworkInterface)) == 1
    assert len(builder.edges_of(AzureNetworkInterface, AzureNetworkDscpConfiguration)) == 1


def test_network_security_group(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkSecurityGroup, builder)
    assert len(collected) == 2


def test_private_link_service(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkPrivateLinkService, builder)
    assert len(collected) == 2


def test_public_ip_address(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkPublicIPAddress, builder)
    assert len(collected) == 3

    resource_types: List[Type[MicrosoftResource]] = [AzureNetworkNatGateway, AzureNetworkPublicIPPrefix]
    connect_resources(builder, resource_types)

    assert len(builder.edges_of(AzureNetworkNatGateway, AzureNetworkPublicIPAddress)) == 1
    assert len(builder.edges_of(AzureNetworkPublicIPPrefix, AzureNetworkPublicIPAddress)) == 1


def test_virtual_network_tap(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureNetworkVirtualNetworkTap, builder)
    assert len(collected) == 2
