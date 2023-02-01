from resoto_plugin_gcp.resources.compute import *
from .random_client import roundtrip, connect_resource


def test_gcp_accelerator_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpAcceleratorType, random_builder)


def test_gcp_address(random_builder: GraphBuilder) -> None:
    address = roundtrip(GcpAddress, random_builder)
    connect_resource(random_builder, address, GcpSubnetwork, selfLink=address.address_subnetwork)
    assert len(random_builder.edges_of(GcpSubnetwork, GcpAddress)) == 1


def test_gcp_autoscaler(random_builder: GraphBuilder) -> None:
    autoscaler = roundtrip(GcpAutoscaler, random_builder)
    connect_resource(random_builder, autoscaler, GcpInstanceGroupManager, selfLink=autoscaler.autoscaler_target)
    assert len(random_builder.edges_of(GcpAutoscaler, GcpInstanceGroupManager)) == 1


def test_gcp_backend_bucket(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBackendBucket, random_builder)


def test_gcp_backend_service(random_builder: GraphBuilder) -> None:
    service = roundtrip(GcpBackendService, random_builder)
    connect_resource(random_builder, service, GcpHealthCheck, selfLink=service.service_health_checks[0])
    assert len(random_builder.edges_of(GcpBackendService, GcpHealthCheck)) == 1
    connect_resource(random_builder, service, GcpInstanceGroup, selfLink=service.service_backends[0].group)
    assert len(random_builder.edges_of(GcpBackendService, GcpInstanceGroup)) == 1
    connect_resource(random_builder, service, GcpNetwork, selfLink=service.service_network)
    assert len(random_builder.edges_of(GcpNetwork, GcpBackendService)) == 1


def test_gcp_disk_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpDiskType, random_builder)


def test_gcp_disk(random_builder: GraphBuilder) -> None:
    disk = roundtrip(GcpDisk, random_builder)
    connect_resource(random_builder, disk, GcpDiskType, selfLink=disk.volume_type)
    assert len(random_builder.edges_of(GcpDiskType, GcpDisk)) == 1


def test_gcp_external_vpn_gateway(random_builder: GraphBuilder) -> None:
    roundtrip(GcpExternalVpnGateway, random_builder)


def test_gcp_firewall_policy(random_builder: GraphBuilder) -> None:
    policy = roundtrip(GcpFirewallPolicy, random_builder)
    connect_resource(random_builder, policy, GcpNetwork, selfLink=policy.policy_rules[0].target_resources[0])
    assert len(random_builder.edges_of(GcpFirewallPolicy, GcpNetwork)) == 1


def test_gcp_firewall(random_builder: GraphBuilder) -> None:
    firewall = roundtrip(GcpFirewall, random_builder)
    connect_resource(random_builder, firewall, GcpNetwork, selfLink=firewall.firewall_network)
    assert len(random_builder.edges_of(GcpFirewall, GcpNetwork)) == 1


def test_gcp_forwarding_rule(random_builder: GraphBuilder) -> None:
    roundtrip(GcpForwardingRule, random_builder)


def test_gcp_network_endpoint_group(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNetworkEndpointGroup, random_builder)


def test_gcp_operation(random_builder: GraphBuilder) -> None:
    roundtrip(GcpOperation, random_builder)


def test_gcp_public_delegated_prefix(random_builder: GraphBuilder) -> None:
    roundtrip(GcpPublicDelegatedPrefix, random_builder)


def test_gcp_health_check(random_builder: GraphBuilder) -> None:
    roundtrip(GcpHealthCheck, random_builder)


def test_gcp_http_health_check(random_builder: GraphBuilder) -> None:
    roundtrip(GcpHttpHealthCheck, random_builder)


def test_gcp_https_health_check(random_builder: GraphBuilder) -> None:
    roundtrip(GcpHttpsHealthCheck, random_builder)


def test_gcp_image(random_builder: GraphBuilder) -> None:
    roundtrip(GcpImage, random_builder)


def test_gcp_instance_group_manager(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInstanceGroupManager, random_builder)


def test_gcp_instance_group(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInstanceGroup, random_builder)


def test_gcp_instance_template(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInstanceTemplate, random_builder)


def test_gcp_instance(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInstance, random_builder)


def test_gcp_interconnect_attachment(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInterconnectAttachment, random_builder)


def test_gcp_interconnect_location(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInterconnectLocation, random_builder)


def test_gcp_interconnect(random_builder: GraphBuilder) -> None:
    roundtrip(GcpInterconnect, random_builder)


def test_gcp_license(random_builder: GraphBuilder) -> None:
    roundtrip(GcpLicense, random_builder)


def test_gcp_machine_image(random_builder: GraphBuilder) -> None:
    roundtrip(GcpMachineImage, random_builder)


def test_gcp_machine_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpMachineType, random_builder)


def test_gcp_network_edge_security_service(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNetworkEdgeSecurityService, random_builder)


def test_gcp_network(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNetwork, random_builder)


def test_gcp_node_group(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNodeGroup, random_builder)


def test_gcp_node_template(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNodeTemplate, random_builder)


def test_gcp_node_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNodeType, random_builder)


def test_gcp_packet_mirroring(random_builder: GraphBuilder) -> None:
    roundtrip(GcpPacketMirroring, random_builder)


def test_gcp_public_advertised_prefix(random_builder: GraphBuilder) -> None:
    roundtrip(GcpPublicAdvertisedPrefix, random_builder)


def test_gcp_commitment(random_builder: GraphBuilder) -> None:
    roundtrip(GcpCommitment, random_builder)


def test_gcp_health_check_service(random_builder: GraphBuilder) -> None:
    roundtrip(GcpHealthCheckService, random_builder)


def test_gcp_notification_endpoint(random_builder: GraphBuilder) -> None:
    roundtrip(GcpNotificationEndpoint, random_builder)


def test_gcp_security_policy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSecurityPolicy, random_builder)


def test_gcp_ssl_certificate(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSslCertificate, random_builder)


def test_gcp_ssl_policy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSslPolicy, random_builder)


def test_gcp_target_http_proxy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetHttpProxy, random_builder)


def test_gcp_target_https_proxy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetHttpsProxy, random_builder)


def test_gcp_target_tcp_proxy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetTcpProxy, random_builder)


def test_gcp_url_map(random_builder: GraphBuilder) -> None:
    roundtrip(GcpUrlMap, random_builder)


def test_gcp_resource_policy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpResourcePolicy, random_builder)


def test_gcp_router(random_builder: GraphBuilder) -> None:
    roundtrip(GcpRouter, random_builder)


def test_gcp_route(random_builder: GraphBuilder) -> None:
    roundtrip(GcpRoute, random_builder)


def test_gcp_service_attachment(random_builder: GraphBuilder) -> None:
    roundtrip(GcpServiceAttachment, random_builder)


def test_gcp_snapshot(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSnapshot, random_builder)


def test_gcp_subnetwork(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSubnetwork, random_builder)


def test_gcp_target_grpc_proxy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetGrpcProxy, random_builder)


def test_gcp_target_instance(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetInstance, random_builder)


def test_gcp_target_pool(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetPool, random_builder)


def test_gcp_target_ssl_proxy(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetSslProxy, random_builder)


def test_gcp_target_vpn_gateway(random_builder: GraphBuilder) -> None:
    roundtrip(GcpTargetVpnGateway, random_builder)


def test_gcp_vpn_gateway(random_builder: GraphBuilder) -> None:
    roundtrip(GcpVpnGateway, random_builder)


def test_gcp_vpn_tunnel(random_builder: GraphBuilder) -> None:
    roundtrip(GcpVpnTunnel, random_builder)
