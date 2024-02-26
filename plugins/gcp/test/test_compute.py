import json
import os
from fix_plugin_gcp.resources.compute import *
from fix_plugin_gcp.resources.billing import GcpSku
from .random_client import roundtrip, connect_resource, FixturedClient
from fix_plugin_gcp.resources.base import GraphBuilder, GcpRegion


def test_gcp_accelerator_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpAcceleratorType, random_builder)


def test_gcp_address(random_builder: GraphBuilder) -> None:
    address = roundtrip(GcpAddress, random_builder)
    connect_resource(random_builder, address, GcpSubnetwork, selfLink=address.subnetwork)
    assert len(random_builder.edges_of(GcpSubnetwork, GcpAddress)) == 1


def test_gcp_autoscaler(random_builder: GraphBuilder) -> None:
    autoscaler = roundtrip(GcpAutoscaler, random_builder)
    connect_resource(random_builder, autoscaler, GcpInstanceGroupManager, selfLink=autoscaler.autoscaler_target)
    assert len(random_builder.edges_of(GcpAutoscaler, GcpInstanceGroupManager)) == 1


def test_gcp_backend_bucket(random_builder: GraphBuilder) -> None:
    roundtrip(GcpBackendBucket, random_builder)


def test_gcp_backend_service(random_builder: GraphBuilder) -> None:
    service = roundtrip(GcpBackendService, random_builder)
    assert service.health_checks
    assert service.backend_service_backends
    connect_resource(random_builder, service, GcpHealthCheck, selfLink=service.health_checks[0])
    assert len(random_builder.edges_of(GcpBackendService, GcpHealthCheck)) == 1
    connect_resource(random_builder, service, GcpInstanceGroup, selfLink=service.backend_service_backends[0].group)
    assert len(random_builder.edges_of(GcpBackendService, GcpInstanceGroup)) == 1
    connect_resource(random_builder, service, GcpNetwork, selfLink=service.network)
    assert len(random_builder.edges_of(GcpNetwork, GcpBackendService)) == 1


def test_gcp_disk_type(random_builder: GraphBuilder) -> None:
    roundtrip(GcpDiskType, random_builder)


def test_disk_type_ondemand_cost(random_builder: GraphBuilder) -> None:
    known_prices_per_gig = [
        ("pd-standard", "us-east1", 0.08),
    ]
    with open(os.path.dirname(__file__) + "/files/skus.json") as f:
        for r in GcpSku.collect(raw=json.load(f)["skus"], builder=random_builder):
            r.post_process_instance(random_builder, {})

    with open(os.path.dirname(__file__) + "/files/disk_type.json") as f:
        for r in GcpDiskType.collect(raw=json.load(f)["items"]["diskTypes"], builder=random_builder):
            r.post_process_instance(random_builder, {})

    regions = random_builder.resources_of(GcpRegion)
    disk_types = random_builder.resources_of(GcpDiskType)

    for price in known_prices_per_gig:
        region = next((obj for obj in regions if obj.id == price[1]), None)
        disk_type = next((obj for obj in disk_types if obj.name == price[0]), None)
        assert disk_type
        disk_type._region = region
        disk_type.connect_in_graph(random_builder, {"Dummy": "Source"})
        assert disk_type.ondemand_cost is not None
        assert disk_type.ondemand_cost > 0.0
        assert round(disk_type.ondemand_cost, 5) == price[2]


def test_gcp_disk(random_builder: GraphBuilder) -> None:
    disk = roundtrip(GcpDisk, random_builder)
    connect_resource(random_builder, disk, GcpDiskType, selfLink=disk.volume_type)
    assert len(random_builder.edges_of(GcpDiskType, GcpDisk)) == 1


def test_gcp_external_vpn_gateway(random_builder: GraphBuilder) -> None:
    roundtrip(GcpExternalVpnGateway, random_builder)


def test_gcp_firewall_policy(random_builder: GraphBuilder) -> None:
    policy = roundtrip(GcpFirewallPolicy, random_builder)
    assert policy.firewall_policy_rules
    assert policy.firewall_policy_rules[0].target_resources
    connect_resource(random_builder, policy, GcpNetwork, selfLink=policy.firewall_policy_rules[0].target_resources[0])
    assert len(random_builder.edges_of(GcpFirewallPolicy, GcpNetwork)) == 1


def test_gcp_firewall(random_builder: GraphBuilder) -> None:
    firewall = roundtrip(GcpFirewall, random_builder)
    connect_resource(random_builder, firewall, GcpNetwork, selfLink=firewall.network)
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
    gcp_instance = roundtrip(GcpInstance, random_builder)
    connect_resource(random_builder, gcp_instance, GcpMachineType, selfLink=gcp_instance.machine_type)
    assert len(random_builder.edges_of(GcpMachineType, GcpInstance)) == 1


def test_gcp_instance_custom_machine_type(random_builder: GraphBuilder) -> None:
    CUSTOM_MACHINE_TYPE_PART = "/zones/us-east1-b/machineTypes/e2-custom-medium-1024"
    CUSTOM_MACHINE_TYPE_FULL = (
        f"https://www.googleapis.com/compute/v1/projects/{random_builder.project.id}/{CUSTOM_MACHINE_TYPE_PART}"
    )
    fixture_replies = {
        "Instance": {"machineType": lambda: CUSTOM_MACHINE_TYPE_PART},
        "MachineType": {"selfLink": lambda: CUSTOM_MACHINE_TYPE_FULL},
    }
    assert len(random_builder.resources_of(GcpMachineType)) == 0

    with FixturedClient(random_builder, fixture_replies) as random_builder:
        res: List[GcpInstance] = GcpInstance.collect_resources(random_builder)  # type: ignore
        random_builder.executor.wait_for_submitted_work()
        for node, data in random_builder.graph.nodes(data=True):
            node.connect_in_graph(random_builder, data.get("source") or {})
        first_instance: GcpInstance = res[0]

    assert len(random_builder.resources_of(GcpMachineType)) == 1
    only_machine_type = random_builder.resources_of(GcpMachineType)[0]
    assert first_instance.instance_cores == only_machine_type.instance_cores
    assert first_instance.instance_memory == only_machine_type.instance_memory
    assert only_machine_type._zone
    assert only_machine_type._region


def test_machine_type_ondemand_cost(random_builder: GraphBuilder) -> None:
    # Cross-checking with pricing calculated on https://gcpinstances.doit-intl.com/
    known_prices_linux_ondemand_hourly = [
        ("n2d-standard-8", "us-east1", 0.33797),
        ("f1-micro", "us-east1", 0.00760),
        ("m1-ultramem-160", "us-east1", 25.17240),
        ("a2-megagpu-16g", "us-east1", 8.79698),
        ("c2d-highcpu-112", "europe-west3", 5.40826),
        ("m2-ultramem-416", "us-east1", 74.5344),
        ("m3-megamem-64", "europe-west3", 9.28266),
        ("t2d-standard-16", "europe-west3", 0.87083),
        # TODO complete test cases (c3 missing)
    ]
    with open(os.path.dirname(__file__) + "/files/skus.json") as f:
        GcpSku.collect(raw=json.load(f)["skus"], builder=random_builder)

    with open(os.path.dirname(__file__) + "/files/machine_type.json") as f:
        GcpMachineType.collect(raw=json.load(f)["items"]["machineTypes"], builder=random_builder)

    regions = random_builder.resources_of(GcpRegion)
    machine_types = random_builder.resources_of(GcpMachineType)

    for price in known_prices_linux_ondemand_hourly:
        region = next((obj for obj in regions if obj.id == price[1]), None)
        machine_type = next((obj for obj in machine_types if obj.name == price[0]), None)
        assert machine_type
        machine_type._region = region
        machine_type.post_process_instance(random_builder, {"Dummy": "Source"})
        assert machine_type.ondemand_cost
        assert round(machine_type.ondemand_cost, 5) == price[2]


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
