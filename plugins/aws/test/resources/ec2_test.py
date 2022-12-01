from types import SimpleNamespace
from typing import cast, Any
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.ec2 import (
    AwsEc2Instance,
    AwsEc2KeyPair,
    AwsEc2Volume,
    AwsEc2NetworkAcl,
    AwsEc2InstanceType,
    AwsEc2ReservedInstances,
    AwsEc2ElasticIp,
    AwsEc2NetworkInterface,
    AwsEc2Vpc,
    AwsEc2Subnet,
    AwsEc2SecurityGroup,
    AwsEc2NatGateway,
    AwsEc2InternetGateway,
    AwsEc2Snapshot,
    AwsEc2VpcPeeringConnection,
    AwsEc2VpcEndpoint,
    AwsEc2RouteTable,
    AwsEc2Host,
)
from test.resources import round_trip_for, build_graph, check_single_node


def test_instance_types() -> None:
    builder = build_graph(AwsEc2InstanceType)
    for it in builder.global_instance_types.values():
        it.connect_in_graph(builder, {})
        check_single_node(it)


def test_reserved_instances() -> None:
    round_trip_for(AwsEc2ReservedInstances)


def test_volumes() -> None:
    round_trip_for(AwsEc2Volume)


def test_delete_volumes() -> None:
    volume, _ = round_trip_for(AwsEc2Volume)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_volume"
        assert kwargs["VolumeId"] == volume.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    volume.delete_resource(client)


def test_snapshots() -> None:
    round_trip_for(AwsEc2Snapshot)


def test_delete_shapshot() -> None:
    snapshot, _ = round_trip_for(AwsEc2Snapshot)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-snapshot"
        assert kwargs["SnapshotId"] == snapshot.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    snapshot.delete_resource(client)


def test_keypair() -> None:
    round_trip_for(AwsEc2KeyPair)


def test_delete_keypair() -> None:
    keypair, _ = round_trip_for(AwsEc2KeyPair)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-key-pair"
        assert kwargs["KeyPairId"] == keypair.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    keypair.delete_resource(client)


def test_instance() -> None:
    round_trip_for(AwsEc2Instance)


def test_delete_instances() -> None:
    instance, _ = round_trip_for(AwsEc2Instance)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "terminate-instances"
        assert kwargs["InstanceIds"] == [instance.id]
        assert kwargs["DryRun"] is False

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource(client)


def test_network_acl() -> None:
    round_trip_for(AwsEc2NetworkAcl)


def test_delete_network_acl() -> None:
    network_acl, _ = round_trip_for(AwsEc2NetworkAcl)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-network-acl"
        assert kwargs["NetworkAclId"] == network_acl.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    network_acl.delete_resource(client)


def test_elastic_ips() -> None:
    round_trip_for(AwsEc2ElasticIp)


def test_delete_elastic_ips() -> None:
    elastic_ip, _ = round_trip_for(AwsEc2ElasticIp)

    def validate_delete_args(**kwargs: Any) -> None:

        assert kwargs["action"] in {"release-address", "disassociate-address"}
        if kwargs["action"] == "disassociate-address":
            assert kwargs["AssociationId"] == elastic_ip.ip_association_id
        if kwargs["action"] == "release-address":
            assert kwargs["AllocationId"] == elastic_ip.ip_allocation_id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    elastic_ip.delete_resource(client)


def test_network_interfaces() -> None:
    nic, gb = round_trip_for(AwsEc2NetworkInterface)
    assert nic.private_ips == ["1.2.3.4"]
    assert nic.public_ips == ["2.3.4.5"]
    assert nic.mac == "0e:63:e5:c8:bb:be"
    assert nic.v6_ips == ["a::a:a:a:a"]
    assert nic.description == "Primary network interface"


def test_delete_network_interfaces() -> None:
    network_interface, _ = round_trip_for(AwsEc2NetworkInterface)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-network-interface"
        assert kwargs["NetworkInterfaceId"] == network_interface.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    network_interface.delete_resource(client)


def test_vpcs() -> None:
    round_trip_for(AwsEc2Vpc)


def test_delete_vpcs() -> None:
    vpc, _ = round_trip_for(AwsEc2Vpc)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-vpc"
        assert kwargs["VpcId"] == vpc.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vpc.delete_resource(client)


def test_vpc_peering_connections() -> None:
    round_trip_for(AwsEc2VpcPeeringConnection)


def test_delete_vpc_peering_connections() -> None:
    vpc_peering_connection, _ = round_trip_for(AwsEc2VpcPeeringConnection)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-vpc-peering-connection"
        assert kwargs["VpcPeeringConnectionId"] == vpc_peering_connection.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vpc_peering_connection.delete_resource(client)


def test_vpc_endpoints() -> None:
    round_trip_for(AwsEc2VpcEndpoint)


def test_delete_vpc_endpoints() -> None:
    vpc_endpoint, _ = round_trip_for(AwsEc2VpcEndpoint)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-vpc-endpoints"
        assert kwargs["VpcEndpointIds"] == [vpc_endpoint.id]

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vpc_endpoint.delete_resource(client)


def test_subnets() -> None:
    round_trip_for(AwsEc2Subnet)


def test_delete_subnets() -> None:
    subnet, _ = round_trip_for(AwsEc2Subnet)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-subnet"
        assert kwargs["SubnetId"] == subnet.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    subnet.delete_resource(client)


def test_route_table() -> None:
    round_trip_for(AwsEc2RouteTable)


def test_delete_route_table() -> None:
    route_table, _ = round_trip_for(AwsEc2RouteTable)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-route-table"
        assert kwargs["RouteTableId"] == route_table.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    route_table.delete_resource(client)


def test_security_groups() -> None:
    round_trip_for(AwsEc2SecurityGroup)


def test_delete_security_groups() -> None:
    security_group, _ = round_trip_for(AwsEc2SecurityGroup)

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "describe-security-groups":
            return [dict()]

        if kwargs["action"] == "delete-security-group":
            assert kwargs["GroupId"] == security_group.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    security_group.delete_resource(client)


def test_nat_gateways() -> None:
    round_trip_for(AwsEc2NatGateway)


def test_delete_nat_gateways() -> None:
    nat_gateway, _ = round_trip_for(AwsEc2NatGateway)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-nat-gateway"
        assert kwargs["NatGatewayId"] == nat_gateway.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    nat_gateway.delete_resource(client)


def test_internet_gateways() -> None:
    round_trip_for(AwsEc2InternetGateway)


def test_delete_internet_gateways() -> None:
    internet_gateway, _ = round_trip_for(AwsEc2InternetGateway)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-internet-gateway"
        assert kwargs["InternetGatewayId"] == internet_gateway.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    internet_gateway.delete_resource(client)


def test_dedicated_hosts() -> None:
    round_trip_for(AwsEc2Host)


def test_delete_dedicated_hosts() -> None:
    host, _ = round_trip_for(AwsEc2Host)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "release-hosts"
        assert kwargs["HostIds"] == [host.id]

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    host.delete_resource(client)


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsEc2Instance)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "create-tags"
        assert kwargs["Resources"] == [instance.id]
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-tags"
        assert kwargs["Resources"] == [instance.id]
        assert kwargs["Tags"] == [{"Key": "foo"}]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource_tag(client, "foo")
