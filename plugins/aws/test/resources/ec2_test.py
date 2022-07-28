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
        assert kwargs["action"] == "delete_snapshot"
        assert kwargs["SnapshotId"] == snapshot.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    snapshot.delete_resource(client)


def test_keypair() -> None:
    round_trip_for(AwsEc2KeyPair)


def test_delete_keypair() -> None:
    keypair, _ = round_trip_for(AwsEc2KeyPair)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_key_pair"
        assert kwargs["KeyPairId"] == keypair.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    keypair.delete_resource(client)


def test_instance() -> None:
    round_trip_for(AwsEc2Instance)


def test_delete_instances() -> None:
    instance, _ = round_trip_for(AwsEc2Instance)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "terminate_instances"
        assert kwargs["InstanceIds"] == [instance.id]
        assert kwargs["DryRun"] is False

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource(client)


def test_network_acl() -> None:
    round_trip_for(AwsEc2NetworkAcl)


def test_delete_network_acl() -> None:
    network_acl, _ = round_trip_for(AwsEc2NetworkAcl)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_network_acl"
        assert kwargs["NetworkAclId"] == network_acl.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    network_acl.delete_resource(client)


def test_elastic_ips() -> None:
    round_trip_for(AwsEc2ElasticIp)


def test_delete_elastic_ips() -> None:
    elastic_ip, _ = round_trip_for(AwsEc2ElasticIp)

    def validate_delete_args(**kwargs: Any) -> None:

        assert kwargs["action"] in {"release_address", "disassociate_address"}
        if kwargs["action"] == "disassociate_address":
            assert kwargs["AssociationId"] == elastic_ip.ip_association_id
        if kwargs["action"] == "release_address":
            assert kwargs["AllocationId"] == elastic_ip.ip_allocation_id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    elastic_ip.delete_resource(client)


def test_network_interfaces() -> None:
    round_trip_for(AwsEc2NetworkInterface)


def test_delete_network_interfaces() -> None:
    network_interface, _ = round_trip_for(AwsEc2NetworkInterface)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_network_interface"
        assert kwargs["NetworkInterfaceId"] == network_interface.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    network_interface.delete_resource(client)


def test_vpcs() -> None:
    round_trip_for(AwsEc2Vpc)


def test_delete_vpcs() -> None:
    vpc, _ = round_trip_for(AwsEc2Vpc)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_vpc"
        assert kwargs["VpcId"] == vpc.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    vpc.delete_resource(client)


def test_vpc_peering_connections() -> None:
    round_trip_for(AwsEc2VpcPeeringConnection)


def test_vpc_endpoints() -> None:
    round_trip_for(AwsEc2VpcEndpoint)


def test_subnets() -> None:
    round_trip_for(AwsEc2Subnet)


def test_delete_subnets() -> None:
    subnet, _ = round_trip_for(AwsEc2Subnet)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_subnet"
        assert kwargs["SubnetId"] == subnet.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    subnet.delete_resource(client)


def test_route_table() -> None:
    round_trip_for(AwsEc2RouteTable)


def test_security_groups() -> None:
    round_trip_for(AwsEc2SecurityGroup)


def test_nat_gateways() -> None:
    round_trip_for(AwsEc2NatGateway)


def test_internet_gateways() -> None:
    round_trip_for(AwsEc2InternetGateway)


def test_tagging() -> None:
    instance, _ = round_trip_for(AwsEc2Instance)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "create_tags"
        assert kwargs["Resources"] == [instance.id]
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete_tags"
        assert kwargs["Resources"] == [instance.id]
        assert kwargs["Tags"] == [{"Key": "foo"}]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    instance.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    instance.delete_resource_tag(client, "foo")
