from collections import defaultdict
from typing import Dict, Any, cast
from types import SimpleNamespace

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.route53 import AwsRoute53Zone
from test.resources import round_trip_for


def test_hosted_zone() -> None:
    first, builder = round_trip_for(AwsRoute53Zone)
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_route53_zone"] == 3
    assert type_count["aws_route53_resource_record_set"] == 2
    assert type_count["aws_route53_resource_record"] == 5
    assert len(first.tags) == 1


def test_tagging_zones() -> None:
    zone, _ = round_trip_for(AwsRoute53Zone)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "change-tags-for-resource":
            assert kwargs["ResourceId"] == zone.id
            assert kwargs["AddTags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "change-tags-for-resource":
            assert kwargs["ResourceId"] == zone.id
            assert kwargs["RemoveTagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    zone.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    zone.delete_resource_tag(client, "foo")


def test_delete_zones() -> None:
    zone, _ = round_trip_for(AwsRoute53Zone)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-hosted-zone"
        assert kwargs["Id"] == zone.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    zone.delete_resource(client)
