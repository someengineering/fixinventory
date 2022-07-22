from resoto_plugin_aws.resource.elb import AwsElb
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_elbs() -> None:
    first, graph = round_trip_for(AwsElb, "public_ip_address")
    assert len(first.tags) == 2


def test_tagging() -> None:
    elb, _ = round_trip_for(AwsElb, "public_ip_address")

    def validate_update_args(**kwargs: Any):
        assert kwargs["action"] == "add_tags"
        assert kwargs["LoadBalancerNames"] == [elb.name]
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any):
        assert kwargs["action"] == "remove_tags"
        assert kwargs["LoadBalancerNames"] == [elb.name]
        assert kwargs["Tags"] == [{"Key": "foo"}]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    elb.update_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    elb.delete_tag(client, "foo")
