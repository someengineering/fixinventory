from resoto_plugin_aws.resource.elbv2 import AwsAlb, AwsAlbTargetGroup
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_albs() -> None:
    first, graph = round_trip_for(AwsAlb)
    assert len(first.alb_listener) == 2
    assert len(first.tags) == 4


def test_alb_deletion() -> None:
    alb, _ = round_trip_for(AwsAlb)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-load-balancer"
        assert kwargs["LoadBalancerArn"] == alb.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    alb.delete_resource(client)


def test_alb_target_group_deletion() -> None:
    alb, _ = round_trip_for(AwsAlbTargetGroup)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-target-group"
        assert kwargs["TargetGroupArn"] == alb.arn

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    alb.delete_resource(client)


def test_alb_target_groups() -> None:
    first, graph = round_trip_for(AwsAlbTargetGroup)
    assert len(first.tags) == 4


def test_tagging() -> None:
    elb, _ = round_trip_for(AwsAlb)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "add-tags"
        assert kwargs["ResourceArns"] == [elb.arn]
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "remove-tags"
        assert kwargs["ResourceArns"] == [elb.arn]
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    elb.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    elb.delete_resource_tag(client, "foo")
