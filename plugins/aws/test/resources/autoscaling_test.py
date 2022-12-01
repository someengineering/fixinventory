from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from test.resources import round_trip_for
from typing import cast, Any
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_autoscaling_groups() -> None:
    round_trip_for(AwsAutoScalingGroup)


def test_tagging() -> None:
    asg, _ = round_trip_for(AwsAutoScalingGroup)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "create-or-update-tags"
        assert kwargs["Tags"] == [
            {
                "ResourceId": asg.name,
                "ResourceType": "auto-scaling-group",
                "Key": "foo",
                "Value": "bar",
                "PropagateAtLaunch": False,
            }
        ]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-tags"
        assert kwargs["Tags"] == [
            {
                "ResourceId": asg.name,
                "ResourceType": "auto-scaling-group",
                "Key": "foo",
            }
        ]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    asg.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    asg.delete_resource_tag(client, "foo")


def test_deletion() -> None:
    asg, _ = round_trip_for(AwsAutoScalingGroup)

    def validate_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-auto-scaling-group"
        assert kwargs["AutoScalingGroupName"] == asg.name
        assert kwargs["ForceDelete"] is True

    client = cast(AwsClient, SimpleNamespace(call=validate_args))

    asg.delete_resource(client)
