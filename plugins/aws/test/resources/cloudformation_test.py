from resoto_plugin_aws.resource.cloudformation import (
    AwsCloudFormationStack,
    AwsCloudFormationStackSet,
    AwsCloudFormationStackInstanceSummary,
)
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from functools import partial


def test_cloud_formation_stacks() -> None:
    round_trip_for(AwsCloudFormationStack)


def test_cloud_formation_stack_sets() -> None:
    stack_set, builder = round_trip_for(AwsCloudFormationStackSet)

    # stack sets
    assert len(builder.resources_of(AwsCloudFormationStackSet)) == 1
    # stack set instance summaries
    assert len(builder.resources_of(AwsCloudFormationStackInstanceSummary)) == 2

    # deferred edges to stack set instances
    assert len(builder.graph.deferred_edges) == 2


def test_cloud_formation_stack_tagging() -> None:
    cf, _ = round_trip_for(AwsCloudFormationStack)

    tag = "alpha.eksctl.io/nodegroup-name"

    def validate_args(delete: bool, **kwargs: Any) -> Any:

        assert kwargs["action"] in {"describe-stacks", "update-stack"}
        if kwargs["action"] == "describe-stacks":
            assert kwargs["StackName"] == cf.name
            return [{"StackStatus": "complete"}]
        if kwargs["action"] == "update-stack":
            tags = cf.tags
            if delete:
                del tags[tag]
            else:
                tags.update({"foo": "bar"})
            assert kwargs["StackName"] == cf.name
            assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
            assert kwargs["UsePreviousTemplate"] is True
            assert kwargs["Tags"] == [{"Key": label, "Value": value} for label, value in tags.items()]
            assert kwargs["Parameters"] == [
                {"ParameterKey": parameter, "UsePreviousValue": True} for parameter in cf.stack_parameters.keys()
            ]

    fn = partial(validate_args, delete=False)
    client = cast(AwsClient, SimpleNamespace(list=fn, call=fn))
    cf.update_resource_tag(client, "foo", "bar")

    fn = partial(validate_args, delete=True)
    client = cast(AwsClient, SimpleNamespace(list=fn, call=fn))
    cf.delete_resource_tag(client, tag)


def test_cloud_formation_stack_delete() -> None:
    cf, _ = round_trip_for(AwsCloudFormationStack)

    def validate_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-stack"
        assert kwargs["StackName"] == cf.name

    client = cast(AwsClient, SimpleNamespace(call=partial(validate_args)))
    cf.delete_resource(client)


def test_cloud_formation_stack_set_tagging() -> None:
    cf, _ = round_trip_for(AwsCloudFormationStackSet)
    cf.tags["bar"] = "bar"

    def validate_args(delete: bool, **kwargs: Any) -> None:

        assert kwargs["action"] == "update-stack-set"
        tags = cf.tags
        if delete:
            del tags["bar"]
        else:
            tags.update({"foo": "bar"})
        assert kwargs["StackSetName"] == cf.name
        assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
        assert kwargs["UsePreviousTemplate"] is True
        assert kwargs["Tags"] == [{"Key": label, "Value": value} for label, value in tags.items()]
        assert kwargs["Parameters"] == [
            {"ParameterKey": parameter, "UsePreviousValue": True}
            for parameter in (cf.stack_set_parameters or {}).keys()
        ]

    client = cast(AwsClient, SimpleNamespace(call=partial(validate_args, delete=False)))
    cf.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=partial(validate_args, delete=True)))
    cf.delete_resource_tag(client, "bar")


def test_cloud_formation_stack_set_delete() -> None:
    cf, _ = round_trip_for(AwsCloudFormationStackSet)

    def validate_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-stack-set"
        assert kwargs["StackSetName"] == cf.name

    client = cast(AwsClient, SimpleNamespace(call=partial(validate_args)))
    cf.delete_resource(client)
