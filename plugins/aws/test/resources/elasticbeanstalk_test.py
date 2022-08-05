from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.resource.elasticbeanstalk import AwsBeanstalkApplication, AwsBeanstalkEnvironment
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for


def test_applications() -> None:
    first, builder = round_trip_for(AwsBeanstalkApplication)
    assert len(builder.resources_of(AwsBeanstalkApplication)) == 3
    assert len(first.tags) == 2


def test_tagging_apps() -> None:
    app, _ = round_trip_for(AwsBeanstalkApplication)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            assert kwargs["TagsToAdd"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            assert kwargs["TagsToRemove"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    app.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    app.delete_resource_tag(client, "foo")


def test_delete_application() -> None:
    app, _ = round_trip_for(AwsBeanstalkApplication)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-application"
        assert kwargs["ApplicationName"] == app.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    app.delete_resource(client)


def test_environments() -> None:
    first, builder = round_trip_for(AwsBeanstalkEnvironment)
    assert len(builder.resources_of(AwsBeanstalkEnvironment)) == 1
    assert len(first.tags) == 2


def test_tagging_envs() -> None:
    env, _ = round_trip_for(AwsBeanstalkEnvironment)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == env.arn
            assert kwargs["TagsToAdd"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == env.arn
            assert kwargs["TagsToRemove"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    env.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    env.delete_resource_tag(client, "foo")


def test_delete_environment() -> None:
    env, _ = round_trip_for(AwsBeanstalkEnvironment)

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "terminate-environment"
        assert kwargs["EnvironmentName"] == env.name

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    env.delete_resource(client)
