from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.resource.elasticbeanstalk import AwsBeanstalkApplication
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for


def test_applications() -> None:
    first, builder = round_trip_for(AwsBeanstalkApplication)
    assert len(builder.resources_of(AwsBeanstalkApplication)) == 3


def test_tagging() -> None:
    app, _ = round_trip_for(AwsBeanstalkApplication)

    def validate_update_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "list-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            assert kwargs["Tagging"] == {"TagSet": [{"Key": "foo", "Value": "bar"}]}

    def validate_delete_args(**kwargs: Any) -> Any:
        if kwargs["action"] == "list-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            return [{"Key": "foo", "Value": "bar"}]

        if kwargs["action"] == "update-tags-for-resource":
            assert kwargs["ResourceArn"] == app.arn
            assert kwargs["Tagging"] == {"TagSet": []}

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
