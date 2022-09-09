from collections import defaultdict
from types import SimpleNamespace
from typing import Any, Dict, cast
from resoto_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for
from resoto_plugin_aws.resource.apigateway import AwsApiGatewayRestApi, AwsApiGatewayDomainName


def test_rest_apis() -> None:
    api, builder = round_trip_for(AwsApiGatewayRestApi)
    assert len(builder.resources_of(AwsApiGatewayRestApi)) == 1
    assert len(api.tags) == 1
    assert api.arn == "arn:aws:apigateway:eu-central-1::/restapis/2lsd9i45ub"
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_api_gateway_deployment"] == 2
    assert type_count["aws_api_gateway_stage"] == 1
    assert type_count["aws_api_gateway_authorizer"] == 1
    assert type_count["aws_api_gateway_resource"] == 1


def test_api_tagging() -> None:
    api, builder = round_trip_for(AwsApiGatewayRestApi)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["resourceArn"] == api.arn
        assert kwargs["tags"] == {"foo": "bar"}

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["resourceArn"] == api.arn
        assert kwargs["tagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    api.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    api.delete_resource_tag(client, "foo")


def test_delete_api() -> None:
    api, _ = round_trip_for(AwsApiGatewayRestApi)

    def validate_delete_args(**kwargs: Any) -> Any:
        assert kwargs["action"] == "delete-rest-api"
        assert kwargs["restApiId"] == api.id

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    api.delete_resource(client)


def test_domain_names() -> None:
    api, builder = round_trip_for(AwsApiGatewayDomainName)
    assert len(builder.resources_of(AwsApiGatewayDomainName)) == 1
    assert len(api.tags) == 1
