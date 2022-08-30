from test.resources import round_trip_for
from resoto_plugin_aws.resource.apigateway import AwsApiGatewayRestApi

def test_data_catalogs() -> None:
    api, builder = round_trip_for(AwsApiGatewayRestApi)
    assert len(builder.resources_of(AwsApiGatewayRestApi)) == 1
    assert len(api.tags) == 1
    assert api.name == "call-me-api"

# def test_data_catalogs_tagging() -> None:
#     res, builder = round_trip_for(AwsAthenaDataCatalog)

#     def validate_update_args(**kwargs: Any) -> None:
#         assert kwargs["action"] == "tag_resource"
#         assert kwargs["ResourceARN"] == res.arn
#         assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

#     def validate_delete_args(**kwargs: Any) -> None:
#         assert kwargs["action"] == "untag_resource"
#         assert kwargs["ResourceARN"] == res.arn
#         assert kwargs["TagKeys"] == ["foo"]

#     client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
#     res.update_resource_tag(client, "foo", "bar")

#     client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
#     res.delete_resource_tag(client, "foo")


# def test_delete_tables() -> None:
#     table, _ = round_trip_for(AwsDynamoDbTable)

#     def validate_delete_args(**kwargs: Any) -> Any:
#         assert kwargs["action"] == "delete-table"
#         assert kwargs["TableName"] == table.name

#     client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
#     table.delete_resource(client)