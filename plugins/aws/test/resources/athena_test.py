from resoto_plugin_aws.resource.athena import AwsAthenaDataCatalog, AwsAthenaWorkGroup
from test.resources import round_trip_for
from typing import Any, cast
from types import SimpleNamespace
from resoto_plugin_aws.aws_client import AwsClient


def test_data_catalogs() -> None:
    res, builder = round_trip_for(AwsAthenaDataCatalog)
    assert len(builder.resources_of(AwsAthenaDataCatalog)) == 1
    assert len(res.tags) == 1
    assert res.arn == "arn:aws:athena:eu-central-1:test:datacatalog/resoto-catalog"


def test_workgroups() -> None:
    res, builder = round_trip_for(AwsAthenaWorkGroup)
    assert len(builder.resources_of(AwsAthenaWorkGroup)) == 1
    assert len(res.tags) == 1
    assert res.arn == "arn:aws:athena:eu-central-1:test:workgroup/resoto-workgroup"


def test_data_catalogs_tagging() -> None:
    res, builder = round_trip_for(AwsAthenaDataCatalog)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["ResourceARN"] == res.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["ResourceARN"] == res.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource_tag(client, "foo")


def test_workgroup_tagging() -> None:
    res, builder = round_trip_for(AwsAthenaWorkGroup)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "tag-resource"
        assert kwargs["ResourceARN"] == res.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "untag-resource"
        assert kwargs["ResourceARN"] == res.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    res.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    res.delete_resource_tag(client, "foo")
