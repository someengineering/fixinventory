from test.resources import round_trip_for
from resoto_plugin_aws.resource.sagemaker import (
    AwsSagemakerNotebook,
    AwsSagemakerAlgorithm,
    # AwsSagemakerApp,
    AwsSagemakerModel,
    # AwsSagemakerDomain,
)


def test_notebooks() -> None:
    first, builder = round_trip_for(AwsSagemakerNotebook)
    assert len(builder.resources_of(AwsSagemakerNotebook)) == 1
    # assert len(first.tags) == 1


def test_algorithms() -> None:
    first, builder = round_trip_for(AwsSagemakerAlgorithm)
    assert len(builder.resources_of(AwsSagemakerAlgorithm)) == 1


# def test_apps() -> None:
#     first, builder = round_trip_for(AwsSagemakerApp)
#     assert len(builder.resources_of(AwsSagemakerApp)) == 1
#     assert first.arn


def test_models() -> None:
    first, builder = round_trip_for(AwsSagemakerModel)
    assert len(builder.resources_of(AwsSagemakerModel)) == 1


# def test_domains() -> None:
#     first, builder = round_trip_for(AwsSagemakerDomain)
#     assert len(builder.resources_of(AwsSagemakerDomain)) == 1
