from test.resources import round_trip_for
from resoto_plugin_aws.resource.sagemaker import (
    AwsSagemakerNotebook,
    AwsSagemakerAlgorithm,
    AwsSagemakerApp,
    AwsSagemakerModel,
    AwsSagemakerDomain,
    AwsSagemakerExperiment,
    AwsSagemakerTrial,
    AwsSagemakerCodeRepository,
    AwsSagemakerEndpoint,
    AwsSagemakerImage,
    AwsSagemakerArtifact,
)


def test_notebooks() -> None:
    first, builder = round_trip_for(AwsSagemakerNotebook)
    assert len(builder.resources_of(AwsSagemakerNotebook)) == 1
    # assert len(first.tags) == 1


def test_algorithms() -> None:
    first, builder = round_trip_for(AwsSagemakerAlgorithm)
    assert len(builder.resources_of(AwsSagemakerAlgorithm)) == 1


def test_apps() -> None:
    first, builder = round_trip_for(AwsSagemakerApp)
    assert len(builder.resources_of(AwsSagemakerApp)) == 1
    assert first.arn


def test_models() -> None:
    first, builder = round_trip_for(AwsSagemakerModel)
    assert len(builder.resources_of(AwsSagemakerModel)) == 1


def test_domains() -> None:
    first, builder = round_trip_for(AwsSagemakerDomain)
    assert len(builder.resources_of(AwsSagemakerDomain)) == 1


def test_experiments() -> None:
    first, builder = round_trip_for(AwsSagemakerExperiment)
    assert len(builder.resources_of(AwsSagemakerExperiment)) == 1


def test_trials() -> None:
    first, builder = round_trip_for(AwsSagemakerTrial)
    assert len(builder.resources_of(AwsSagemakerTrial)) == 1


def test_repos() -> None:
    first, builder = round_trip_for(AwsSagemakerCodeRepository)
    assert len(builder.resources_of(AwsSagemakerCodeRepository)) == 1


def test_endpoint() -> None:
    first, builder = round_trip_for(AwsSagemakerEndpoint)
    assert len(builder.resources_of(AwsSagemakerEndpoint)) == 1


def test_image() -> None:
    first, builder = round_trip_for(AwsSagemakerImage)
    assert len(builder.resources_of(AwsSagemakerImage)) == 1


def test_artifact() -> None:
    first, builder = round_trip_for(AwsSagemakerArtifact)
    assert len(builder.resources_of(AwsSagemakerArtifact)) == 1
