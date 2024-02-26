from types import SimpleNamespace
from typing import Any, cast
from fix_plugin_aws.aws_client import AwsClient
from test.resources import round_trip_for
from fix_plugin_aws.resource.sagemaker import (
    AwsSagemakerNotebook,
    AwsSagemakerAlgorithm,
    AwsSagemakerApp,
    AwsSagemakerModel,
    AwsSagemakerDomain,
    AwsSagemakerExperiment,
    AwsSagemakerTrial,
    AwsSagemakerProject,
    AwsSagemakerCodeRepository,
    AwsSagemakerEndpoint,
    AwsSagemakerImage,
    AwsSagemakerArtifact,
    AwsSagemakerUserProfile,
    AwsSagemakerPipeline,
    AwsSagemakerWorkteam,
    AwsSagemakerAutoMLJob,
    AwsSagemakerCompilationJob,
    AwsSagemakerEdgePackagingJob,
    AwsSagemakerHyperParameterTuningJob,
    AwsSagemakerInferenceRecommendationsJob,
    AwsSagemakerLabelingJob,
    AwsSagemakerProcessingJob,
    AwsSagemakerTrainingJob,
    AwsSagemakerTransformJob,
)


def test_tagging() -> None:
    notebook, builder = round_trip_for(AwsSagemakerNotebook)

    def validate_update_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "add-tags"
        assert kwargs["ResourceArn"] == notebook.arn
        assert kwargs["Tags"] == [{"Key": "foo", "Value": "bar"}]

    def validate_delete_args(**kwargs: Any) -> None:
        assert kwargs["action"] == "delete-tags"
        assert kwargs["ResourceArn"] == notebook.arn
        assert kwargs["TagKeys"] == ["foo"]

    client = cast(AwsClient, SimpleNamespace(call=validate_update_args))
    notebook.update_resource_tag(client, "foo", "bar")

    client = cast(AwsClient, SimpleNamespace(call=validate_delete_args))
    notebook.delete_resource_tag(client, "foo")


def test_notebooks() -> None:
    first, builder = round_trip_for(AwsSagemakerNotebook)
    assert len(builder.resources_of(AwsSagemakerNotebook)) == 1
    assert len(first.tags) == 1


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


def test_projects() -> None:
    first, builder = round_trip_for(AwsSagemakerProject)
    assert len(builder.resources_of(AwsSagemakerProject)) == 1


def test_repos() -> None:
    first, builder = round_trip_for(AwsSagemakerCodeRepository)
    assert len(builder.resources_of(AwsSagemakerCodeRepository)) == 1
    assert first.code_repository_url == "some.url"


def test_endpoint() -> None:
    first, builder = round_trip_for(AwsSagemakerEndpoint)
    assert len(builder.resources_of(AwsSagemakerEndpoint)) == 1


def test_image() -> None:
    first, builder = round_trip_for(AwsSagemakerImage)
    assert len(builder.resources_of(AwsSagemakerImage)) == 1


def test_artifact() -> None:
    first, builder = round_trip_for(AwsSagemakerArtifact)
    assert len(builder.resources_of(AwsSagemakerArtifact)) == 2


def test_user_profile() -> None:
    first, builder = round_trip_for(AwsSagemakerUserProfile)
    assert len(builder.resources_of(AwsSagemakerUserProfile)) == 1


def test_pipeline() -> None:
    first, builder = round_trip_for(AwsSagemakerPipeline)
    assert len(builder.resources_of(AwsSagemakerPipeline)) == 1


def test_workteam() -> None:
    first, builder = round_trip_for(AwsSagemakerWorkteam)
    assert len(builder.resources_of(AwsSagemakerWorkteam)) == 1


def test_auto_ml_job() -> None:
    first, builder = round_trip_for(AwsSagemakerAutoMLJob)
    assert len(builder.resources_of(AwsSagemakerAutoMLJob)) == 1


def test_compilation_job() -> None:
    first, builder = round_trip_for(AwsSagemakerCompilationJob)
    assert len(builder.resources_of(AwsSagemakerCompilationJob)) == 1


def test_edge_packaging_job() -> None:
    first, builder = round_trip_for(AwsSagemakerEdgePackagingJob)
    assert len(builder.resources_of(AwsSagemakerEdgePackagingJob)) == 1


def test_hyper_parameter_tuning_job() -> None:
    first, builder = round_trip_for(AwsSagemakerHyperParameterTuningJob)
    assert len(builder.resources_of(AwsSagemakerHyperParameterTuningJob)) == 1


def test_inference_recommendations_job() -> None:
    first, builder = round_trip_for(AwsSagemakerInferenceRecommendationsJob)
    assert len(builder.resources_of(AwsSagemakerInferenceRecommendationsJob)) == 1


def test_labeling_job() -> None:
    first, builder = round_trip_for(AwsSagemakerLabelingJob)
    assert len(builder.resources_of(AwsSagemakerLabelingJob)) == 1
    assert len(first.tags) == 1


def test_processing_job() -> None:
    first, builder = round_trip_for(AwsSagemakerProcessingJob)
    assert len(builder.resources_of(AwsSagemakerProcessingJob)) == 1


def test_training_job() -> None:
    first, builder = round_trip_for(AwsSagemakerTrainingJob)
    assert len(builder.resources_of(AwsSagemakerTrainingJob)) == 1


def test_transform_job() -> None:
    first, builder = round_trip_for(AwsSagemakerTransformJob)
    assert len(builder.resources_of(AwsSagemakerTransformJob)) == 1
