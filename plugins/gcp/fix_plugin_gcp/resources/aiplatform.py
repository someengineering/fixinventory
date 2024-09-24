from datetime import datetime
import logging
from typing import ClassVar, Dict, Optional, List, Any, Type, cast

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import (
    GcpErrorHandler,
    GcpExpectedErrorCodes,
    GcpResource,
    GcpDeprecationStatus,
    GraphBuilder,
)
from fixlib.json_bender import Bender, S, Bend, ForallBend, MapDict
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")

# The following list of regions is sourced from the official Google Cloud Vertex AI service endpoints documentation:
# https://cloud.google.com/vertex-ai/docs/reference/rest#service-endpoint
# AI Platform (Vertex AI) resources can only be deployed and managed within these specific regions.

regions = [
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "australia-southeast2",
    "europe-central2",
    "europe-north1",
    "europe-southwest1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "me-west1",
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
]


class AIPlatformRegionFilter:
    @classmethod
    def collect_resources(cls, builder: GraphBuilder, **kwargs: Any) -> List[GcpResource]:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        if issubclass(cls, GcpResource):
            if kwargs:
                log.info(f"[GCP:{builder.project.id}] Collecting {cls.kind} with ({kwargs})")
            else:
                log.info(f"[GCP:{builder.project.id}] Collecting {cls.kind}")
            if spec := cls.api_spec:
                expected_errors = GcpExpectedErrorCodes | (spec.expected_errors or set())
                with GcpErrorHandler(
                    builder.core_feedback, expected_errors, f" in {builder.project.id} kind {cls.kind}"
                ):
                    if builder.region and builder.region.id in regions:
                        items = builder.client.list(spec, **kwargs)
                        collected_resources = cls.collect(items, builder)
                        log.info(f"[GCP:{builder.project.id}] finished collecting: {cls.kind}")
                        return collected_resources
        return []


@define(eq=False, slots=False)
class GcpAIPlatformCompletionStats:
    kind: ClassVar[str] = "gcp_ai_platform_completion_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failed_count": S("failedCount"),
        "incomplete_count": S("incompleteCount"),
        "successful_count": S("successfulCount"),
        "successful_forecast_point_count": S("successfulForecastPointCount"),
    }
    failed_count: Optional[str] = field(default=None)
    incomplete_count: Optional[str] = field(default=None)
    successful_count: Optional[str] = field(default=None)
    successful_forecast_point_count: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformMachineSpec:
    kind: ClassVar[str] = "gcp_ai_platform_machine_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "accelerator_count": S("acceleratorCount"),
        "accelerator_type": S("acceleratorType"),
        "machine_type": S("machineType"),
        "tpu_topology": S("tpuTopology"),
    }
    accelerator_count: Optional[int] = field(default=None)
    accelerator_type: Optional[str] = field(default=None)
    machine_type: Optional[str] = field(default=None)
    tpu_topology: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchDedicatedResources:
    kind: ClassVar[str] = "gcp_ai_platform_batch_dedicated_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "machine_spec": S("machineSpec", default={}) >> Bend(GcpAIPlatformMachineSpec.mapping),
        "max_replica_count": S("maxReplicaCount"),
        "starting_replica_count": S("startingReplicaCount"),
    }
    machine_spec: Optional[GcpAIPlatformMachineSpec] = field(default=None)
    max_replica_count: Optional[int] = field(default=None)
    starting_replica_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpDetails:
    kind: ClassVar[str] = "gcp_details"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpGoogleRpcStatus:
    kind: ClassVar[str] = "gcp_google_rpc_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "details": S("details", default=[]) >> ForallBend(GcpDetails.mapping),
        "message": S("message"),
    }
    code: Optional[int] = field(default=None)
    details: Optional[List[GcpDetails]] = field(default=None)
    message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationMetadataInputMetadataFeatureValueDomain:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_metadata_input_metadata_feature_value_domain"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_value": S("maxValue"),
        "min_value": S("minValue"),
        "original_mean": S("originalMean"),
        "original_stddev": S("originalStddev"),
    }
    max_value: Optional[float] = field(default=None)
    min_value: Optional[float] = field(default=None)
    original_mean: Optional[float] = field(default=None)
    original_stddev: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationMetadataInputMetadataVisualization:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_metadata_input_metadata_visualization"
    mapping: ClassVar[Dict[str, Bender]] = {
        "clip_percent_lowerbound": S("clipPercentLowerbound"),
        "clip_percent_upperbound": S("clipPercentUpperbound"),
        "color_map": S("colorMap"),
        "overlay_type": S("overlayType"),
        "polarity": S("polarity"),
        "type": S("type"),
    }
    clip_percent_lowerbound: Optional[float] = field(default=None)
    clip_percent_upperbound: Optional[float] = field(default=None)
    color_map: Optional[str] = field(default=None)
    overlay_type: Optional[str] = field(default=None)
    polarity: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationMetadataInputMetadata:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_metadata_input_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "dense_shape_tensor_name": S("denseShapeTensorName"),
        "encoded_tensor_name": S("encodedTensorName"),
        "encoding": S("encoding"),
        "feature_value_domain": S("featureValueDomain", default={})
        >> Bend(GcpAIPlatformExplanationMetadataInputMetadataFeatureValueDomain.mapping),
        "group_name": S("groupName"),
        "index_feature_mapping": S("indexFeatureMapping", default=[]),
        "indices_tensor_name": S("indicesTensorName"),
        "input_tensor_name": S("inputTensorName"),
        "modality": S("modality"),
        "visualization": S("visualization", default={})
        >> Bend(GcpAIPlatformExplanationMetadataInputMetadataVisualization.mapping),
    }
    dense_shape_tensor_name: Optional[str] = field(default=None)
    encoded_tensor_name: Optional[str] = field(default=None)
    encoding: Optional[str] = field(default=None)
    feature_value_domain: Optional[GcpAIPlatformExplanationMetadataInputMetadataFeatureValueDomain] = field(
        default=None
    )
    group_name: Optional[str] = field(default=None)
    index_feature_mapping: Optional[List[str]] = field(default=None)
    indices_tensor_name: Optional[str] = field(default=None)
    input_tensor_name: Optional[str] = field(default=None)
    modality: Optional[str] = field(default=None)
    visualization: Optional[GcpAIPlatformExplanationMetadataInputMetadataVisualization] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationMetadataOutputMetadata:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_metadata_output_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "display_name_mapping_key": S("displayNameMappingKey"),
        "index_display_name_mapping": S("indexDisplayNameMapping"),
        "output_tensor_name": S("outputTensorName"),
    }
    display_name_mapping_key: Optional[str] = field(default=None)
    index_display_name_mapping: Optional[Any] = field(default=None)
    output_tensor_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationMetadata:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "feature_attributions_schema_uri": S("featureAttributionsSchemaUri"),
        "inputs": S("inputs", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformExplanationMetadataInputMetadata.mapping)),
        "latent_space_source": S("latentSpaceSource"),
        "outputs": S("outputs", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformExplanationMetadataOutputMetadata.mapping)),
    }
    feature_attributions_schema_uri: Optional[str] = field(default=None)
    inputs: Optional[Dict[str, GcpAIPlatformExplanationMetadataInputMetadata]] = field(default=None)
    latent_space_source: Optional[str] = field(default=None)
    outputs: Optional[Dict[str, GcpAIPlatformExplanationMetadataOutputMetadata]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformGcsSource:
    kind: ClassVar[str] = "gcp_ai_platform_gcs_source"
    mapping: ClassVar[Dict[str, Bender]] = {"uris": S("uris", default=[])}
    uris: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExamplesExampleGcsSource:
    kind: ClassVar[str] = "gcp_ai_platform_examples_example_gcs_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_format": S("dataFormat"),
        "gcs_source": S("gcsSource", default={}) >> Bend(GcpAIPlatformGcsSource.mapping),
    }
    data_format: Optional[str] = field(default=None)
    gcs_source: Optional[GcpAIPlatformGcsSource] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPresets:
    kind: ClassVar[str] = "gcp_ai_platform_presets"
    mapping: ClassVar[Dict[str, Bender]] = {"modality": S("modality"), "query": S("query")}
    modality: Optional[str] = field(default=None)
    query: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExamples:
    kind: ClassVar[str] = "gcp_ai_platform_examples"
    mapping: ClassVar[Dict[str, Bender]] = {
        "example_gcs_source": S("exampleGcsSource", default={}) >> Bend(GcpAIPlatformExamplesExampleGcsSource.mapping),
        "nearest_neighbor_search_config": S("nearestNeighborSearchConfig"),
        "neighbor_count": S("neighborCount"),
        "presets": S("presets", default={}) >> Bend(GcpAIPlatformPresets.mapping),
    }
    example_gcs_source: Optional[GcpAIPlatformExamplesExampleGcsSource] = field(default=None)
    nearest_neighbor_search_config: Optional[Any] = field(default=None)
    neighbor_count: Optional[int] = field(default=None)
    presets: Optional[GcpAIPlatformPresets] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeatureNoiseSigmaNoiseSigmaForFeature:
    kind: ClassVar[str] = "gcp_ai_platform_feature_noise_sigma_noise_sigma_for_feature"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "sigma": S("sigma")}
    name: Optional[str] = field(default=None)
    sigma: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeatureNoiseSigma:
    kind: ClassVar[str] = "gcp_ai_platform_feature_noise_sigma"
    mapping: ClassVar[Dict[str, Bender]] = {
        "noise_sigma": S("noiseSigma", default=[])
        >> ForallBend(GcpAIPlatformFeatureNoiseSigmaNoiseSigmaForFeature.mapping)
    }
    noise_sigma: Optional[List[GcpAIPlatformFeatureNoiseSigmaNoiseSigmaForFeature]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSmoothGradConfig:
    kind: ClassVar[str] = "gcp_ai_platform_smooth_grad_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "feature_noise_sigma": S("featureNoiseSigma", default={}) >> Bend(GcpAIPlatformFeatureNoiseSigma.mapping),
        "noise_sigma": S("noiseSigma"),
        "noisy_sample_count": S("noisySampleCount"),
    }
    feature_noise_sigma: Optional[GcpAIPlatformFeatureNoiseSigma] = field(default=None)
    noise_sigma: Optional[float] = field(default=None)
    noisy_sample_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformIntegratedGradientsAttribution:
    kind: ClassVar[str] = "gcp_ai_platform_integrated_gradients_attribution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blur_baseline_config": S("blurBaselineConfig", "maxBlurSigma"),
        "smooth_grad_config": S("smoothGradConfig", default={}) >> Bend(GcpAIPlatformSmoothGradConfig.mapping),
        "step_count": S("stepCount"),
    }
    blur_baseline_config: Optional[float] = field(default=None)
    smooth_grad_config: Optional[GcpAIPlatformSmoothGradConfig] = field(default=None)
    step_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformXraiAttribution:
    kind: ClassVar[str] = "gcp_ai_platform_xrai_attribution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blur_baseline_config": S("blurBaselineConfig", "maxBlurSigma"),
        "smooth_grad_config": S("smoothGradConfig", default={}) >> Bend(GcpAIPlatformSmoothGradConfig.mapping),
        "step_count": S("stepCount"),
    }
    blur_baseline_config: Optional[float] = field(default=None)
    smooth_grad_config: Optional[GcpAIPlatformSmoothGradConfig] = field(default=None)
    step_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationParameters:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "examples": S("examples", default={}) >> Bend(GcpAIPlatformExamples.mapping),
        "integrated_gradients_attribution": S("integratedGradientsAttribution", default={})
        >> Bend(GcpAIPlatformIntegratedGradientsAttribution.mapping),
        "sampled_shapley_attribution": S("sampledShapleyAttribution", "pathCount"),
        "top_k": S("topK"),
        "xrai_attribution": S("xraiAttribution", default={}) >> Bend(GcpAIPlatformXraiAttribution.mapping),
    }
    examples: Optional[GcpAIPlatformExamples] = field(default=None)
    integrated_gradients_attribution: Optional[GcpAIPlatformIntegratedGradientsAttribution] = field(default=None)
    sampled_shapley_attribution: Optional[int] = field(default=None)
    top_k: Optional[int] = field(default=None)
    xrai_attribution: Optional[GcpAIPlatformXraiAttribution] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExplanationSpec:
    kind: ClassVar[str] = "gcp_ai_platform_explanation_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "metadata": S("metadata", default={}) >> Bend(GcpAIPlatformExplanationMetadata.mapping),
        "parameters": S("parameters", default={}) >> Bend(GcpAIPlatformExplanationParameters.mapping),
    }
    metadata: Optional[GcpAIPlatformExplanationMetadata] = field(default=None)
    parameters: Optional[GcpAIPlatformExplanationParameters] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchPredictionJobInputConfig:
    kind: ClassVar[str] = "gcp_ai_platform_batch_prediction_job_input_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_source": S("bigquerySource", "inputUri"),
        "gcs_source": S("gcsSource", default={}) >> Bend(GcpAIPlatformGcsSource.mapping),
        "instances_format": S("instancesFormat"),
    }
    bigquery_source: Optional[str] = field(default=None)
    gcs_source: Optional[GcpAIPlatformGcsSource] = field(default=None)
    instances_format: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchPredictionJobInstanceConfig:
    kind: ClassVar[str] = "gcp_ai_platform_batch_prediction_job_instance_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "excluded_fields": S("excludedFields", default=[]),
        "included_fields": S("includedFields", default=[]),
        "instance_type": S("instanceType"),
        "key_field": S("keyField"),
    }
    excluded_fields: Optional[List[str]] = field(default=None)
    included_fields: Optional[List[str]] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    key_field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchPredictionJobOutputConfig:
    kind: ClassVar[str] = "gcp_ai_platform_batch_prediction_job_output_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_destination": S("bigqueryDestination", "outputUri"),
        "gcs_destination": S("gcsDestination", "outputUriPrefix"),
        "predictions_format": S("predictionsFormat"),
    }
    bigquery_destination: Optional[str] = field(default=None)
    gcs_destination: Optional[str] = field(default=None)
    predictions_format: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchPredictionJobOutputInfo:
    kind: ClassVar[str] = "gcp_ai_platform_batch_prediction_job_output_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_output_dataset": S("bigqueryOutputDataset"),
        "bigquery_output_table": S("bigqueryOutputTable"),
        "gcs_output_directory": S("gcsOutputDirectory"),
    }
    bigquery_output_dataset: Optional[str] = field(default=None)
    bigquery_output_table: Optional[str] = field(default=None)
    gcs_output_directory: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformEnvVar:
    kind: ClassVar[str] = "gcp_ai_platform_env_var"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "value": S("value")}
    name: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformProbeExecAction:
    kind: ClassVar[str] = "gcp_ai_platform_probe_exec_action"
    mapping: ClassVar[Dict[str, Bender]] = {"command": S("command", default=[])}
    command: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformProbe:
    kind: ClassVar[str] = "gcp_ai_platform_probe"
    mapping: ClassVar[Dict[str, Bender]] = {
        "exec": S("exec", default={}) >> Bend(GcpAIPlatformProbeExecAction.mapping),
        "period_seconds": S("periodSeconds"),
        "timeout_seconds": S("timeoutSeconds"),
    }
    exec: Optional[GcpAIPlatformProbeExecAction] = field(default=None)
    period_seconds: Optional[int] = field(default=None)
    timeout_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelContainerSpec:
    kind: ClassVar[str] = "gcp_ai_platform_model_container_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "command": S("command", default=[]),
        "deployment_timeout": S("deploymentTimeout"),
        "env": S("env", default=[]) >> ForallBend(GcpAIPlatformEnvVar.mapping),
        "grpc_ports": S("grpcPorts", default=[]) >> ForallBend(S("containerPort")),
        "health_probe": S("healthProbe", default={}) >> Bend(GcpAIPlatformProbe.mapping),
        "health_route": S("healthRoute"),
        "image_uri": S("imageUri"),
        "ports": S("ports", default=[]) >> ForallBend(S("containerPort")),
        "predict_route": S("predictRoute"),
        "shared_memory_size_mb": S("sharedMemorySizeMb"),
        "startup_probe": S("startupProbe", default={}) >> Bend(GcpAIPlatformProbe.mapping),
    }
    args: Optional[List[str]] = field(default=None)
    command: Optional[List[str]] = field(default=None)
    deployment_timeout: Optional[str] = field(default=None)
    env: Optional[List[GcpAIPlatformEnvVar]] = field(default=None)
    grpc_ports: Optional[List[int]] = field(default=None)
    health_probe: Optional[GcpAIPlatformProbe] = field(default=None)
    health_route: Optional[str] = field(default=None)
    image_uri: Optional[str] = field(default=None)
    ports: Optional[List[int]] = field(default=None)
    predict_route: Optional[str] = field(default=None)
    shared_memory_size_mb: Optional[str] = field(default=None)
    startup_probe: Optional[GcpAIPlatformProbe] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPredictSchemata:
    kind: ClassVar[str] = "gcp_ai_platform_predict_schemata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_schema_uri": S("instanceSchemaUri"),
        "parameters_schema_uri": S("parametersSchemaUri"),
        "prediction_schema_uri": S("predictionSchemaUri"),
    }
    instance_schema_uri: Optional[str] = field(default=None)
    parameters_schema_uri: Optional[str] = field(default=None)
    prediction_schema_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformUnmanagedContainerModel:
    kind: ClassVar[str] = "gcp_ai_platform_unmanaged_container_model"
    mapping: ClassVar[Dict[str, Bender]] = {
        "artifact_uri": S("artifactUri"),
        "container_spec": S("containerSpec", default={}) >> Bend(GcpAIPlatformModelContainerSpec.mapping),
        "predict_schemata": S("predictSchemata", default={}) >> Bend(GcpAIPlatformPredictSchemata.mapping),
    }
    artifact_uri: Optional[str] = field(default=None)
    container_spec: Optional[GcpAIPlatformModelContainerSpec] = field(default=None)
    predict_schemata: Optional[GcpAIPlatformPredictSchemata] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBatchPredictionJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_batch_prediction_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "batchPredictionJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="batchPredictionJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "completion_stats": S("completionStats", default={}) >> Bend(GcpAIPlatformCompletionStats.mapping),
        "create_time": S("createTime"),
        "dedicated_resources": S("dedicatedResources", default={})
        >> Bend(GcpAIPlatformBatchDedicatedResources.mapping),
        "disable_container_logging": S("disableContainerLogging"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "explanation_spec": S("explanationSpec", default={}) >> Bend(GcpAIPlatformExplanationSpec.mapping),
        "generate_explanation": S("generateExplanation"),
        "input_config": S("inputConfig", default={}) >> Bend(GcpAIPlatformBatchPredictionJobInputConfig.mapping),
        "instance_config": S("instanceConfig", default={})
        >> Bend(GcpAIPlatformBatchPredictionJobInstanceConfig.mapping),
        "manual_batch_tuning_parameters": S("manualBatchTuningParameters", "batchSize"),
        "model": S("model"),
        "model_parameters": S("modelParameters"),
        "model_version_id": S("modelVersionId"),
        "output_config": S("outputConfig", default={}) >> Bend(GcpAIPlatformBatchPredictionJobOutputConfig.mapping),
        "output_info": S("outputInfo", default={}) >> Bend(GcpAIPlatformBatchPredictionJobOutputInfo.mapping),
        "partial_failures": S("partialFailures", default=[]) >> ForallBend(GcpGoogleRpcStatus.mapping),
        "resources_consumed": S("resourcesConsumed", "replicaHours"),
        "service_account": S("serviceAccount"),
        "start_time": S("startTime"),
        "state": S("state"),
        "unmanaged_container_model": S("unmanagedContainerModel", default={})
        >> Bend(GcpAIPlatformUnmanagedContainerModel.mapping),
        "update_time": S("updateTime"),
    }
    completion_stats: Optional[GcpAIPlatformCompletionStats] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    dedicated_resources: Optional[GcpAIPlatformBatchDedicatedResources] = field(default=None)
    disable_container_logging: Optional[bool] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    explanation_spec: Optional[GcpAIPlatformExplanationSpec] = field(default=None)
    generate_explanation: Optional[bool] = field(default=None)
    input_config: Optional[GcpAIPlatformBatchPredictionJobInputConfig] = field(default=None)
    instance_config: Optional[GcpAIPlatformBatchPredictionJobInstanceConfig] = field(default=None)
    manual_batch_tuning_parameters: Optional[int] = field(default=None)
    model: Optional[str] = field(default=None)
    model_parameters: Optional[Any] = field(default=None)
    model_version_id: Optional[str] = field(default=None)
    output_config: Optional[GcpAIPlatformBatchPredictionJobOutputConfig] = field(default=None)
    output_info: Optional[GcpAIPlatformBatchPredictionJobOutputInfo] = field(default=None)
    partial_failures: Optional[List[GcpGoogleRpcStatus]] = field(default=None)
    resources_consumed: Optional[float] = field(default=None)
    service_account: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    unmanaged_container_model: Optional[GcpAIPlatformUnmanagedContainerModel] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformScheduling:
    kind: ClassVar[str] = "gcp_ai_platform_scheduling"
    mapping: ClassVar[Dict[str, Bender]] = {
        "disable_retries": S("disableRetries"),
        "restart_job_on_worker_restart": S("restartJobOnWorkerRestart"),
        "timeout": S("timeout"),
    }
    disable_retries: Optional[bool] = field(default=None)
    restart_job_on_worker_restart: Optional[bool] = field(default=None)
    timeout: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformContainerSpec:
    kind: ClassVar[str] = "gcp_ai_platform_container_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "command": S("command", default=[]),
        "env": S("env", default=[]) >> ForallBend(GcpAIPlatformEnvVar.mapping),
        "image_uri": S("imageUri"),
    }
    args: Optional[List[str]] = field(default=None)
    command: Optional[List[str]] = field(default=None)
    env: Optional[List[GcpAIPlatformEnvVar]] = field(default=None)
    image_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDiskSpec:
    kind: ClassVar[str] = "gcp_ai_platform_disk_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "boot_disk_size_gb": S("bootDiskSizeGb"),
        "boot_disk_type": S("bootDiskType"),
    }
    boot_disk_size_gb: Optional[int] = field(default=None)
    boot_disk_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformNfsMount:
    kind: ClassVar[str] = "gcp_ai_platform_nfs_mount"
    mapping: ClassVar[Dict[str, Bender]] = {"mount_point": S("mountPoint"), "path": S("path"), "server": S("server")}
    mount_point: Optional[str] = field(default=None)
    path: Optional[str] = field(default=None)
    server: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPythonPackageSpec:
    kind: ClassVar[str] = "gcp_ai_platform_python_package_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "args": S("args", default=[]),
        "env": S("env", default=[]) >> ForallBend(GcpAIPlatformEnvVar.mapping),
        "executor_image_uri": S("executorImageUri"),
        "package_uris": S("packageUris", default=[]),
        "python_module": S("pythonModule"),
    }
    args: Optional[List[str]] = field(default=None)
    env: Optional[List[GcpAIPlatformEnvVar]] = field(default=None)
    executor_image_uri: Optional[str] = field(default=None)
    package_uris: Optional[List[str]] = field(default=None)
    python_module: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformWorkerPoolSpec:
    kind: ClassVar[str] = "gcp_ai_platform_worker_pool_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_spec": S("containerSpec", default={}) >> Bend(GcpAIPlatformContainerSpec.mapping),
        "disk_spec": S("diskSpec", default={}) >> Bend(GcpAIPlatformDiskSpec.mapping),
        "machine_spec": S("machineSpec", default={}) >> Bend(GcpAIPlatformMachineSpec.mapping),
        "nfs_mounts": S("nfsMounts", default=[]) >> ForallBend(GcpAIPlatformNfsMount.mapping),
        "python_package_spec": S("pythonPackageSpec", default={}) >> Bend(GcpAIPlatformPythonPackageSpec.mapping),
        "replica_count": S("replicaCount"),
    }
    container_spec: Optional[GcpAIPlatformContainerSpec] = field(default=None)
    disk_spec: Optional[GcpAIPlatformDiskSpec] = field(default=None)
    machine_spec: Optional[GcpAIPlatformMachineSpec] = field(default=None)
    nfs_mounts: Optional[List[GcpAIPlatformNfsMount]] = field(default=None)
    python_package_spec: Optional[GcpAIPlatformPythonPackageSpec] = field(default=None)
    replica_count: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformCustomJobSpec:
    kind: ClassVar[str] = "gcp_ai_platform_custom_job_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "base_output_directory": S("baseOutputDirectory", "outputUriPrefix"),
        "enable_dashboard_access": S("enableDashboardAccess"),
        "enable_web_access": S("enableWebAccess"),
        "experiment": S("experiment"),
        "experiment_run": S("experimentRun"),
        "models": S("models", default=[]),
        "network": S("network"),
        "persistent_resource_id": S("persistentResourceId"),
        "protected_artifact_location_id": S("protectedArtifactLocationId"),
        "reserved_ip_ranges": S("reservedIpRanges", default=[]),
        "scheduling": S("scheduling", default={}) >> Bend(GcpAIPlatformScheduling.mapping),
        "service_account": S("serviceAccount"),
        "tensorboard": S("tensorboard"),
        "worker_pool_specs": S("workerPoolSpecs", default=[]) >> ForallBend(GcpAIPlatformWorkerPoolSpec.mapping),
    }
    base_output_directory: Optional[str] = field(default=None)
    enable_dashboard_access: Optional[bool] = field(default=None)
    enable_web_access: Optional[bool] = field(default=None)
    experiment: Optional[str] = field(default=None)
    experiment_run: Optional[str] = field(default=None)
    models: Optional[List[str]] = field(default=None)
    network: Optional[str] = field(default=None)
    persistent_resource_id: Optional[str] = field(default=None)
    protected_artifact_location_id: Optional[str] = field(default=None)
    reserved_ip_ranges: Optional[List[str]] = field(default=None)
    scheduling: Optional[GcpAIPlatformScheduling] = field(default=None)
    service_account: Optional[str] = field(default=None)
    tensorboard: Optional[str] = field(default=None)
    worker_pool_specs: Optional[List[GcpAIPlatformWorkerPoolSpec]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformCustomJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_custom_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "customJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="customJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "custom_job_spec": S("jobSpec", default={}) >> Bend(GcpAIPlatformCustomJobSpec.mapping),
        "start_time": S("startTime"),
        "state": S("state"),
        "update_time": S("updateTime"),
        "web_access_uris": S("webAccessUris"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    custom_job_spec: Optional[GcpAIPlatformCustomJobSpec] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    web_access_uris: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSavedQuery:
    kind: ClassVar[str] = "gcp_ai_platform_saved_query"
    mapping: ClassVar[Dict[str, Bender]] = {
        "annotation_filter": S("annotationFilter"),
        "annotation_spec_count": S("annotationSpecCount"),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "etag": S("etag"),
        "metadata": S("metadata"),
        "name": S("name"),
        "problem_type": S("problemType"),
        "support_automl_training": S("supportAutomlTraining"),
        "update_time": S("updateTime"),
    }
    annotation_filter: Optional[str] = field(default=None)
    annotation_spec_count: Optional[int] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    problem_type: Optional[str] = field(default=None)
    support_automl_training: Optional[bool] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDataset(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_dataset"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "datasets"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="datasets",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "data_item_count": S("dataItemCount"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "metadata": S("metadata"),
        "metadata_artifact": S("metadataArtifact"),
        "metadata_schema_uri": S("metadataSchemaUri"),
        "model_reference": S("modelReference"),
        "saved_queries": S("savedQueries", default=[]) >> ForallBend(GcpAIPlatformSavedQuery.mapping),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    data_item_count: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    metadata_artifact: Optional[str] = field(default=None)
    metadata_schema_uri: Optional[str] = field(default=None)
    model_reference: Optional[str] = field(default=None)
    saved_queries: Optional[List[GcpAIPlatformSavedQuery]] = field(default=None)
    update_time: Optional[datetime] = field(default=None)

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpAIPlatformDataset and for each:
        # - collect related GcpAIPlatformDatasetVersion
        result: List[GcpResource] = super().collect(raw, builder)  # type: ignore
        dataset_ids = [dataset.id for dataset in cast(List[GcpAIPlatformDataset], result)]
        for dataset_id in dataset_ids:
            builder.submit_work(GcpAIPlatformDatasetVersion.collect_resources, builder, parent=dataset_id)

        return result


@define(eq=False, slots=False)
class GcpAIPlatformDatasetVersion(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_dataset_version"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "datasets", "datasetVersions"],
        action="list",
        request_parameter={"parent": "{parent}"},
        request_parameter_in={"parent"},
        response_path="datasetVersions",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "big_query_dataset_name": S("bigQueryDatasetName"),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "etag": S("etag"),
        "metadata": S("metadata"),
        "model_reference": S("modelReference"),
        "update_time": S("updateTime"),
    }
    big_query_dataset_name: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    model_reference: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformAutomaticResources:
    kind: ClassVar[str] = "gcp_ai_platform_automatic_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_replica_count": S("maxReplicaCount"),
        "min_replica_count": S("minReplicaCount"),
    }
    max_replica_count: Optional[int] = field(default=None)
    min_replica_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPrivateEndpoints:
    kind: ClassVar[str] = "gcp_ai_platform_private_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {
        "explain_http_uri": S("explainHttpUri"),
        "health_http_uri": S("healthHttpUri"),
        "predict_http_uri": S("predictHttpUri"),
        "service_attachment": S("serviceAttachment"),
    }
    explain_http_uri: Optional[str] = field(default=None)
    health_http_uri: Optional[str] = field(default=None)
    predict_http_uri: Optional[str] = field(default=None)
    service_attachment: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformAutoscalingMetricSpec:
    kind: ClassVar[str] = "gcp_ai_platform_autoscaling_metric_spec"
    mapping: ClassVar[Dict[str, Bender]] = {"metric_name": S("metricName"), "target": S("target")}
    metric_name: Optional[str] = field(default=None)
    target: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDedicatedResources:
    kind: ClassVar[str] = "gcp_ai_platform_dedicated_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "autoscaling_metric_specs": S("autoscalingMetricSpecs", default=[])
        >> ForallBend(GcpAIPlatformAutoscalingMetricSpec.mapping),
        "machine_spec": S("machineSpec", default={}) >> Bend(GcpAIPlatformMachineSpec.mapping),
        "max_replica_count": S("maxReplicaCount"),
        "min_replica_count": S("minReplicaCount"),
    }
    autoscaling_metric_specs: Optional[List[GcpAIPlatformAutoscalingMetricSpec]] = field(default=None)
    machine_spec: Optional[GcpAIPlatformMachineSpec] = field(default=None)
    max_replica_count: Optional[int] = field(default=None)
    min_replica_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedModel:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_model"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic_resources": S("automaticResources", default={}) >> Bend(GcpAIPlatformAutomaticResources.mapping),
        "create_time": S("createTime"),
        "dedicated_resources": S("dedicatedResources", default={}) >> Bend(GcpAIPlatformDedicatedResources.mapping),
        "disable_container_logging": S("disableContainerLogging"),
        "disable_explanations": S("disableExplanations"),
        "display_name": S("displayName"),
        "enable_access_logging": S("enableAccessLogging"),
        "explanation_spec": S("explanationSpec", default={}) >> Bend(GcpAIPlatformExplanationSpec.mapping),
        "id": S("id"),
        "model": S("model"),
        "model_version_id": S("modelVersionId"),
        "private_endpoints": S("privateEndpoints", default={}) >> Bend(GcpAIPlatformPrivateEndpoints.mapping),
        "service_account": S("serviceAccount"),
        "shared_resources": S("sharedResources"),
    }
    automatic_resources: Optional[GcpAIPlatformAutomaticResources] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    dedicated_resources: Optional[GcpAIPlatformDedicatedResources] = field(default=None)
    disable_container_logging: Optional[bool] = field(default=None)
    disable_explanations: Optional[bool] = field(default=None)
    display_name: Optional[str] = field(default=None)
    enable_access_logging: Optional[bool] = field(default=None)
    explanation_spec: Optional[GcpAIPlatformExplanationSpec] = field(default=None)
    id: Optional[str] = field(default=None)
    model: Optional[str] = field(default=None)
    model_version_id: Optional[str] = field(default=None)
    private_endpoints: Optional[GcpAIPlatformPrivateEndpoints] = field(default=None)
    service_account: Optional[str] = field(default=None)
    shared_resources: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPredictRequestResponseLoggingConfig:
    kind: ClassVar[str] = "gcp_ai_platform_predict_request_response_logging_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_destination": S("bigqueryDestination", "outputUri"),
        "enabled": S("enabled"),
        "sampling_rate": S("samplingRate"),
    }
    bigquery_destination: Optional[str] = field(default=None)
    enabled: Optional[bool] = field(default=None)
    sampling_rate: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPrivateServiceConnectConfig:
    kind: ClassVar[str] = "gcp_ai_platform_private_service_connect_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_private_service_connect": S("enablePrivateServiceConnect"),
        "project_allowlist": S("projectAllowlist", default=[]),
    }
    enable_private_service_connect: Optional[bool] = field(default=None)
    project_allowlist: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpTrafficsplit:
    kind: ClassVar[str] = "gcp_trafficsplit"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpAIPlatformEndpoint(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_endpoint"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "endpoints"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="endpoints",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "endpoint_deployed_models": S("deployedModels", default=[]) >> ForallBend(GcpAIPlatformDeployedModel.mapping),
        "display_name": S("displayName"),
        "enable_private_service_connect": S("enablePrivateServiceConnect"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "model_deployment_monitoring_job": S("modelDeploymentMonitoringJob"),
        "network": S("network"),
        "predict_request_response_logging_config": S("predictRequestResponseLoggingConfig", default={})
        >> Bend(GcpAIPlatformPredictRequestResponseLoggingConfig.mapping),
        "private_service_connect_config": S("privateServiceConnectConfig", default={})
        >> Bend(GcpAIPlatformPrivateServiceConnectConfig.mapping),
        "traffic_split": S("trafficSplit", default={}) >> Bend(GcpTrafficsplit.mapping),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    endpoint_deployed_models: Optional[List[GcpAIPlatformDeployedModel]] = field(default=None)
    display_name: Optional[str] = field(default=None)
    enable_private_service_connect: Optional[bool] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    model_deployment_monitoring_job: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    predict_request_response_logging_config: Optional[GcpAIPlatformPredictRequestResponseLoggingConfig] = field(
        default=None
    )
    private_service_connect_config: Optional[GcpAIPlatformPrivateServiceConnectConfig] = field(default=None)
    traffic_split: Optional[GcpTrafficsplit] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeatureGroupBigQuery:
    kind: ClassVar[str] = "gcp_google_cloud_aiplatform_v1_feature_group_big_query"
    mapping: ClassVar[Dict[str, Bender]] = {
        "big_query_source": S("bigQuerySource", "inputUri"),
        "entity_id_columns": S("entityIdColumns", default=[]),
    }
    big_query_source: Optional[str] = field(default=None)
    entity_id_columns: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeatureGroup(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_feature_group"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        accessors=["projects", "locations", "featureGroups"],
        service_with_region_prefix=True,
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="featureGroups",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "big_query": S("bigQuery", default={}) >> Bend(GcpAIPlatformFeatureGroupBigQuery.mapping),
        "create_time": S("createTime"),
        "etag": S("etag"),
        "update_time": S("updateTime"),
    }
    big_query: Optional[GcpAIPlatformFeatureGroupBigQuery] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    etag: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpAIPlatformFeatureGroup and for each:
        # - collect related GcpAIPlatformFeature
        result: List[GcpResource] = super().collect(raw, builder)  # type: ignore
        group_ids = [group.id for group in cast(List[GcpAIPlatformFeatureGroup], result)]
        for group_id in group_ids:
            builder.submit_work(GcpAIPlatformFeature.collect_resources, builder, parent=group_id)

        return result


@define(eq=False, slots=False)
class GcpAIPlatformFeatureStatsAnomaly:
    kind: ClassVar[str] = "gcp_ai_platform_feature_stats_anomaly"
    mapping: ClassVar[Dict[str, Bender]] = {
        "anomaly_detection_threshold": S("anomalyDetectionThreshold"),
        "anomaly_uri": S("anomalyUri"),
        "distribution_deviation": S("distributionDeviation"),
        "end_time": S("endTime"),
        "score": S("score"),
        "start_time": S("startTime"),
        "stats_uri": S("statsUri"),
    }
    anomaly_detection_threshold: Optional[float] = field(default=None)
    anomaly_uri: Optional[str] = field(default=None)
    distribution_deviation: Optional[float] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    score: Optional[float] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    stats_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeatureMonitoringStatsAnomaly:
    kind: ClassVar[str] = "gcp_ai_platform_feature_monitoring_stats_anomaly"
    mapping: ClassVar[Dict[str, Bender]] = {
        "feature_stats_anomaly": S("featureStatsAnomaly", default={}) >> Bend(GcpAIPlatformFeatureStatsAnomaly.mapping),
        "objective": S("objective"),
    }
    feature_stats_anomaly: Optional[GcpAIPlatformFeatureStatsAnomaly] = field(default=None)
    objective: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeature(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_feature"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "featureGroups", "features"],
        action="list",
        request_parameter={"parent": "{parent}"},
        request_parameter_in={"parent"},
        response_path="features",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "disable_monitoring": S("disableMonitoring"),
        "etag": S("etag"),
        "monitoring_stats_anomalies": S("monitoringStatsAnomalies", default=[])
        >> ForallBend(GcpAIPlatformFeatureMonitoringStatsAnomaly.mapping),
        "point_of_contact": S("pointOfContact"),
        "update_time": S("updateTime"),
        "value_type": S("valueType"),
        "version_column_name": S("versionColumnName"),
    }
    create_time: Optional[datetime] = field(default=None)
    disable_monitoring: Optional[bool] = field(default=None)
    etag: Optional[str] = field(default=None)
    monitoring_stats_anomalies: Optional[List[GcpAIPlatformFeatureMonitoringStatsAnomaly]] = field(default=None)
    point_of_contact: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    value_type: Optional[str] = field(default=None)
    version_column_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeaturestoreOnlineServingConfigScaling:
    kind: ClassVar[str] = "gcp_ai_platform_featurestore_online_serving_config_scaling"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cpu_utilization_target": S("cpuUtilizationTarget"),
        "max_node_count": S("maxNodeCount"),
        "min_node_count": S("minNodeCount"),
    }
    cpu_utilization_target: Optional[int] = field(default=None)
    max_node_count: Optional[int] = field(default=None)
    min_node_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeaturestoreOnlineServingConfig:
    kind: ClassVar[str] = "gcp_ai_platform_featurestore_online_serving_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "fixed_node_count": S("fixedNodeCount"),
        "scaling": S("scaling", default={}) >> Bend(GcpAIPlatformFeaturestoreOnlineServingConfigScaling.mapping),
    }
    fixed_node_count: Optional[int] = field(default=None)
    scaling: Optional[GcpAIPlatformFeaturestoreOnlineServingConfigScaling] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFeaturestore(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_featurestore"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "featurestores"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="featurestores",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "online_serving_config": S("onlineServingConfig", default={})
        >> Bend(GcpAIPlatformFeaturestoreOnlineServingConfig.mapping),
        "online_storage_ttl_days": S("onlineStorageTtlDays"),
        "state": S("state"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    online_serving_config: Optional[GcpAIPlatformFeaturestoreOnlineServingConfig] = field(default=None)
    online_storage_ttl_days: Optional[int] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecConvexAutomatedStoppingSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_convex_automated_stopping_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "learning_rate_parameter_name": S("learningRateParameterName"),
        "max_step_count": S("maxStepCount"),
        "min_measurement_count": S("minMeasurementCount"),
        "min_step_count": S("minStepCount"),
        "update_all_stopped_trials": S("updateAllStoppedTrials"),
        "use_elapsed_duration": S("useElapsedDuration"),
    }
    learning_rate_parameter_name: Optional[str] = field(default=None)
    max_step_count: Optional[str] = field(default=None)
    min_measurement_count: Optional[str] = field(default=None)
    min_step_count: Optional[str] = field(default=None)
    update_all_stopped_trials: Optional[bool] = field(default=None)
    use_elapsed_duration: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecMetricSpecSafetyMetricConfig:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_metric_spec_safety_metric_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "desired_min_safe_trials_fraction": S("desiredMinSafeTrialsFraction"),
        "safety_threshold": S("safetyThreshold"),
    }
    desired_min_safe_trials_fraction: Optional[float] = field(default=None)
    safety_threshold: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecMetricSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_metric_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "goal": S("goal"),
        "metric_id": S("metricId"),
        "safety_config": S("safetyConfig", default={})
        >> Bend(GcpAIPlatformStudySpecMetricSpecSafetyMetricConfig.mapping),
    }
    goal: Optional[str] = field(default=None)
    metric_id: Optional[str] = field(default=None)
    safety_config: Optional[GcpAIPlatformStudySpecMetricSpecSafetyMetricConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecCategoricalValueSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_categorical_value_spec"
    mapping: ClassVar[Dict[str, Bender]] = {"default_value": S("defaultValue"), "values": S("values", default=[])}
    default_value: Optional[str] = field(default=None)
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecCategoricalValueCondition:
    kind: ClassVar[str] = (
        "gcp_ai_platform_study_spec_parameter_spec_conditional_parameter_spec_categorical_value_condition"
    )
    mapping: ClassVar[Dict[str, Bender]] = {"values": S("values", default=[])}
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecDiscreteValueCondition:
    kind: ClassVar[str] = (
        "gcp_ai_platform_study_spec_parameter_spec_conditional_parameter_spec_discrete_value_condition"
    )
    mapping: ClassVar[Dict[str, Bender]] = {"values": S("values", default=[])}
    values: Optional[List[float]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecIntValueCondition:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_conditional_parameter_spec_int_value_condition"
    mapping: ClassVar[Dict[str, Bender]] = {"values": S("values", default=[])}
    values: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecConditionalParameterSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_conditional_parameter_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "parent_categorical_values": S("parentCategoricalValues", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecCategoricalValueCondition.mapping),
        "parent_discrete_values": S("parentDiscreteValues", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecDiscreteValueCondition.mapping),
        "parent_int_values": S("parentIntValues", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecIntValueCondition.mapping),
    }
    parent_categorical_values: Optional[
        GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecCategoricalValueCondition
    ] = field(default=None)
    parent_discrete_values: Optional[
        GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecDiscreteValueCondition
    ] = field(default=None)
    parent_int_values: Optional[GcpAIPlatformStudySpecParameterSpecConditionalParameterSpecIntValueCondition] = field(
        default=None
    )


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecDiscreteValueSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_discrete_value_spec"
    mapping: ClassVar[Dict[str, Bender]] = {"default_value": S("defaultValue"), "values": S("values", default=[])}
    default_value: Optional[float] = field(default=None)
    values: Optional[List[float]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecDoubleValueSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_double_value_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_value": S("defaultValue"),
        "max_value": S("maxValue"),
        "min_value": S("minValue"),
    }
    default_value: Optional[float] = field(default=None)
    max_value: Optional[float] = field(default=None)
    min_value: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpecIntegerValueSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec_integer_value_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_value": S("defaultValue"),
        "max_value": S("maxValue"),
        "min_value": S("minValue"),
    }
    default_value: Optional[str] = field(default=None)
    max_value: Optional[str] = field(default=None)
    min_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecParameterSpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_parameter_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "categorical_value_spec": S("categoricalValueSpec", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecCategoricalValueSpec.mapping),
        "conditional_parameter_specs": S("conditionalParameterSpecs", default=[])
        >> ForallBend(GcpAIPlatformStudySpecParameterSpecConditionalParameterSpec.mapping),
        "discrete_value_spec": S("discreteValueSpec", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecDiscreteValueSpec.mapping),
        "double_value_spec": S("doubleValueSpec", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecDoubleValueSpec.mapping),
        "integer_value_spec": S("integerValueSpec", default={})
        >> Bend(GcpAIPlatformStudySpecParameterSpecIntegerValueSpec.mapping),
        "parameter_id": S("parameterId"),
        "scale_type": S("scaleType"),
    }
    categorical_value_spec: Optional[GcpAIPlatformStudySpecParameterSpecCategoricalValueSpec] = field(default=None)
    conditional_parameter_specs: Optional[List[GcpAIPlatformStudySpecParameterSpecConditionalParameterSpec]] = field(
        default=None
    )
    discrete_value_spec: Optional[GcpAIPlatformStudySpecParameterSpecDiscreteValueSpec] = field(default=None)
    double_value_spec: Optional[GcpAIPlatformStudySpecParameterSpecDoubleValueSpec] = field(default=None)
    integer_value_spec: Optional[GcpAIPlatformStudySpecParameterSpecIntegerValueSpec] = field(default=None)
    parameter_id: Optional[str] = field(default=None)
    scale_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudyTimeConstraint:
    kind: ClassVar[str] = "gcp_ai_platform_study_time_constraint"
    mapping: ClassVar[Dict[str, Bender]] = {"end_time": S("endTime"), "max_duration": S("maxDuration")}
    end_time: Optional[datetime] = field(default=None)
    max_duration: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpecStudyStoppingConfig:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec_study_stopping_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_duration_no_progress": S("maxDurationNoProgress"),
        "max_num_trials": S("maxNumTrials"),
        "max_num_trials_no_progress": S("maxNumTrialsNoProgress"),
        "maximum_runtime_constraint": S("maximumRuntimeConstraint", default={})
        >> Bend(GcpAIPlatformStudyTimeConstraint.mapping),
        "min_num_trials": S("minNumTrials"),
        "minimum_runtime_constraint": S("minimumRuntimeConstraint", default={})
        >> Bend(GcpAIPlatformStudyTimeConstraint.mapping),
        "should_stop_asap": S("shouldStopAsap"),
    }
    max_duration_no_progress: Optional[str] = field(default=None)
    max_num_trials: Optional[int] = field(default=None)
    max_num_trials_no_progress: Optional[int] = field(default=None)
    maximum_runtime_constraint: Optional[GcpAIPlatformStudyTimeConstraint] = field(default=None)
    min_num_trials: Optional[int] = field(default=None)
    minimum_runtime_constraint: Optional[GcpAIPlatformStudyTimeConstraint] = field(default=None)
    should_stop_asap: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStudySpec:
    kind: ClassVar[str] = "gcp_ai_platform_study_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "algorithm": S("algorithm"),
        "convex_automated_stopping_spec": S("convexAutomatedStoppingSpec", default={})
        >> Bend(GcpAIPlatformStudySpecConvexAutomatedStoppingSpec.mapping),
        "decay_curve_stopping_spec": S("decayCurveStoppingSpec", "useElapsedDuration"),
        "measurement_selection_type": S("measurementSelectionType"),
        "median_automated_stopping_spec": S("medianAutomatedStoppingSpec", "useElapsedDuration"),
        "metrics": S("metrics", default=[]) >> ForallBend(GcpAIPlatformStudySpecMetricSpec.mapping),
        "observation_noise": S("observationNoise"),
        "parameters": S("parameters", default=[]) >> ForallBend(GcpAIPlatformStudySpecParameterSpec.mapping),
        "study_stopping_config": S("studyStoppingConfig", default={})
        >> Bend(GcpAIPlatformStudySpecStudyStoppingConfig.mapping),
    }
    algorithm: Optional[str] = field(default=None)
    convex_automated_stopping_spec: Optional[GcpAIPlatformStudySpecConvexAutomatedStoppingSpec] = field(default=None)
    decay_curve_stopping_spec: Optional[bool] = field(default=None)
    measurement_selection_type: Optional[str] = field(default=None)
    median_automated_stopping_spec: Optional[bool] = field(default=None)
    metrics: Optional[List[GcpAIPlatformStudySpecMetricSpec]] = field(default=None)
    observation_noise: Optional[str] = field(default=None)
    parameters: Optional[List[GcpAIPlatformStudySpecParameterSpec]] = field(default=None)
    study_stopping_config: Optional[GcpAIPlatformStudySpecStudyStoppingConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformMeasurementMetric:
    kind: ClassVar[str] = "gcp_ai_platform_measurement_metric"
    mapping: ClassVar[Dict[str, Bender]] = {"metric_id": S("metricId"), "value": S("value")}
    metric_id: Optional[str] = field(default=None)
    value: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformMeasurement:
    kind: ClassVar[str] = "gcp_ai_platform_measurement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "elapsed_duration": S("elapsedDuration"),
        "metrics": S("metrics", default=[]) >> ForallBend(GcpAIPlatformMeasurementMetric.mapping),
        "step_count": S("stepCount"),
    }
    elapsed_duration: Optional[str] = field(default=None)
    metrics: Optional[List[GcpAIPlatformMeasurementMetric]] = field(default=None)
    step_count: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTrialParameter:
    kind: ClassVar[str] = "gcp_ai_platform_trial_parameter"
    mapping: ClassVar[Dict[str, Bender]] = {"parameter_id": S("parameterId"), "value": S("value")}
    parameter_id: Optional[str] = field(default=None)
    value: Optional[Any] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTrial:
    kind: ClassVar[str] = "gcp_ai_platform_trial"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_id": S("clientId"),
        "custom_job": S("customJob"),
        "end_time": S("endTime"),
        "final_measurement": S("finalMeasurement", default={}) >> Bend(GcpAIPlatformMeasurement.mapping),
        "id": S("id"),
        "infeasible_reason": S("infeasibleReason"),
        "measurements": S("measurements", default=[]) >> ForallBend(GcpAIPlatformMeasurement.mapping),
        "name": S("name"),
        "parameters": S("parameters", default=[]) >> ForallBend(GcpAIPlatformTrialParameter.mapping),
        "start_time": S("startTime"),
        "state": S("state"),
        "web_access_uris": S("webAccessUris"),
    }
    client_id: Optional[str] = field(default=None)
    custom_job: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    final_measurement: Optional[GcpAIPlatformMeasurement] = field(default=None)
    id: Optional[str] = field(default=None)
    infeasible_reason: Optional[str] = field(default=None)
    measurements: Optional[List[GcpAIPlatformMeasurement]] = field(default=None)
    name: Optional[str] = field(default=None)
    parameters: Optional[List[GcpAIPlatformTrialParameter]] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    web_access_uris: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformHyperparameterTuningJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_hyperparameter_tuning_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "hyperparameterTuningJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="hyperparameterTuningJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "max_failed_trial_count": S("maxFailedTrialCount"),
        "max_trial_count": S("maxTrialCount"),
        "parallel_trial_count": S("parallelTrialCount"),
        "start_time": S("startTime"),
        "state": S("state"),
        "study_spec": S("studySpec", default={}) >> Bend(GcpAIPlatformStudySpec.mapping),
        "trial_job_spec": S("trialJobSpec", default={}) >> Bend(GcpAIPlatformCustomJobSpec.mapping),
        "trials": S("trials", default=[]) >> ForallBend(GcpAIPlatformTrial.mapping),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    max_failed_trial_count: Optional[int] = field(default=None)
    max_trial_count: Optional[int] = field(default=None)
    parallel_trial_count: Optional[int] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    study_spec: Optional[GcpAIPlatformStudySpec] = field(default=None)
    trial_job_spec: Optional[GcpAIPlatformCustomJobSpec] = field(default=None)
    trials: Optional[List[GcpAIPlatformTrial]] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedIndexAuthConfigAuthProvider:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_index_auth_config_auth_provider"
    mapping: ClassVar[Dict[str, Bender]] = {
        "allowed_issuers": S("allowedIssuers", default=[]),
        "audiences": S("audiences", default=[]),
    }
    allowed_issuers: Optional[List[str]] = field(default=None)
    audiences: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedIndexAuthConfig:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_index_auth_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auth_provider": S("authProvider", default={}) >> Bend(GcpAIPlatformDeployedIndexAuthConfigAuthProvider.mapping)
    }
    auth_provider: Optional[GcpAIPlatformDeployedIndexAuthConfigAuthProvider] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPscAutomatedEndpoints:
    kind: ClassVar[str] = "gcp_ai_platform_psc_automated_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_address": S("matchAddress"),
        "network": S("network"),
        "project_id": S("projectId"),
    }
    match_address: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    project_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformIndexPrivateEndpoints:
    kind: ClassVar[str] = "gcp_ai_platform_index_private_endpoints"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_grpc_address": S("matchGrpcAddress"),
        "psc_automated_endpoints": S("pscAutomatedEndpoints", default=[])
        >> ForallBend(GcpAIPlatformPscAutomatedEndpoints.mapping),
        "service_attachment": S("serviceAttachment"),
    }
    match_grpc_address: Optional[str] = field(default=None)
    psc_automated_endpoints: Optional[List[GcpAIPlatformPscAutomatedEndpoints]] = field(default=None)
    service_attachment: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedIndex:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_index"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic_resources": S("automaticResources", default={}) >> Bend(GcpAIPlatformAutomaticResources.mapping),
        "create_time": S("createTime"),
        "dedicated_resources": S("dedicatedResources", default={}) >> Bend(GcpAIPlatformDedicatedResources.mapping),
        "deployed_index_auth_config": S("deployedIndexAuthConfig", default={})
        >> Bend(GcpAIPlatformDeployedIndexAuthConfig.mapping),
        "deployment_group": S("deploymentGroup"),
        "display_name": S("displayName"),
        "enable_access_logging": S("enableAccessLogging"),
        "id": S("id"),
        "index": S("index"),
        "index_sync_time": S("indexSyncTime"),
        "private_endpoints": S("privateEndpoints", default={}) >> Bend(GcpAIPlatformIndexPrivateEndpoints.mapping),
        "reserved_ip_ranges": S("reservedIpRanges", default=[]),
    }
    automatic_resources: Optional[GcpAIPlatformAutomaticResources] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    dedicated_resources: Optional[GcpAIPlatformDedicatedResources] = field(default=None)
    deployed_index_auth_config: Optional[GcpAIPlatformDeployedIndexAuthConfig] = field(default=None)
    deployment_group: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    enable_access_logging: Optional[bool] = field(default=None)
    id: Optional[str] = field(default=None)
    index: Optional[str] = field(default=None)
    index_sync_time: Optional[datetime] = field(default=None)
    private_endpoints: Optional[GcpAIPlatformIndexPrivateEndpoints] = field(default=None)
    reserved_ip_ranges: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformIndexEndpoint(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_index_endpoint"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "indexEndpoints"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="indexEndpoints",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "endpoint_deployed_indexes": S("deployedIndexes", default=[]) >> ForallBend(GcpAIPlatformDeployedIndex.mapping),
        "display_name": S("displayName"),
        "enable_private_service_connect": S("enablePrivateServiceConnect"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "network": S("network"),
        "private_service_connect_config": S("privateServiceConnectConfig", default={})
        >> Bend(GcpAIPlatformPrivateServiceConnectConfig.mapping),
        "public_endpoint_domain_name": S("publicEndpointDomainName"),
        "public_endpoint_enabled": S("publicEndpointEnabled"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    endpoint_deployed_indexes: Optional[List[GcpAIPlatformDeployedIndex]] = field(default=None)
    display_name: Optional[str] = field(default=None)
    enable_private_service_connect: Optional[bool] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    network: Optional[str] = field(default=None)
    private_service_connect_config: Optional[GcpAIPlatformPrivateServiceConnectConfig] = field(default=None)
    public_endpoint_domain_name: Optional[str] = field(default=None)
    public_endpoint_enabled: Optional[bool] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedIndexRef:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_index_ref"
    mapping: ClassVar[Dict[str, Bender]] = {
        "deployed_index_id": S("deployedIndexId"),
        "display_name": S("displayName"),
        "index_endpoint": S("indexEndpoint"),
    }
    deployed_index_id: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    index_endpoint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformIndexStats:
    kind: ClassVar[str] = "gcp_ai_platform_index_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "shards_count": S("shardsCount"),
        "sparse_vectors_count": S("sparseVectorsCount"),
        "vectors_count": S("vectorsCount"),
    }
    shards_count: Optional[int] = field(default=None)
    sparse_vectors_count: Optional[str] = field(default=None)
    vectors_count: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformIndex(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_index"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "indexes"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="indexes",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "deployed_indexes": S("deployedIndexes", default=[]) >> ForallBend(GcpAIPlatformDeployedIndexRef.mapping),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "index_stats": S("indexStats", default={}) >> Bend(GcpAIPlatformIndexStats.mapping),
        "index_update_method": S("indexUpdateMethod"),
        "metadata": S("metadata"),
        "metadata_schema_uri": S("metadataSchemaUri"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    deployed_indexes: Optional[List[GcpAIPlatformDeployedIndexRef]] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    index_stats: Optional[GcpAIPlatformIndexStats] = field(default=None)
    index_update_method: Optional[str] = field(default=None)
    metadata_schema_uri: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformArtifact:
    kind: ClassVar[str] = "gcp_ai_platform_artifact"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "metadataStores", "artifacts"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="artifacts",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "etag": S("etag"),
        "schema_title": S("schemaTitle"),
        "schema_version": S("schemaVersion"),
        "state": S("state"),
        "update_time": S("updateTime"),
        "uri": S("uri"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    schema_title: Optional[str] = field(default=None)
    schema_version: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDeploymentMonitoringBigQueryTable:
    kind: ClassVar[str] = "gcp_ai_platform_model_deployment_monitoring_big_query_table"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_table_path": S("bigqueryTablePath"),
        "log_source": S("logSource"),
        "log_type": S("logType"),
        "request_response_logging_schema_version": S("requestResponseLoggingSchemaVersion"),
    }
    bigquery_table_path: Optional[str] = field(default=None)
    log_source: Optional[str] = field(default=None)
    log_type: Optional[str] = field(default=None)
    request_response_logging_schema_version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDeploymentMonitoringJobLatestMonitoringPipelineMetadata:
    kind: ClassVar[str] = "gcp_ai_platform_model_deployment_monitoring_job_latest_monitoring_pipeline_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {
        "run_time": S("runTime"),
        "status": S("status", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
    }
    run_time: Optional[datetime] = field(default=None)
    status: Optional[GcpGoogleRpcStatus] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSamplingStrategy:
    kind: ClassVar[str] = "gcp_ai_platform_sampling_strategy"
    mapping: ClassVar[Dict[str, Bender]] = {"random_sample_config": S("randomSampleConfig", "sampleRate")}
    random_sample_config: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfigExplanationBaseline:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config_explanation_config_explanation_baseline"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery": S("bigquery", "outputUri"),
        "gcs": S("gcs", "outputUriPrefix"),
        "prediction_format": S("predictionFormat"),
    }
    bigquery: Optional[str] = field(default=None)
    gcs: Optional[str] = field(default=None)
    prediction_format: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config_explanation_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_feature_attributes": S("enableFeatureAttributes"),
        "explanation_baseline": S("explanationBaseline", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfigExplanationBaseline.mapping),
    }
    enable_feature_attributes: Optional[bool] = field(default=None)
    explanation_baseline: Optional[GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfigExplanationBaseline] = (
        field(default=None)
    )


@define(eq=False, slots=False)
class GcpAIPlatformThresholdConfig:
    kind: ClassVar[str] = "gcp_ai_platform_threshold_config"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value")}
    value: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfigPredictionDriftDetectionConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config_prediction_drift_detection_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attribution_score_drift_thresholds": S("attributionScoreDriftThresholds", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformThresholdConfig.mapping)),
        "default_drift_threshold": S("defaultDriftThreshold", "value"),
        "drift_thresholds": S("driftThresholds", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformThresholdConfig.mapping)),
    }
    attribution_score_drift_thresholds: Optional[Dict[str, GcpAIPlatformThresholdConfig]] = field(default=None)
    default_drift_threshold: Optional[float] = field(default=None)
    drift_thresholds: Optional[Dict[str, GcpAIPlatformThresholdConfig]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfigTrainingDataset:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config_training_dataset"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bigquery_source": S("bigquerySource", "inputUri"),
        "data_format": S("dataFormat"),
        "dataset": S("dataset"),
        "gcs_source": S("gcsSource", default={}) >> Bend(GcpAIPlatformGcsSource.mapping),
        "logging_sampling_strategy": S("loggingSamplingStrategy", default={})
        >> Bend(GcpAIPlatformSamplingStrategy.mapping),
        "target_field": S("targetField"),
    }
    bigquery_source: Optional[str] = field(default=None)
    data_format: Optional[str] = field(default=None)
    dataset: Optional[str] = field(default=None)
    gcs_source: Optional[GcpAIPlatformGcsSource] = field(default=None)
    logging_sampling_strategy: Optional[GcpAIPlatformSamplingStrategy] = field(default=None)
    target_field: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfigTrainingPredictionSkewDetectionConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config_training_prediction_skew_detection_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "attribution_score_skew_thresholds": S("attributionScoreSkewThresholds", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformThresholdConfig.mapping)),
        "default_skew_threshold": S("defaultSkewThreshold", "value"),
        "skew_thresholds": S("skewThresholds", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformThresholdConfig.mapping)),
    }
    attribution_score_skew_thresholds: Optional[Dict[str, GcpAIPlatformThresholdConfig]] = field(default=None)
    default_skew_threshold: Optional[float] = field(default=None)
    skew_thresholds: Optional[Dict[str, GcpAIPlatformThresholdConfig]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringObjectiveConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_objective_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "explanation_config": S("explanationConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfig.mapping),
        "prediction_drift_detection_config": S("predictionDriftDetectionConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfigPredictionDriftDetectionConfig.mapping),
        "training_dataset": S("trainingDataset", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfigTrainingDataset.mapping),
        "training_prediction_skew_detection_config": S("trainingPredictionSkewDetectionConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfigTrainingPredictionSkewDetectionConfig.mapping),
    }
    explanation_config: Optional[GcpAIPlatformModelMonitoringObjectiveConfigExplanationConfig] = field(default=None)
    prediction_drift_detection_config: Optional[
        GcpAIPlatformModelMonitoringObjectiveConfigPredictionDriftDetectionConfig
    ] = field(default=None)
    training_dataset: Optional[GcpAIPlatformModelMonitoringObjectiveConfigTrainingDataset] = field(default=None)
    training_prediction_skew_detection_config: Optional[
        GcpAIPlatformModelMonitoringObjectiveConfigTrainingPredictionSkewDetectionConfig
    ] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDeploymentMonitoringObjectiveConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_deployment_monitoring_objective_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "deployed_model_id": S("deployedModelId"),
        "objective_config": S("objectiveConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringObjectiveConfig.mapping),
    }
    deployed_model_id: Optional[str] = field(default=None)
    objective_config: Optional[GcpAIPlatformModelMonitoringObjectiveConfig] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDeploymentMonitoringScheduleConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_deployment_monitoring_schedule_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "monitor_interval": S("monitorInterval"),
        "monitor_window": S("monitorWindow"),
    }
    monitor_interval: Optional[str] = field(default=None)
    monitor_window: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringAlertConfigEmailAlertConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_alert_config_email_alert_config"
    mapping: ClassVar[Dict[str, Bender]] = {"user_emails": S("userEmails", default=[])}
    user_emails: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelMonitoringAlertConfig:
    kind: ClassVar[str] = "gcp_ai_platform_model_monitoring_alert_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "email_alert_config": S("emailAlertConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringAlertConfigEmailAlertConfig.mapping),
        "enable_logging": S("enableLogging"),
        "notification_channels": S("notificationChannels", default=[]),
    }
    email_alert_config: Optional[GcpAIPlatformModelMonitoringAlertConfigEmailAlertConfig] = field(default=None)
    enable_logging: Optional[bool] = field(default=None)
    notification_channels: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDeploymentMonitoringJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_model_deployment_monitoring_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "modelDeploymentMonitoringJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="modelDeploymentMonitoringJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "analysis_instance_schema_uri": S("analysisInstanceSchemaUri"),
        "bigquery_tables": S("bigqueryTables", default=[])
        >> ForallBend(GcpAIPlatformModelDeploymentMonitoringBigQueryTable.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "enable_monitoring_pipeline_logs": S("enableMonitoringPipelineLogs"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "endpoint": S("endpoint"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "latest_monitoring_pipeline_metadata": S("latestMonitoringPipelineMetadata", default={})
        >> Bend(GcpAIPlatformModelDeploymentMonitoringJobLatestMonitoringPipelineMetadata.mapping),
        "log_ttl": S("logTtl"),
        "logging_sampling_strategy": S("loggingSamplingStrategy", default={})
        >> Bend(GcpAIPlatformSamplingStrategy.mapping),
        "model_deployment_monitoring_objective_configs": S("modelDeploymentMonitoringObjectiveConfigs", default=[])
        >> ForallBend(GcpAIPlatformModelDeploymentMonitoringObjectiveConfig.mapping),
        "model_deployment_monitoring_schedule_config": S("modelDeploymentMonitoringScheduleConfig", default={})
        >> Bend(GcpAIPlatformModelDeploymentMonitoringScheduleConfig.mapping),
        "model_monitoring_alert_config": S("modelMonitoringAlertConfig", default={})
        >> Bend(GcpAIPlatformModelMonitoringAlertConfig.mapping),
        "next_schedule_time": S("nextScheduleTime"),
        "predict_instance_schema_uri": S("predictInstanceSchemaUri"),
        "sample_predict_instance": S("samplePredictInstance"),
        "schedule_state": S("scheduleState"),
        "state": S("state"),
        "stats_anomalies_base_directory": S("statsAnomaliesBaseDirectory", "outputUriPrefix"),
        "update_time": S("updateTime"),
    }
    analysis_instance_schema_uri: Optional[str] = field(default=None)
    bigquery_tables: Optional[List[GcpAIPlatformModelDeploymentMonitoringBigQueryTable]] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    enable_monitoring_pipeline_logs: Optional[bool] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    endpoint: Optional[str] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    latest_monitoring_pipeline_metadata: Optional[
        GcpAIPlatformModelDeploymentMonitoringJobLatestMonitoringPipelineMetadata
    ] = field(default=None)
    log_ttl: Optional[str] = field(default=None)
    logging_sampling_strategy: Optional[GcpAIPlatformSamplingStrategy] = field(default=None)
    model_deployment_monitoring_objective_configs: Optional[
        List[GcpAIPlatformModelDeploymentMonitoringObjectiveConfig]
    ] = field(default=None)
    model_deployment_monitoring_schedule_config: Optional[GcpAIPlatformModelDeploymentMonitoringScheduleConfig] = field(
        default=None
    )
    model_monitoring_alert_config: Optional[GcpAIPlatformModelMonitoringAlertConfig] = field(default=None)
    next_schedule_time: Optional[datetime] = field(default=None)
    predict_instance_schema_uri: Optional[str] = field(default=None)
    sample_predict_instance: Optional[Any] = field(default=None)
    schedule_state: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    stats_anomalies_base_directory: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelBaseModelSource:
    kind: ClassVar[str] = "gcp_ai_platform_model_base_model_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "genie_source": S("genieSource", "baseModelUri"),
        "model_garden_source": S("modelGardenSource", "publicModelName"),
    }
    genie_source: Optional[str] = field(default=None)
    model_garden_source: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelDataStats:
    kind: ClassVar[str] = "gcp_ai_platform_model_data_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "test_annotations_count": S("testAnnotationsCount"),
        "test_data_items_count": S("testDataItemsCount"),
        "training_annotations_count": S("trainingAnnotationsCount"),
        "training_data_items_count": S("trainingDataItemsCount"),
        "validation_annotations_count": S("validationAnnotationsCount"),
        "validation_data_items_count": S("validationDataItemsCount"),
    }
    test_annotations_count: Optional[str] = field(default=None)
    test_data_items_count: Optional[str] = field(default=None)
    training_annotations_count: Optional[str] = field(default=None)
    training_data_items_count: Optional[str] = field(default=None)
    validation_annotations_count: Optional[str] = field(default=None)
    validation_data_items_count: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformDeployedModelRef:
    kind: ClassVar[str] = "gcp_ai_platform_deployed_model_ref"
    mapping: ClassVar[Dict[str, Bender]] = {"deployed_model_id": S("deployedModelId"), "endpoint": S("endpoint")}
    deployed_model_id: Optional[str] = field(default=None)
    endpoint: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelSourceInfo:
    kind: ClassVar[str] = "gcp_ai_platform_model_source_info"
    mapping: ClassVar[Dict[str, Bender]] = {"copy": S("copy"), "source_type": S("sourceType")}
    copy: Optional[bool] = field(default=None)
    source_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelExportFormat:
    kind: ClassVar[str] = "gcp_ai_platform_model_export_format"
    mapping: ClassVar[Dict[str, Bender]] = {"exportable_contents": S("exportableContents", default=[]), "id": S("id")}
    exportable_contents: Optional[List[str]] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModel(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_model"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "models"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="models",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "artifact_uri": S("artifactUri"),
        "base_model_source": S("baseModelSource", default={}) >> Bend(GcpAIPlatformModelBaseModelSource.mapping),
        "container_spec": S("containerSpec", default={}) >> Bend(GcpAIPlatformModelContainerSpec.mapping),
        "create_time": S("createTime"),
        "data_stats": S("dataStats", default={}) >> Bend(GcpAIPlatformModelDataStats.mapping),
        "endpoint_deployed_model_refs": S("deployedModels", default=[])
        >> ForallBend(GcpAIPlatformDeployedModelRef.mapping),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "explanation_spec": S("explanationSpec", default={}) >> Bend(GcpAIPlatformExplanationSpec.mapping),
        "metadata": S("metadata"),
        "metadata_artifact": S("metadataArtifact"),
        "metadata_schema_uri": S("metadataSchemaUri"),
        "model_source_info": S("modelSourceInfo", default={}) >> Bend(GcpAIPlatformModelSourceInfo.mapping),
        "original_model_info": S("originalModelInfo", "model"),
        "pipeline_job": S("pipelineJob"),
        "predict_schemata": S("predictSchemata", default={}) >> Bend(GcpAIPlatformPredictSchemata.mapping),
        "satisfies_pzi": S("satisfiesPzi"),
        "satisfies_pzs": S("satisfiesPzs"),
        "supported_deployment_resources_types": S("supportedDeploymentResourcesTypes", default=[]),
        "supported_export_formats": S("supportedExportFormats", default=[])
        >> ForallBend(GcpAIPlatformModelExportFormat.mapping),
        "supported_input_storage_formats": S("supportedInputStorageFormats", default=[]),
        "supported_output_storage_formats": S("supportedOutputStorageFormats", default=[]),
        "training_pipeline": S("trainingPipeline"),
        "update_time": S("updateTime"),
        "version_aliases": S("versionAliases", default=[]),
        "version_create_time": S("versionCreateTime"),
        "version_description": S("versionDescription"),
        "version_id": S("versionId"),
        "version_update_time": S("versionUpdateTime"),
    }
    artifact_uri: Optional[str] = field(default=None)
    base_model_source: Optional[GcpAIPlatformModelBaseModelSource] = field(default=None)
    container_spec: Optional[GcpAIPlatformModelContainerSpec] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    data_stats: Optional[GcpAIPlatformModelDataStats] = field(default=None)
    endpoint_deployed_model_refs: Optional[List[GcpAIPlatformDeployedModelRef]] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    explanation_spec: Optional[GcpAIPlatformExplanationSpec] = field(default=None)
    metadata_artifact: Optional[str] = field(default=None)
    metadata_schema_uri: Optional[str] = field(default=None)
    model_source_info: Optional[GcpAIPlatformModelSourceInfo] = field(default=None)
    original_model_info: Optional[str] = field(default=None)
    pipeline_job: Optional[str] = field(default=None)
    predict_schemata: Optional[GcpAIPlatformPredictSchemata] = field(default=None)
    satisfies_pzi: Optional[bool] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    supported_deployment_resources_types: Optional[List[str]] = field(default=None)
    supported_export_formats: Optional[List[GcpAIPlatformModelExportFormat]] = field(default=None)
    supported_input_storage_formats: Optional[List[str]] = field(default=None)
    supported_output_storage_formats: Optional[List[str]] = field(default=None)
    training_pipeline: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    version_aliases: Optional[List[str]] = field(default=None)
    version_create_time: Optional[datetime] = field(default=None)
    version_description: Optional[str] = field(default=None)
    version_id: Optional[str] = field(default=None)
    version_update_time: Optional[datetime] = field(default=None)

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpAIPlatformModel and for each:
        # - collect related GcpAIPlatformModelEvaluation
        result: List[GcpResource] = super().collect(raw, builder)  # type: ignore
        model_ids = [model.id for model in cast(List[GcpAIPlatformModel], result)]
        for model_id in model_ids:
            builder.submit_work(GcpAIPlatformModelEvaluation.collect_resources, builder, parent=model_id)

        return result


@define(eq=False, slots=False)
class GcpAIPlatformModelEvaluationModelEvaluationExplanationSpec:
    kind: ClassVar[str] = "gcp_ai_platform_model_evaluation_model_evaluation_explanation_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "explanation_spec": S("explanationSpec", default={}) >> Bend(GcpAIPlatformExplanationSpec.mapping),
        "explanation_type": S("explanationType"),
    }
    explanation_spec: Optional[GcpAIPlatformExplanationSpec] = field(default=None)
    explanation_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformAttribution:
    kind: ClassVar[str] = "gcp_ai_platform_attribution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "approximation_error": S("approximationError"),
        "baseline_output_value": S("baselineOutputValue"),
        "feature_attributions": S("featureAttributions"),
        "instance_output_value": S("instanceOutputValue"),
        "output_display_name": S("outputDisplayName"),
        "output_index": S("outputIndex", default=[]),
        "output_name": S("outputName"),
    }
    approximation_error: Optional[float] = field(default=None)
    baseline_output_value: Optional[float] = field(default=None)
    feature_attributions: Optional[Any] = field(default=None)
    instance_output_value: Optional[float] = field(default=None)
    output_display_name: Optional[str] = field(default=None)
    output_index: Optional[List[int]] = field(default=None)
    output_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelExplanation:
    kind: ClassVar[str] = "gcp_ai_platform_model_explanation"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mean_attributions": S("meanAttributions", default=[]) >> ForallBend(GcpAIPlatformAttribution.mapping)
    }
    mean_attributions: Optional[List[GcpAIPlatformAttribution]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformModelEvaluation(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_model_evaluation"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "models", "evaluations"],
        action="list",
        request_parameter={"parent": "{parent}"},
        request_parameter_in={"parent"},
        response_path="modelEvaluations",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "annotation_schema_uri": S("annotationSchemaUri"),
        "create_time": S("createTime"),
        "data_item_schema_uri": S("dataItemSchemaUri"),
        "display_name": S("displayName"),
        "explanation_specs": S("explanationSpecs", default=[])
        >> ForallBend(GcpAIPlatformModelEvaluationModelEvaluationExplanationSpec.mapping),
        "metadata": S("metadata"),
        "metrics": S("metrics"),
        "metrics_schema_uri": S("metricsSchemaUri"),
        "model_explanation": S("modelExplanation", default={}) >> Bend(GcpAIPlatformModelExplanation.mapping),
        "slice_dimensions": S("sliceDimensions", default=[]),
    }
    annotation_schema_uri: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    data_item_schema_uri: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    explanation_specs: Optional[List[GcpAIPlatformModelEvaluationModelEvaluationExplanationSpec]] = field(default=None)
    metrics: Optional[Any] = field(default=None)
    metrics_schema_uri: Optional[str] = field(default=None)
    model_explanation: Optional[GcpAIPlatformModelExplanation] = field(default=None)
    slice_dimensions: Optional[List[str]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskExecutorDetailContainerDetail:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_executor_detail_container_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failed_main_jobs": S("failedMainJobs", default=[]),
        "failed_pre_caching_check_jobs": S("failedPreCachingCheckJobs", default=[]),
        "main_job": S("mainJob"),
        "pre_caching_check_job": S("preCachingCheckJob"),
    }
    failed_main_jobs: Optional[List[str]] = field(default=None)
    failed_pre_caching_check_jobs: Optional[List[str]] = field(default=None)
    main_job: Optional[str] = field(default=None)
    pre_caching_check_job: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskExecutorDetailCustomJobDetail:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_executor_detail_custom_job_detail"
    mapping: ClassVar[Dict[str, Bender]] = {"failed_jobs": S("failedJobs", default=[]), "job": S("job")}
    failed_jobs: Optional[List[str]] = field(default=None)
    job: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskExecutorDetail:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_executor_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_detail": S("containerDetail", default={})
        >> Bend(GcpAIPlatformPipelineTaskExecutorDetailContainerDetail.mapping),
        "custom_job_detail": S("customJobDetail", default={})
        >> Bend(GcpAIPlatformPipelineTaskExecutorDetailCustomJobDetail.mapping),
    }
    container_detail: Optional[GcpAIPlatformPipelineTaskExecutorDetailContainerDetail] = field(default=None)
    custom_job_detail: Optional[GcpAIPlatformPipelineTaskExecutorDetailCustomJobDetail] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskDetailArtifactList:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_detail_artifact_list"
    mapping: ClassVar[Dict[str, Bender]] = {
        "artifacts": S("artifacts", default=[]) >> ForallBend(GcpAIPlatformArtifact.mapping)
    }
    artifacts: Optional[List[GcpAIPlatformArtifact]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskDetailPipelineTaskStatus:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_detail_pipeline_task_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "state": S("state"),
        "update_time": S("updateTime"),
    }
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformExecution:
    kind: ClassVar[str] = "gcp_ai_platform_execution"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "metadataStores", "executions"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "location"},
        response_path="executions",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "etag": S("etag"),
        "schema_title": S("schemaTitle"),
        "schema_version": S("schemaVersion"),
        "state": S("state"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    schema_title: Optional[str] = field(default=None)
    schema_version: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineTaskDetail:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_task_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "create_time": S("createTime"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "execution": S("execution", default={}) >> Bend(GcpAIPlatformExecution.mapping),
        "executor_detail": S("executorDetail", default={}) >> Bend(GcpAIPlatformPipelineTaskExecutorDetail.mapping),
        "inputs": S("inputs", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformPipelineTaskDetailArtifactList.mapping)),
        "outputs": S("outputs", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformPipelineTaskDetailArtifactList.mapping)),
        "parent_task_id": S("parentTaskId"),
        "pipeline_task_status": S("pipelineTaskStatus", default=[])
        >> ForallBend(GcpAIPlatformPipelineTaskDetailPipelineTaskStatus.mapping),
        "start_time": S("startTime"),
        "state": S("state"),
        "task_id": S("taskId"),
        "task_name": S("taskName"),
    }
    create_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    execution: Optional[GcpAIPlatformExecution] = field(default=None)
    executor_detail: Optional[GcpAIPlatformPipelineTaskExecutorDetail] = field(default=None)
    inputs: Optional[Dict[str, GcpAIPlatformPipelineTaskDetailArtifactList]] = field(default=None)
    outputs: Optional[Dict[str, GcpAIPlatformPipelineTaskDetailArtifactList]] = field(default=None)
    parent_task_id: Optional[str] = field(default=None)
    pipeline_task_status: Optional[List[GcpAIPlatformPipelineTaskDetailPipelineTaskStatus]] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    task_id: Optional[str] = field(default=None)
    task_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformContext:
    kind: ClassVar[str] = "gcp_ai_platform_context"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "metadataStores", "contexts"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "location"},
        response_path="contexts",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "etag": S("etag"),
        "parent_contexts": S("parentContexts", default=[]),
        "schema_title": S("schemaTitle"),
        "schema_version": S("schemaVersion"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    parent_contexts: Optional[List[str]] = field(default=None)
    schema_title: Optional[str] = field(default=None)
    schema_version: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineJobDetail:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_job_detail"
    mapping: ClassVar[Dict[str, Bender]] = {
        "pipeline_context": S("pipelineContext", default={}) >> Bend(GcpAIPlatformContext.mapping),
        "pipeline_run_context": S("pipelineRunContext", default={}) >> Bend(GcpAIPlatformContext.mapping),
        "task_details": S("taskDetails", default=[]) >> ForallBend(GcpAIPlatformPipelineTaskDetail.mapping),
    }
    pipeline_context: Optional[GcpAIPlatformContext] = field(default=None)
    pipeline_run_context: Optional[GcpAIPlatformContext] = field(default=None)
    task_details: Optional[List[GcpAIPlatformPipelineTaskDetail]] = field(default=None)


@define(eq=False, slots=False)
class GcpPipelinespec:
    kind: ClassVar[str] = "gcp_pipelinespec"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpAIPlatformPipelineJobRuntimeConfigInputArtifact:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_job_runtime_config_input_artifact"
    mapping: ClassVar[Dict[str, Bender]] = {"artifact_id": S("artifactId")}
    artifact_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpParametervalues:
    kind: ClassVar[str] = "gcp_parametervalues"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpAIPlatformValue:
    kind: ClassVar[str] = "gcp_ai_platform_value"
    mapping: ClassVar[Dict[str, Bender]] = {
        "double_value": S("doubleValue"),
        "int_value": S("intValue"),
        "string_value": S("stringValue"),
    }
    double_value: Optional[float] = field(default=None)
    int_value: Optional[str] = field(default=None)
    string_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineJobRuntimeConfig:
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_job_runtime_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "failure_policy": S("failurePolicy"),
        "gcs_output_directory": S("gcsOutputDirectory"),
        "input_artifacts": S("inputArtifacts", default={})
        >> MapDict(value_bender=Bend(GcpAIPlatformPipelineJobRuntimeConfigInputArtifact.mapping)),
        "parameter_values": S("parameterValues", default={}) >> Bend(GcpParametervalues.mapping),
        "parameters": S("parameters", default={}) >> MapDict(value_bender=Bend(GcpAIPlatformValue.mapping)),
    }
    failure_policy: Optional[str] = field(default=None)
    gcs_output_directory: Optional[str] = field(default=None)
    input_artifacts: Optional[Dict[str, GcpAIPlatformPipelineJobRuntimeConfigInputArtifact]] = field(default=None)
    parameter_values: Optional[GcpParametervalues] = field(default=None)
    parameters: Optional[Dict[str, GcpAIPlatformValue]] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPipelineJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_pipeline_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "pipelineJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="pipelineJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "job_detail": S("jobDetail", default={}) >> Bend(GcpAIPlatformPipelineJobDetail.mapping),
        "network": S("network"),
        "pipeline_spec": S("pipelineSpec", default={}) >> Bend(GcpPipelinespec.mapping),
        "preflight_validations": S("preflightValidations"),
        "reserved_ip_ranges": S("reservedIpRanges", default=[]),
        "runtime_config": S("runtimeConfig", default={}) >> Bend(GcpAIPlatformPipelineJobRuntimeConfig.mapping),
        "schedule_name": S("scheduleName"),
        "service_account": S("serviceAccount"),
        "start_time": S("startTime"),
        "state": S("state"),
        "template_metadata": S("templateMetadata", "version"),
        "template_uri": S("templateUri"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    job_detail: Optional[GcpAIPlatformPipelineJobDetail] = field(default=None)
    network: Optional[str] = field(default=None)
    pipeline_spec: Optional[GcpPipelinespec] = field(default=None)
    preflight_validations: Optional[bool] = field(default=None)
    reserved_ip_ranges: Optional[List[str]] = field(default=None)
    runtime_config: Optional[GcpAIPlatformPipelineJobRuntimeConfig] = field(default=None)
    schedule_name: Optional[str] = field(default=None)
    service_account: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    template_metadata: Optional[str] = field(default=None)
    template_uri: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformCreatePipelineJobRequest:
    kind: ClassVar[str] = "gcp_ai_platform_create_pipeline_job_request"
    mapping: ClassVar[Dict[str, Bender]] = {
        "parent": S("parent"),
        "pipeline_job": S("pipelineJob", default={}) >> Bend(GcpAIPlatformPipelineJob.mapping),
        "pipeline_job_id": S("pipelineJobId"),
    }
    parent: Optional[str] = field(default=None)
    pipeline_job: Optional[GcpAIPlatformPipelineJob] = field(default=None)
    pipeline_job_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformScheduleRunResponse:
    kind: ClassVar[str] = "gcp_ai_platform_schedule_run_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "run_response": S("runResponse"),
        "scheduled_run_time": S("scheduledRunTime"),
    }
    run_response: Optional[str] = field(default=None)
    scheduled_run_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSchedule(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_schedule"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "schedules"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="schedules",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "allow_queueing": S("allowQueueing"),
        "catch_up": S("catchUp"),
        "create_pipeline_job_request": S("createPipelineJobRequest", default={})
        >> Bend(GcpAIPlatformCreatePipelineJobRequest.mapping),
        "create_time": S("createTime"),
        "cron": S("cron"),
        "display_name": S("displayName"),
        "end_time": S("endTime"),
        "last_pause_time": S("lastPauseTime"),
        "last_resume_time": S("lastResumeTime"),
        "last_scheduled_run_response": S("lastScheduledRunResponse", default={})
        >> Bend(GcpAIPlatformScheduleRunResponse.mapping),
        "max_concurrent_run_count": S("maxConcurrentRunCount"),
        "max_run_count": S("maxRunCount"),
        "next_run_time": S("nextRunTime"),
        "start_time": S("startTime"),
        "started_run_count": S("startedRunCount"),
        "state": S("state"),
        "update_time": S("updateTime"),
    }
    allow_queueing: Optional[bool] = field(default=None)
    catch_up: Optional[bool] = field(default=None)
    create_pipeline_job_request: Optional[GcpAIPlatformCreatePipelineJobRequest] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    cron: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    last_pause_time: Optional[datetime] = field(default=None)
    last_resume_time: Optional[datetime] = field(default=None)
    last_scheduled_run_response: Optional[GcpAIPlatformScheduleRunResponse] = field(default=None)
    max_concurrent_run_count: Optional[str] = field(default=None)
    max_run_count: Optional[str] = field(default=None)
    next_run_time: Optional[datetime] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    started_run_count: Optional[str] = field(default=None)
    state: Optional[str] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTensorboard(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_tensorboard"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "tensorboards"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="tensorboards",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "blob_storage_path_prefix": S("blobStoragePathPrefix"),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "etag": S("etag"),
        "is_default": S("isDefault"),
        "run_count": S("runCount"),
        "satisfies_pzi": S("satisfiesPzi"),
        "satisfies_pzs": S("satisfiesPzs"),
        "update_time": S("updateTime"),
    }
    blob_storage_path_prefix: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    etag: Optional[str] = field(default=None)
    is_default: Optional[bool] = field(default=None)
    run_count: Optional[int] = field(default=None)
    satisfies_pzi: Optional[bool] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


define(eq=False, slots=False)


class GcpAIPlatformFilterSplit:
    kind: ClassVar[str] = "gcp_ai_platform_filter_split"
    mapping: ClassVar[Dict[str, Bender]] = {
        "test_filter": S("testFilter"),
        "training_filter": S("trainingFilter"),
        "validation_filter": S("validationFilter"),
    }
    test_filter: Optional[str] = field(default=None)
    training_filter: Optional[str] = field(default=None)
    validation_filter: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFractionSplit:
    kind: ClassVar[str] = "gcp_ai_platform_fraction_split"
    mapping: ClassVar[Dict[str, Bender]] = {
        "test_fraction": S("testFraction"),
        "training_fraction": S("trainingFraction"),
        "validation_fraction": S("validationFraction"),
    }
    test_fraction: Optional[float] = field(default=None)
    training_fraction: Optional[float] = field(default=None)
    validation_fraction: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformStratifiedSplit:
    kind: ClassVar[str] = "gcp_ai_platform_stratified_split"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "test_fraction": S("testFraction"),
        "training_fraction": S("trainingFraction"),
        "validation_fraction": S("validationFraction"),
    }
    key: Optional[str] = field(default=None)
    test_fraction: Optional[float] = field(default=None)
    training_fraction: Optional[float] = field(default=None)
    validation_fraction: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTimestampSplit:
    kind: ClassVar[str] = "gcp_ai_platform_timestamp_split"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "test_fraction": S("testFraction"),
        "training_fraction": S("trainingFraction"),
        "validation_fraction": S("validationFraction"),
    }
    key: Optional[str] = field(default=None)
    test_fraction: Optional[float] = field(default=None)
    training_fraction: Optional[float] = field(default=None)
    validation_fraction: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformInputDataConfig:
    kind: ClassVar[str] = "gcp_ai_platform_input_data_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "annotation_schema_uri": S("annotationSchemaUri"),
        "annotations_filter": S("annotationsFilter"),
        "bigquery_destination": S("bigqueryDestination", "outputUri"),
        "dataset_id": S("datasetId"),
        "filter_split": S("filterSplit", default={}) >> Bend(GcpAIPlatformFilterSplit.mapping),
        "fraction_split": S("fractionSplit", default={}) >> Bend(GcpAIPlatformFractionSplit.mapping),
        "gcs_destination": S("gcsDestination", "outputUriPrefix"),
        "persist_ml_use_assignment": S("persistMlUseAssignment"),
        "predefined_split": S("predefinedSplit", "key"),
        "saved_query_id": S("savedQueryId"),
        "stratified_split": S("stratifiedSplit", default={}) >> Bend(GcpAIPlatformStratifiedSplit.mapping),
        "timestamp_split": S("timestampSplit", default={}) >> Bend(GcpAIPlatformTimestampSplit.mapping),
    }
    annotation_schema_uri: Optional[str] = field(default=None)
    annotations_filter: Optional[str] = field(default=None)
    bigquery_destination: Optional[str] = field(default=None)
    dataset_id: Optional[str] = field(default=None)
    filter_split: Optional[GcpAIPlatformFilterSplit] = field(default=None)
    fraction_split: Optional[GcpAIPlatformFractionSplit] = field(default=None)
    gcs_destination: Optional[str] = field(default=None)
    persist_ml_use_assignment: Optional[bool] = field(default=None)
    predefined_split: Optional[str] = field(default=None)
    saved_query_id: Optional[str] = field(default=None)
    stratified_split: Optional[GcpAIPlatformStratifiedSplit] = field(default=None)
    timestamp_split: Optional[GcpAIPlatformTimestampSplit] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTrainingPipeline(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_training_pipeline"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "trainingPipelines"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="trainingPipelines",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "create_time": S("createTime"),
        "display_name": S("displayName"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "input_data_config": S("inputDataConfig", default={}) >> Bend(GcpAIPlatformInputDataConfig.mapping),
        "model_id": S("modelId"),
        "model_to_upload": S("modelToUpload", default={}) >> Bend(GcpAIPlatformModel.mapping),
        "parent_model": S("parentModel"),
        "start_time": S("startTime"),
        "state": S("state"),
        "training_task_definition": S("trainingTaskDefinition"),
        "training_task_inputs": S("trainingTaskInputs"),
        "training_task_metadata": S("trainingTaskMetadata"),
        "update_time": S("updateTime"),
    }
    create_time: Optional[datetime] = field(default=None)
    display_name: Optional[str] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    input_data_config: Optional[GcpAIPlatformInputDataConfig] = field(default=None)
    model_id: Optional[str] = field(default=None)
    model_to_upload: Optional[GcpAIPlatformModel] = field(default=None)
    parent_model: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    training_task_definition: Optional[str] = field(default=None)
    training_task_inputs: Optional[Any] = field(default=None)
    training_task_metadata: Optional[Any] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSupervisedHyperParameters:
    kind: ClassVar[str] = "gcp_ai_platform_supervised_hyper_parameters"
    mapping: ClassVar[Dict[str, Bender]] = {
        "adapter_size": S("adapterSize"),
        "epoch_count": S("epochCount"),
        "learning_rate_multiplier": S("learningRateMultiplier"),
    }
    adapter_size: Optional[str] = field(default=None)
    epoch_count: Optional[str] = field(default=None)
    learning_rate_multiplier: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSupervisedTuningSpec:
    kind: ClassVar[str] = "gcp_ai_platform_supervised_tuning_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "hyper_parameters": S("hyperParameters", default={}) >> Bend(GcpAIPlatformSupervisedHyperParameters.mapping),
        "training_dataset_uri": S("trainingDatasetUri"),
        "validation_dataset_uri": S("validationDatasetUri"),
    }
    hyper_parameters: Optional[GcpAIPlatformSupervisedHyperParameters] = field(default=None)
    training_dataset_uri: Optional[str] = field(default=None)
    validation_dataset_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTunedModel:
    kind: ClassVar[str] = "gcp_ai_platform_tuned_model"
    mapping: ClassVar[Dict[str, Bender]] = {"endpoint": S("endpoint"), "model": S("model")}
    endpoint: Optional[str] = field(default=None)
    model: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFileData:
    kind: ClassVar[str] = "gcp_ai_platform_file_data"
    mapping: ClassVar[Dict[str, Bender]] = {"file_uri": S("fileUri"), "mime_type": S("mimeType")}
    file_uri: Optional[str] = field(default=None)
    mime_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpArgs:
    kind: ClassVar[str] = "gcp_args"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class GcpAIPlatformFunctionCall:
    kind: ClassVar[str] = "gcp_ai_platform_function_call"
    mapping: ClassVar[Dict[str, Bender]] = {"args": S("args", default={}) >> Bend(GcpArgs.mapping), "name": S("name")}
    args: Optional[GcpArgs] = field(default=None)
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformFunctionResponse:
    kind: ClassVar[str] = "gcp_ai_platform_function_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
    }
    name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformBlob:
    kind: ClassVar[str] = "gcp_ai_platform_blob"
    mapping: ClassVar[Dict[str, Bender]] = {"data": S("data"), "mime_type": S("mimeType")}
    data: Optional[str] = field(default=None)
    mime_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformVideoMetadata:
    kind: ClassVar[str] = "gcp_ai_platform_video_metadata"
    mapping: ClassVar[Dict[str, Bender]] = {"end_offset": S("endOffset"), "start_offset": S("startOffset")}
    end_offset: Optional[str] = field(default=None)
    start_offset: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformPart:
    kind: ClassVar[str] = "gcp_ai_platform_part"
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_data": S("fileData", default={}) >> Bend(GcpAIPlatformFileData.mapping),
        "function_call": S("functionCall", default={}) >> Bend(GcpAIPlatformFunctionCall.mapping),
        "function_response": S("functionResponse", default={}) >> Bend(GcpAIPlatformFunctionResponse.mapping),
        "inline_data": S("inlineData", default={}) >> Bend(GcpAIPlatformBlob.mapping),
        "text": S("text"),
        "video_metadata": S("videoMetadata", default={}) >> Bend(GcpAIPlatformVideoMetadata.mapping),
    }
    file_data: Optional[GcpAIPlatformFileData] = field(default=None)
    function_call: Optional[GcpAIPlatformFunctionCall] = field(default=None)
    function_response: Optional[GcpAIPlatformFunctionResponse] = field(default=None)
    inline_data: Optional[GcpAIPlatformBlob] = field(default=None)
    text: Optional[str] = field(default=None)
    video_metadata: Optional[GcpAIPlatformVideoMetadata] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformContent:
    kind: ClassVar[str] = "gcp_ai_platform_content"
    mapping: ClassVar[Dict[str, Bender]] = {
        "parts": S("parts", default=[]) >> ForallBend(GcpAIPlatformPart.mapping),
        "role": S("role"),
    }
    parts: Optional[List[GcpAIPlatformPart]] = field(default=None)
    role: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSupervisedTuningDatasetDistributionDatasetBucket:
    kind: ClassVar[str] = "gcp_ai_platform_supervised_tuning_dataset_distribution_dataset_bucket"
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("count"), "left": S("left"), "right": S("right")}
    count: Optional[float] = field(default=None)
    left: Optional[float] = field(default=None)
    right: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSupervisedTuningDatasetDistribution:
    kind: ClassVar[str] = "gcp_ai_platform_supervised_tuning_dataset_distribution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "billable_sum": S("billableSum"),
        "buckets": S("buckets", default=[])
        >> ForallBend(GcpAIPlatformSupervisedTuningDatasetDistributionDatasetBucket.mapping),
        "max": S("max"),
        "mean": S("mean"),
        "median": S("median"),
        "min": S("min"),
        "p5": S("p5"),
        "p95": S("p95"),
        "sum": S("sum"),
    }
    billable_sum: Optional[str] = field(default=None)
    buckets: Optional[List[GcpAIPlatformSupervisedTuningDatasetDistributionDatasetBucket]] = field(default=None)
    max: Optional[float] = field(default=None)
    mean: Optional[float] = field(default=None)
    median: Optional[float] = field(default=None)
    min: Optional[float] = field(default=None)
    p5: Optional[float] = field(default=None)
    p95: Optional[float] = field(default=None)
    sum: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformSupervisedTuningDataStats:
    kind: ClassVar[str] = "gcp_ai_platform_supervised_tuning_data_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "total_billable_character_count": S("totalBillableCharacterCount"),
        "total_billable_token_count": S("totalBillableTokenCount"),
        "total_tuning_character_count": S("totalTuningCharacterCount"),
        "tuning_dataset_example_count": S("tuningDatasetExampleCount"),
        "tuning_step_count": S("tuningStepCount"),
        "user_dataset_examples": S("userDatasetExamples", default=[]) >> ForallBend(GcpAIPlatformContent.mapping),
        "user_input_token_distribution": S("userInputTokenDistribution", default={})
        >> Bend(GcpAIPlatformSupervisedTuningDatasetDistribution.mapping),
        "user_message_per_example_distribution": S("userMessagePerExampleDistribution", default={})
        >> Bend(GcpAIPlatformSupervisedTuningDatasetDistribution.mapping),
        "user_output_token_distribution": S("userOutputTokenDistribution", default={})
        >> Bend(GcpAIPlatformSupervisedTuningDatasetDistribution.mapping),
    }
    total_billable_character_count: Optional[str] = field(default=None)
    total_billable_token_count: Optional[str] = field(default=None)
    total_tuning_character_count: Optional[str] = field(default=None)
    tuning_dataset_example_count: Optional[str] = field(default=None)
    tuning_step_count: Optional[str] = field(default=None)
    user_dataset_examples: Optional[List[GcpAIPlatformContent]] = field(default=None)
    user_input_token_distribution: Optional[GcpAIPlatformSupervisedTuningDatasetDistribution] = field(default=None)
    user_message_per_example_distribution: Optional[GcpAIPlatformSupervisedTuningDatasetDistribution] = field(
        default=None
    )
    user_output_token_distribution: Optional[GcpAIPlatformSupervisedTuningDatasetDistribution] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTuningDataStats:
    kind: ClassVar[str] = "gcp_ai_platform_tuning_data_stats"
    mapping: ClassVar[Dict[str, Bender]] = {
        "supervised_tuning_data_stats": S("supervisedTuningDataStats", default={})
        >> Bend(GcpAIPlatformSupervisedTuningDataStats.mapping)
    }
    supervised_tuning_data_stats: Optional[GcpAIPlatformSupervisedTuningDataStats] = field(default=None)


@define(eq=False, slots=False)
class GcpAIPlatformTuningJob(AIPlatformRegionFilter, GcpResource):
    kind: ClassVar[str] = "gcp_ai_platform_tuning_job"
    kind_display = ""
    kind_service = ""
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="aiplatform",
        version="v1",
        service_with_region_prefix=True,
        accessors=["projects", "locations", "tuningJobs"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/{region}"},
        request_parameter_in={"project", "region"},
        response_path="tuningJobs",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "base_model": S("baseModel"),
        "create_time": S("createTime"),
        "encryption_spec": S("encryptionSpec", "kmsKeyName"),
        "end_time": S("endTime"),
        "rpc_error": S("error", default={}) >> Bend(GcpGoogleRpcStatus.mapping),
        "experiment": S("experiment"),
        "start_time": S("startTime"),
        "state": S("state"),
        "supervised_tuning_spec": S("supervisedTuningSpec", default={})
        >> Bend(GcpAIPlatformSupervisedTuningSpec.mapping),
        "tuned_model": S("tunedModel", default={}) >> Bend(GcpAIPlatformTunedModel.mapping),
        "tuned_model_display_name": S("tunedModelDisplayName"),
        "tuning_data_stats": S("tuningDataStats", default={}) >> Bend(GcpAIPlatformTuningDataStats.mapping),
        "update_time": S("updateTime"),
    }
    base_model: Optional[str] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    encryption_spec: Optional[str] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    rpc_error: Optional[GcpGoogleRpcStatus] = field(default=None)
    experiment: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    state: Optional[str] = field(default=None)
    supervised_tuning_spec: Optional[GcpAIPlatformSupervisedTuningSpec] = field(default=None)
    tuned_model: Optional[GcpAIPlatformTunedModel] = field(default=None)
    tuned_model_display_name: Optional[str] = field(default=None)
    tuning_data_stats: Optional[GcpAIPlatformTuningDataStats] = field(default=None)
    update_time: Optional[datetime] = field(default=None)


resources: List[Type[GcpResource]] = [
    GcpAIPlatformModel,
    GcpAIPlatformDataset,
    # GcpAIPlatformDatasetVersion, : collected via GcpAIPlatformFeatureGroup
    GcpAIPlatformEndpoint,
    GcpAIPlatformSchedule,
    GcpAIPlatformFeatureGroup,
    # GcpAIPlatformFeature, : collected via GcpAIPlatformFeatureGroup
    GcpAIPlatformTrainingPipeline,
    GcpAIPlatformBatchPredictionJob,
    # GcpAIPlatformModelEvaluation, : collected via GcpAIPlatformModel
    GcpAIPlatformFeaturestore,
    GcpAIPlatformHyperparameterTuningJob,
    GcpAIPlatformCustomJob,
    GcpAIPlatformPipelineJob,
    GcpAIPlatformTensorboard,
    GcpAIPlatformIndex,
    GcpAIPlatformIndexEndpoint,
    GcpAIPlatformModelDeploymentMonitoringJob,
    GcpAIPlatformTuningJob,
]
