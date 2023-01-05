from datetime import datetime
from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resotolib.json_bender import S, Bend, Bender, ForallBend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsSagemakerNotebook(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_notebook"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-notebook-instances", "NotebookInstances")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NotebookInstanceName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("NotebookInstanceName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("NotebookInstanceArn"),
        "notebook_instance_status": S("NotebookInstanceStatus"),
        "notebook_failure_reason": S("FailureReason"),
        "notebook_url": S("Url"),
        "notebook_instance_type": S("InstanceType"),
        "notebook_subnet_id": S("SubnetId"),
        "notebook_security_groups": S("SecurityGroups", default=[]),
        "notebook_role_arn": S("RoleArn"),
        "notebook_kms_key_id": S("KmsKeyId"),
        "notebook_network_interface_id": S("NetworkInterfaceId"),
        "notebook_instance_lifecycle_config_name": S("NotebookInstanceLifecycleConfigName"),
        "notebook_direct_internet_access": S("DirectInternetAccess"),
        "notebook_volume_size_in_gb": S("VolumeSizeInGB"),
        "notebook_accelerator_types": S("AcceleratorTypes", default=[]),
        "notebook_default_code_repository": S("DefaultCodeRepository"),
        "notebook_additional_code_repositories": S("AdditionalCodeRepositories", default=[]),
        "notebook_root_access": S("RootAccess"),
        "notebook_platform_identifier": S("PlatformIdentifier"),
        "notebook_instance_metadata_service_configuration": S(
            "InstanceMetadataServiceConfiguration", "MinimumInstanceMetadataServiceVersion"
        ),
    }
    notebook_instance_status: Optional[str] = field(default=None)
    notebook_failure_reason: Optional[str] = field(default=None)
    notebook_url: Optional[str] = field(default=None)
    notebook_instance_type: Optional[str] = field(default=None)
    notebook_subnet_id: Optional[str] = field(default=None)
    notebook_security_groups: List[str] = field(factory=list)
    notebook_role_arn: Optional[str] = field(default=None)
    notebook_kms_key_id: Optional[str] = field(default=None)
    notebook_network_interface_id: Optional[str] = field(default=None)
    notebook_instance_lifecycle_config_name: Optional[str] = field(default=None)
    notebook_direct_internet_access: Optional[str] = field(default=None)
    notebook_volume_size_in_gb: Optional[int] = field(default=None)
    notebook_accelerator_types: List[str] = field(factory=list)
    notebook_default_code_repository: Optional[str] = field(default=None)
    notebook_additional_code_repositories: List[str] = field(factory=list)
    notebook_root_access: Optional[str] = field(default=None)
    notebook_platform_identifier: Optional[str] = field(default=None)
    notebook_instance_metadata_service_configuration: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for notebook in json:
            notebook_description = builder.client.get(
                "sagemaker", "describe-notebook-instance", None, NotebookInstanceName=notebook["NotebookInstanceName"]
            )
            if notebook_description:
                notebook_instance = AwsSagemakerNotebook.from_api(notebook_description)
                builder.add_node(notebook_instance, notebook_description)


@define(eq=False, slots=False)
class AwsSagemakerIntegerParameterRangeSpecification:
    kind: ClassVar[str] = "aws_sagemaker_integer_parameter_range_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"min_value": S("MinValue"), "max_value": S("MaxValue")}
    min_value: Optional[str] = field(default=None)
    max_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerContinuousParameterRangeSpecification:
    kind: ClassVar[str] = "aws_sagemaker_continuous_parameter_range_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"min_value": S("MinValue"), "max_value": S("MaxValue")}
    min_value: Optional[str] = field(default=None)
    max_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCategoricalParameterRangeSpecification:
    kind: ClassVar[str] = "aws_sagemaker_categorical_parameter_range_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"values": S("Values", default=[])}
    values: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerParameterRange:
    kind: ClassVar[str] = "aws_sagemaker_parameter_range"
    mapping: ClassVar[Dict[str, Bender]] = {
        "integer_parameter_range_specification": S("IntegerParameterRangeSpecification")
        >> Bend(AwsSagemakerIntegerParameterRangeSpecification.mapping),
        "continuous_parameter_range_specification": S("ContinuousParameterRangeSpecification")
        >> Bend(AwsSagemakerContinuousParameterRangeSpecification.mapping),
        "categorical_parameter_range_specification": S("CategoricalParameterRangeSpecification")
        >> Bend(AwsSagemakerCategoricalParameterRangeSpecification.mapping),
    }
    integer_parameter_range_specification: Optional[AwsSagemakerIntegerParameterRangeSpecification] = field(
        default=None
    )
    continuous_parameter_range_specification: Optional[AwsSagemakerContinuousParameterRangeSpecification] = field(
        default=None
    )
    categorical_parameter_range_specification: Optional[AwsSagemakerCategoricalParameterRangeSpecification] = field(
        default=None
    )


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterSpecification:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "description": S("Description"),
        "type": S("Type"),
        "range": S("Range") >> Bend(AwsSagemakerParameterRange.mapping),
        "is_tunable": S("IsTunable"),
        "is_required": S("IsRequired"),
        "default_value": S("DefaultValue"),
    }
    name: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    range: Optional[AwsSagemakerParameterRange] = field(default=None)
    is_tunable: Optional[bool] = field(default=None)
    is_required: Optional[bool] = field(default=None)
    default_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerMetricDefinition:
    kind: ClassVar[str] = "aws_sagemaker_metric_definition"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "regex": S("Regex")}
    name: Optional[str] = field(default=None)
    regex: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerChannelSpecification:
    kind: ClassVar[str] = "aws_sagemaker_channel_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "description": S("Description"),
        "is_required": S("IsRequired"),
        "supported_content_types": S("SupportedContentTypes", default=[]),
        "supported_compression_types": S("SupportedCompressionTypes", default=[]),
        "supported_input_modes": S("SupportedInputModes", default=[]),
    }
    name: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    is_required: Optional[bool] = field(default=None)
    supported_content_types: List[str] = field(factory=list)
    supported_compression_types: List[str] = field(factory=list)
    supported_input_modes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningJobObjective:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_job_objective"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "metric_name": S("MetricName")}
    type: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrainingSpecification:
    kind: ClassVar[str] = "aws_sagemaker_training_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "training_image": S("TrainingImage"),
        "training_image_digest": S("TrainingImageDigest"),
        "supported_hyper_parameters": S("SupportedHyperParameters", default=[])
        >> ForallBend(AwsSagemakerHyperParameterSpecification.mapping),
        "supported_training_instance_types": S("SupportedTrainingInstanceTypes", default=[]),
        "supports_distributed_training": S("SupportsDistributedTraining"),
        "metric_definitions": S("MetricDefinitions", default=[]) >> ForallBend(AwsSagemakerMetricDefinition.mapping),
        "training_channels": S("TrainingChannels", default=[]) >> ForallBend(AwsSagemakerChannelSpecification.mapping),
        "supported_tuning_job_objective_metrics": S("SupportedTuningJobObjectiveMetrics", default=[])
        >> ForallBend(AwsSagemakerHyperParameterTuningJobObjective.mapping),
    }
    training_image: Optional[str] = field(default=None)
    training_image_digest: Optional[str] = field(default=None)
    supported_hyper_parameters: List[AwsSagemakerHyperParameterSpecification] = field(factory=list)
    supported_training_instance_types: List[str] = field(factory=list)
    supports_distributed_training: Optional[bool] = field(default=None)
    metric_definitions: List[AwsSagemakerMetricDefinition] = field(factory=list)
    training_channels: List[AwsSagemakerChannelSpecification] = field(factory=list)
    supported_tuning_job_objective_metrics: List[AwsSagemakerHyperParameterTuningJobObjective] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerModelPackageContainerDefinition:
    kind: ClassVar[str] = "aws_sagemaker_model_package_container_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_hostname": S("ContainerHostname"),
        "image": S("Image"),
        "image_digest": S("ImageDigest"),
        "model_data_url": S("ModelDataUrl"),
        "product_id": S("ProductId"),
        "environment": S("Environment"),
        "model_input": S("ModelInput", "DataInputConfig"),
        "framework": S("Framework"),
        "framework_version": S("FrameworkVersion"),
        "nearest_model_name": S("NearestModelName"),
    }
    container_hostname: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    image_digest: Optional[str] = field(default=None)
    model_data_url: Optional[str] = field(default=None)
    product_id: Optional[str] = field(default=None)
    environment: Optional[Dict[str, str]] = field(default=None)
    model_input: Optional[str] = field(default=None)
    framework: Optional[str] = field(default=None)
    framework_version: Optional[str] = field(default=None)
    nearest_model_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerInferenceSpecification:
    kind: ClassVar[str] = "aws_sagemaker_inference_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "containers": S("Containers", default=[]) >> ForallBend(AwsSagemakerModelPackageContainerDefinition.mapping),
        "supported_transform_instance_types": S("SupportedTransformInstanceTypes", default=[]),
        "supported_realtime_inference_instance_types": S("SupportedRealtimeInferenceInstanceTypes", default=[]),
        "supported_content_types": S("SupportedContentTypes", default=[]),
        "supported_response_mime_types": S("SupportedResponseMIMETypes", default=[]),
    }
    containers: List[AwsSagemakerModelPackageContainerDefinition] = field(factory=list)
    supported_transform_instance_types: List[str] = field(factory=list)
    supported_realtime_inference_instance_types: List[str] = field(factory=list)
    supported_content_types: List[str] = field(factory=list)
    supported_response_mime_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerS3DataSource:
    kind: ClassVar[str] = "aws_sagemaker_s3_data_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_type": S("S3DataType"),
        "s3_uri": S("S3Uri"),
        "s3_data_distribution_type": S("S3DataDistributionType"),
        "attribute_names": S("AttributeNames", default=[]),
        "instance_group_names": S("InstanceGroupNames", default=[]),
    }
    s3_data_type: Optional[str] = field(default=None)
    s3_uri: Optional[str] = field(default=None)
    s3_data_distribution_type: Optional[str] = field(default=None)
    attribute_names: List[str] = field(factory=list)
    instance_group_names: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerFileSystemDataSource:
    kind: ClassVar[str] = "aws_sagemaker_file_system_data_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "file_system_id": S("FileSystemId"),
        "file_system_access_mode": S("FileSystemAccessMode"),
        "file_system_type": S("FileSystemType"),
        "directory_path": S("DirectoryPath"),
    }
    file_system_id: Optional[str] = field(default=None)
    file_system_access_mode: Optional[str] = field(default=None)
    file_system_type: Optional[str] = field(default=None)
    directory_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDataSource:
    kind: ClassVar[str] = "aws_sagemaker_data_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource") >> Bend(AwsSagemakerS3DataSource.mapping),
        "file_system_data_source": S("FileSystemDataSource") >> Bend(AwsSagemakerFileSystemDataSource.mapping),
    }
    s3_data_source: Optional[AwsSagemakerS3DataSource] = field(default=None)
    file_system_data_source: Optional[AwsSagemakerFileSystemDataSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerChannel:
    kind: ClassVar[str] = "aws_sagemaker_channel"
    mapping: ClassVar[Dict[str, Bender]] = {
        "channel_name": S("ChannelName"),
        "data_source": S("DataSource") >> Bend(AwsSagemakerDataSource.mapping),
        "content_type": S("ContentType"),
        "compression_type": S("CompressionType"),
        "record_wrapper_type": S("RecordWrapperType"),
        "input_mode": S("InputMode"),
        "shuffle_config": S("ShuffleConfig", "Seed"),
    }
    channel_name: Optional[str] = field(default=None)
    data_source: Optional[AwsSagemakerDataSource] = field(default=None)
    content_type: Optional[str] = field(default=None)
    compression_type: Optional[str] = field(default=None)
    record_wrapper_type: Optional[str] = field(default=None)
    input_mode: Optional[str] = field(default=None)
    shuffle_config: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerOutputDataConfig:
    kind: ClassVar[str] = "aws_sagemaker_output_data_config"
    mapping: ClassVar[Dict[str, Bender]] = {"kms_key_id": S("KmsKeyId"), "s3_output_path": S("S3OutputPath")}
    kms_key_id: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerInstanceGroup:
    kind: ClassVar[str] = "aws_sagemaker_instance_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "instance_group_name": S("InstanceGroupName"),
    }
    instance_type: Optional[str] = field(default=None)
    instance_count: Optional[int] = field(default=None)
    instance_group_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerResourceConfig:
    kind: ClassVar[str] = "aws_sagemaker_resource_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "volume_kms_key_id": S("VolumeKmsKeyId"),
        "instance_groups": S("InstanceGroups", default=[]) >> ForallBend(AwsSagemakerInstanceGroup.mapping),
        "keep_alive_period_in_seconds": S("KeepAlivePeriodInSeconds"),
    }
    instance_type: Optional[str] = field(default=None)
    instance_count: Optional[int] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)
    instance_groups: List[AwsSagemakerInstanceGroup] = field(factory=list)
    keep_alive_period_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerStoppingCondition:
    kind: ClassVar[str] = "aws_sagemaker_stopping_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_runtime_in_seconds": S("MaxRuntimeInSeconds"),
        "max_wait_time_in_seconds": S("MaxWaitTimeInSeconds"),
    }
    max_runtime_in_seconds: Optional[int] = field(default=None)
    max_wait_time_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrainingJobDefinition:
    kind: ClassVar[str] = "aws_sagemaker_training_job_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "training_input_mode": S("TrainingInputMode"),
        "hyper_parameters": S("HyperParameters"),
        "input_data_config": S("InputDataConfig", default=[]) >> ForallBend(AwsSagemakerChannel.mapping),
        "output_data_config": S("OutputDataConfig") >> Bend(AwsSagemakerOutputDataConfig.mapping),
        "resource_config": S("ResourceConfig") >> Bend(AwsSagemakerResourceConfig.mapping),
        "stopping_condition": S("StoppingCondition") >> Bend(AwsSagemakerStoppingCondition.mapping),
    }
    training_input_mode: Optional[str] = field(default=None)
    hyper_parameters: Optional[Dict[str, str]] = field(default=None)
    input_data_config: List[AwsSagemakerChannel] = field(factory=list)
    output_data_config: Optional[AwsSagemakerOutputDataConfig] = field(default=None)
    resource_config: Optional[AwsSagemakerResourceConfig] = field(default=None)
    stopping_condition: Optional[AwsSagemakerStoppingCondition] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformS3DataSource:
    kind: ClassVar[str] = "aws_sagemaker_transform_s3_data_source"
    mapping: ClassVar[Dict[str, Bender]] = {"s3_data_type": S("S3DataType"), "s3_uri": S("S3Uri")}
    s3_data_type: Optional[str] = field(default=None)
    s3_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformDataSource:
    kind: ClassVar[str] = "aws_sagemaker_transform_data_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource") >> Bend(AwsSagemakerTransformS3DataSource.mapping)
    }
    s3_data_source: Optional[AwsSagemakerTransformS3DataSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformInput:
    kind: ClassVar[str] = "aws_sagemaker_transform_input"
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_source": S("DataSource") >> Bend(AwsSagemakerTransformDataSource.mapping),
        "content_type": S("ContentType"),
        "compression_type": S("CompressionType"),
        "split_type": S("SplitType"),
    }
    data_source: Optional[AwsSagemakerTransformDataSource] = field(default=None)
    content_type: Optional[str] = field(default=None)
    compression_type: Optional[str] = field(default=None)
    split_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformOutput:
    kind: ClassVar[str] = "aws_sagemaker_transform_output"
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_output_path": S("S3OutputPath"),
        "accept": S("Accept"),
        "assemble_with": S("AssembleWith"),
        "kms_key_id": S("KmsKeyId"),
    }
    s3_output_path: Optional[str] = field(default=None)
    accept: Optional[str] = field(default=None)
    assemble_with: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformResources:
    kind: ClassVar[str] = "aws_sagemaker_transform_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "volume_kms_key_id": S("VolumeKmsKeyId"),
    }
    instance_type: Optional[str] = field(default=None)
    instance_count: Optional[int] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformJobDefinition:
    kind: ClassVar[str] = "aws_sagemaker_transform_job_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_concurrent_transforms": S("MaxConcurrentTransforms"),
        "max_payload_in_mb": S("MaxPayloadInMB"),
        "batch_strategy": S("BatchStrategy"),
        "environment": S("Environment"),
        "transform_input": S("TransformInput") >> Bend(AwsSagemakerTransformInput.mapping),
        "transform_output": S("TransformOutput") >> Bend(AwsSagemakerTransformOutput.mapping),
        "transform_resources": S("TransformResources") >> Bend(AwsSagemakerTransformResources.mapping),
    }
    max_concurrent_transforms: Optional[int] = field(default=None)
    max_payload_in_mb: Optional[int] = field(default=None)
    batch_strategy: Optional[str] = field(default=None)
    environment: Optional[Dict[str, str]] = field(default=None)
    transform_input: Optional[AwsSagemakerTransformInput] = field(default=None)
    transform_output: Optional[AwsSagemakerTransformOutput] = field(default=None)
    transform_resources: Optional[AwsSagemakerTransformResources] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmValidationProfile:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_validation_profile"
    mapping: ClassVar[Dict[str, Bender]] = {
        "profile_name": S("ProfileName"),
        "training_job_definition": S("TrainingJobDefinition") >> Bend(AwsSagemakerTrainingJobDefinition.mapping),
        "transform_job_definition": S("TransformJobDefinition") >> Bend(AwsSagemakerTransformJobDefinition.mapping),
    }
    profile_name: Optional[str] = field(default=None)
    training_job_definition: Optional[AwsSagemakerTrainingJobDefinition] = field(default=None)
    transform_job_definition: Optional[AwsSagemakerTransformJobDefinition] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmValidationSpecification:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_validation_specification"
    mapping: ClassVar[Dict[str, Bender]] = {
        "validation_role": S("ValidationRole"),
        "validation_profiles": S("ValidationProfiles", default=[])
        >> ForallBend(AwsSagemakerAlgorithmValidationProfile.mapping),
    }
    validation_role: Optional[str] = field(default=None)
    validation_profiles: List[AwsSagemakerAlgorithmValidationProfile] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmStatusItem:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_status_item"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "status": S("Status"),
        "failure_reason": S("FailureReason"),
    }
    name: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    failure_reason: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmStatusDetails:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_status_details"
    mapping: ClassVar[Dict[str, Bender]] = {
        "validation_statuses": S("ValidationStatuses", default=[])
        >> ForallBend(AwsSagemakerAlgorithmStatusItem.mapping),
        "image_scan_statuses": S("ImageScanStatuses", default=[])
        >> ForallBend(AwsSagemakerAlgorithmStatusItem.mapping),
    }
    validation_statuses: List[AwsSagemakerAlgorithmStatusItem] = field(factory=list)
    image_scan_statuses: List[AwsSagemakerAlgorithmStatusItem] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithm(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_algorithm"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-algorithms", "AlgorithmSummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AlgorithmName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("AlgorithmName"),
        "ctime": S("CreationTime"),
        "arn": S("AlgorithmArn"),
        "algorithm_description": S("AlgorithmDescription"),
        "algorithm_training_specification": S("TrainingSpecification")
        >> Bend(AwsSagemakerTrainingSpecification.mapping),
        "algorithm_inference_specification": S("InferenceSpecification")
        >> Bend(AwsSagemakerInferenceSpecification.mapping),
        "algorithm_validation_specification": S("ValidationSpecification")
        >> Bend(AwsSagemakerAlgorithmValidationSpecification.mapping),
        "algorithm_status": S("AlgorithmStatus"),
        "algorithm_status_details": S("AlgorithmStatusDetails") >> Bend(AwsSagemakerAlgorithmStatusDetails.mapping),
        "algorithm_product_id": S("ProductId"),
        "algorithm_certify_for_marketplace": S("CertifyForMarketplace"),
    }
    algorithm_description: Optional[str] = field(default=None)
    algorithm_training_specification: Optional[AwsSagemakerTrainingSpecification] = field(default=None)
    algorithm_inference_specification: Optional[AwsSagemakerInferenceSpecification] = field(default=None)
    algorithm_validation_specification: Optional[AwsSagemakerAlgorithmValidationSpecification] = field(default=None)
    algorithm_status: Optional[str] = field(default=None)
    algorithm_status_details: Optional[AwsSagemakerAlgorithmStatusDetails] = field(default=None)
    algorithm_product_id: Optional[str] = field(default=None)
    algorithm_certify_for_marketplace: Optional[bool] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for algorithm in json:
            algorithm_description = builder.client.get(
                "sagemaker", "describe-algorithm", None, AlgorithmName=algorithm["AlgorithmName"]
            )
            if algorithm_description:
                algorithm_instance = AwsSagemakerAlgorithm.from_api(algorithm_description)
                builder.add_node(algorithm_instance, algorithm_description)


@define(eq=False, slots=False)
class AwsSagemakerImageConfig:
    kind: ClassVar[str] = "aws_sagemaker_image_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "repository_access_mode": S("RepositoryAccessMode"),
        "repository_auth_config": S("RepositoryAuthConfig", "RepositoryCredentialsProviderArn"),
    }
    repository_access_mode: Optional[str] = field(default=None)
    repository_auth_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerContainerDefinition:
    kind: ClassVar[str] = "aws_sagemaker_container_definition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "container_hostname": S("ContainerHostname"),
        "image": S("Image"),
        "image_config": S("ImageConfig") >> Bend(AwsSagemakerImageConfig.mapping),
        "mode": S("Mode"),
        "model_data_url": S("ModelDataUrl"),
        "environment": S("Environment"),
        "model_package_name": S("ModelPackageName"),
        "inference_specification_name": S("InferenceSpecificationName"),
        "multi_model_config": S("MultiModelConfig", "ModelCacheSetting"),
    }
    container_hostname: Optional[str] = field(default=None)
    image: Optional[str] = field(default=None)
    image_config: Optional[AwsSagemakerImageConfig] = field(default=None)
    mode: Optional[str] = field(default=None)
    model_data_url: Optional[str] = field(default=None)
    environment: Optional[Dict[str, str]] = field(default=None)
    model_package_name: Optional[str] = field(default=None)
    inference_specification_name: Optional[str] = field(default=None)
    multi_model_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerVpcConfig:
    kind: ClassVar[str] = "aws_sagemaker_vpc_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("SecurityGroupIds", default=[]),
        "subnets": S("Subnets", default=[]),
    }
    security_group_ids: List[str] = field(factory=list)
    subnets: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerModel(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_model"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-models", "Models")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ModelName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ModelName"),
        "ctime": S("CreationTime"),
        "arn": S("ModelArn"),
        "model_primary_container": S("PrimaryContainer") >> Bend(AwsSagemakerContainerDefinition.mapping),
        "model_containers": S("Containers", default=[]) >> ForallBend(AwsSagemakerContainerDefinition.mapping),
        "model_inference_execution_config": S("InferenceExecutionConfig", "Mode"),
        "model_execution_role_arn": S("ExecutionRoleArn"),
        "model_vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
        "model_enable_network_isolation": S("EnableNetworkIsolation"),
    }
    model_primary_container: Optional[AwsSagemakerContainerDefinition] = field(default=None)
    model_containers: List[AwsSagemakerContainerDefinition] = field(factory=list)
    model_inference_execution_config: Optional[str] = field(default=None)
    model_execution_role_arn: Optional[str] = field(default=None)
    model_vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)
    model_enable_network_isolation: Optional[bool] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for model in json:
            model_description = builder.client.get("sagemaker", "describe-model", None, ModelName=model["ModelName"])
            if model_description:
                model_instance = AwsSagemakerModel.from_api(model_description)
                builder.add_node(model_instance, model_description)


@define(eq=False, slots=False)
class AwsSagemakerResourceSpec:
    kind: ClassVar[str] = "aws_sagemaker_resource_spec"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sage_maker_image_arn": S("SageMakerImageArn"),
        "sage_maker_image_version_arn": S("SageMakerImageVersionArn"),
        "instance_type": S("InstanceType"),
        "lifecycle_config_arn": S("LifecycleConfigArn"),
    }
    sage_maker_image_arn: Optional[str] = field(default=None)
    sage_maker_image_version_arn: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    lifecycle_config_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerApp(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_app"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-apps", "Apps")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AppName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("AppName"),
        "ctime": S("CreationTime"),
        "atime": S("LastUserActivityTimestamp"),
        "arn": S("AppArn"),
        "app_type": S("AppType"),
        "app_domain_id": S("DomainId"),
        "app_user_profile_name": S("UserProfileName"),
        "app_status": S("Status"),
        "app_last_health_check_timestamp": S("LastHealthCheckTimestamp"),
        "app_failure_reason": S("FailureReason"),
        "app_resource_spec": S("ResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "app_space_name": S("SpaceName"),
    }
    app_type: Optional[str] = field(default=None)
    app_domain_id: Optional[str] = field(default=None)
    app_user_profile_name: Optional[str] = field(default=None)
    app_status: Optional[str] = field(default=None)
    app_last_health_check_timestamp: Optional[datetime] = field(default=None)
    app_failure_reason: Optional[str] = field(default=None)
    app_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    app_space_name: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for app in json:
            app_description = builder.client.get(
                "sagemaker",
                "describe-app",
                None,
                DomainId=app["DomainId"],
                AppType=app["AppType"],
                AppName=app["AppName"],
            )
            if app_description:
                app_instance = AwsSagemakerApp.from_api(app_description)
                builder.add_node(app_instance, app_description)


@define(eq=False, slots=False)
class AwsSagemakerSharingSettings:
    kind: ClassVar[str] = "aws_sagemaker_sharing_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "notebook_output_option": S("NotebookOutputOption"),
        "s3_output_path": S("S3OutputPath"),
        "s3_kms_key_id": S("S3KmsKeyId"),
    }
    notebook_output_option: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)
    s3_kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerJupyterServerAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_jupyter_server_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "lifecycle_config_arns": S("LifecycleConfigArns", default=[]),
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    lifecycle_config_arns: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerCustomImage:
    kind: ClassVar[str] = "aws_sagemaker_custom_image"
    mapping: ClassVar[Dict[str, Bender]] = {
        "image_name": S("ImageName"),
        "image_version_number": S("ImageVersionNumber"),
        "app_image_config_name": S("AppImageConfigName"),
    }
    image_name: Optional[str] = field(default=None)
    image_version_number: Optional[int] = field(default=None)
    app_image_config_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerKernelGatewayAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_kernel_gateway_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "custom_images": S("CustomImages", default=[]) >> ForallBend(AwsSagemakerCustomImage.mapping),
        "lifecycle_config_arns": S("LifecycleConfigArns", default=[]),
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    custom_images: List[AwsSagemakerCustomImage] = field(factory=list)
    lifecycle_config_arns: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerTensorBoardAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_tensor_board_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping)
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRStudioServerProAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_r_studio_server_pro_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {"access_status": S("AccessStatus"), "user_group": S("UserGroup")}
    access_status: Optional[str] = field(default=None)
    user_group: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRSessionAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_r_session_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "custom_images": S("CustomImages", default=[]) >> ForallBend(AwsSagemakerCustomImage.mapping),
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    custom_images: List[AwsSagemakerCustomImage] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerTimeSeriesForecastingSettings:
    kind: ClassVar[str] = "aws_sagemaker_time_series_forecasting_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "amazon_forecast_role_arn": S("AmazonForecastRoleArn"),
    }
    status: Optional[str] = field(default=None)
    amazon_forecast_role_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCanvasAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_canvas_app_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "time_series_forecasting_settings": S("TimeSeriesForecastingSettings")
        >> Bend(AwsSagemakerTimeSeriesForecastingSettings.mapping)
    }
    time_series_forecasting_settings: Optional[AwsSagemakerTimeSeriesForecastingSettings] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUserSettings:
    kind: ClassVar[str] = "aws_sagemaker_user_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "execution_role": S("ExecutionRole"),
        "security_groups": S("SecurityGroups", default=[]),
        "sharing_settings": S("SharingSettings") >> Bend(AwsSagemakerSharingSettings.mapping),
        "jupyter_server_app_settings": S("JupyterServerAppSettings")
        >> Bend(AwsSagemakerJupyterServerAppSettings.mapping),
        "kernel_gateway_app_settings": S("KernelGatewayAppSettings")
        >> Bend(AwsSagemakerKernelGatewayAppSettings.mapping),
        "tensor_board_app_settings": S("TensorBoardAppSettings") >> Bend(AwsSagemakerTensorBoardAppSettings.mapping),
        "r_studio_server_pro_app_settings": S("RStudioServerProAppSettings")
        >> Bend(AwsSagemakerRStudioServerProAppSettings.mapping),
        "r_session_app_settings": S("RSessionAppSettings") >> Bend(AwsSagemakerRSessionAppSettings.mapping),
        "canvas_app_settings": S("CanvasAppSettings") >> Bend(AwsSagemakerCanvasAppSettings.mapping),
    }
    execution_role: Optional[str] = field(default=None)
    security_groups: List[str] = field(factory=list)
    sharing_settings: Optional[AwsSagemakerSharingSettings] = field(default=None)
    jupyter_server_app_settings: Optional[AwsSagemakerJupyterServerAppSettings] = field(default=None)
    kernel_gateway_app_settings: Optional[AwsSagemakerKernelGatewayAppSettings] = field(default=None)
    tensor_board_app_settings: Optional[AwsSagemakerTensorBoardAppSettings] = field(default=None)
    r_studio_server_pro_app_settings: Optional[AwsSagemakerRStudioServerProAppSettings] = field(default=None)
    r_session_app_settings: Optional[AwsSagemakerRSessionAppSettings] = field(default=None)
    canvas_app_settings: Optional[AwsSagemakerCanvasAppSettings] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRStudioServerProDomainSettings:
    kind: ClassVar[str] = "aws_sagemaker_r_studio_server_pro_domain_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_execution_role_arn": S("DomainExecutionRoleArn"),
        "r_studio_connect_url": S("RStudioConnectUrl"),
        "r_studio_package_manager_url": S("RStudioPackageManagerUrl"),
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
    }
    domain_execution_role_arn: Optional[str] = field(default=None)
    r_studio_connect_url: Optional[str] = field(default=None)
    r_studio_package_manager_url: Optional[str] = field(default=None)
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDomainSettings:
    kind: ClassVar[str] = "aws_sagemaker_domain_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("SecurityGroupIds", default=[]),
        "r_studio_server_pro_domain_settings": S("RStudioServerProDomainSettings")
        >> Bend(AwsSagemakerRStudioServerProDomainSettings.mapping),
        "execution_role_identity_config": S("ExecutionRoleIdentityConfig"),
    }
    security_group_ids: List[str] = field(factory=list)
    r_studio_server_pro_domain_settings: Optional[AwsSagemakerRStudioServerProDomainSettings] = field(default=None)
    execution_role_identity_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDefaultSpaceSettings:
    kind: ClassVar[str] = "aws_sagemaker_default_space_settings"
    mapping: ClassVar[Dict[str, Bender]] = {
        "execution_role": S("ExecutionRole"),
        "security_groups": S("SecurityGroups", default=[]),
        "jupyter_server_app_settings": S("JupyterServerAppSettings")
        >> Bend(AwsSagemakerJupyterServerAppSettings.mapping),
        "kernel_gateway_app_settings": S("KernelGatewayAppSettings")
        >> Bend(AwsSagemakerKernelGatewayAppSettings.mapping),
    }
    execution_role: Optional[str] = field(default=None)
    security_groups: List[str] = field(factory=list)
    jupyter_server_app_settings: Optional[AwsSagemakerJupyterServerAppSettings] = field(default=None)
    kernel_gateway_app_settings: Optional[AwsSagemakerKernelGatewayAppSettings] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDomain(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_domain"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-domains", "Domains")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DomainId"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("DomainName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("DomainArn"),
        "domain_home_efs_file_system_id": S("HomeEfsFileSystemId"),
        "domain_single_sign_on_managed_application_instance_id": S("SingleSignOnManagedApplicationInstanceId"),
        "domain_status": S("Status"),
        "domain_failure_reason": S("FailureReason"),
        "domain_auth_mode": S("AuthMode"),
        "domain_default_user_settings": S("DefaultUserSettings") >> Bend(AwsSagemakerUserSettings.mapping),
        "domain_app_network_access_type": S("AppNetworkAccessType"),
        "domain_home_efs_file_system_kms_key_id": S("HomeEfsFileSystemKmsKeyId"),
        "domain_subnet_ids": S("SubnetIds", default=[]),
        "domain_url": S("Url"),
        "domain_vpc_id": S("VpcId"),
        "domain_kms_key_id": S("KmsKeyId"),
        "domain_settings": S("DomainSettings") >> Bend(AwsSagemakerDomainSettings.mapping),
        "domain_app_security_group_management": S("AppSecurityGroupManagement"),
        "domain_security_group_id_for_domain_boundary": S("SecurityGroupIdForDomainBoundary"),
        "domain_default_space_settings": S("DefaultSpaceSettings") >> Bend(AwsSagemakerDefaultSpaceSettings.mapping),
    }
    domain_home_efs_file_system_id: Optional[str] = field(default=None)
    domain_single_sign_on_managed_application_instance_id: Optional[str] = field(default=None)
    domain_status: Optional[str] = field(default=None)
    domain_failure_reason: Optional[str] = field(default=None)
    domain_auth_mode: Optional[str] = field(default=None)
    domain_default_user_settings: Optional[AwsSagemakerUserSettings] = field(default=None)
    domain_app_network_access_type: Optional[str] = field(default=None)
    domain_home_efs_file_system_kms_key_id: Optional[str] = field(default=None)
    domain_subnet_ids: List[str] = field(factory=list)
    domain_url: Optional[str] = field(default=None)
    domain_vpc_id: Optional[str] = field(default=None)
    domain_kms_key_id: Optional[str] = field(default=None)
    domain_settings: Optional[AwsSagemakerDomainSettings] = field(default=None)
    domain_app_security_group_management: Optional[str] = field(default=None)
    domain_security_group_id_for_domain_boundary: Optional[str] = field(default=None)
    domain_default_space_settings: Optional[AwsSagemakerDefaultSpaceSettings] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for domain in json:
            domain_description = builder.client.get(
                "sagemaker",
                "describe-domain",
                None,
                DomainId=domain["DomainId"],
            )
            if domain_description:
                domain_instance = AwsSagemakerDomain.from_api(domain_description)
                builder.add_node(domain_instance, domain_description)


@define(eq=False, slots=False)
class AwsSagemakerExperimentSource:
    kind: ClassVar[str] = "aws_sagemaker_experiment_source"
    mapping: ClassVar[Dict[str, Bender]] = {"source_arn": S("SourceArn"), "source_type": S("SourceType")}
    source_arn: Optional[str] = field(default=None)
    source_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerExperiment(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_experiment"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-experiments", "ExperimentSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ExperimentName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ExperimentName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ExperimentArn"),
        "experiment_display_name": S("DisplayName"),
        "experiment_source": S("ExperimentSource") >> Bend(AwsSagemakerExperimentSource.mapping),  # a job?
    }
    experiment_display_name: Optional[str] = field(default=None)
    experiment_source: Optional[AwsSagemakerExperimentSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrialSource:
    kind: ClassVar[str] = "aws_sagemaker_trial_source"
    mapping: ClassVar[Dict[str, Bender]] = {"source_arn": S("SourceArn"), "source_type": S("SourceType")}
    source_arn: Optional[str] = field(default=None)
    source_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUserContext:
    kind: ClassVar[str] = "aws_sagemaker_user_context"
    mapping: ClassVar[Dict[str, Bender]] = {
        "user_profile_arn": S("UserProfileArn"),
        "user_profile_name": S("UserProfileName"),
        "domain_id": S("DomainId"),
    }
    user_profile_arn: Optional[str] = field(default=None)
    user_profile_name: Optional[str] = field(default=None)
    domain_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerMetadataProperties:
    kind: ClassVar[str] = "aws_sagemaker_metadata_properties"
    mapping: ClassVar[Dict[str, Bender]] = {
        "commit_id": S("CommitId"),
        "repository": S("Repository"),
        "generated_by": S("GeneratedBy"),
        "project_id": S("ProjectId"),
    }
    commit_id: Optional[str] = field(default=None)
    repository: Optional[str] = field(default=None)
    generated_by: Optional[str] = field(default=None)
    project_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrial(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_trial"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-trials", "TrialSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TrialName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("TrialName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("TrialArn"),
        "trial_display_name": S("DisplayName"),
        "trial_experiment_name": S("ExperimentName"),
        "trial_source": S("Source") >> Bend(AwsSagemakerTrialSource.mapping),
        "trial_created_by": S("CreatedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "trial_last_modified_by": S("LastModifiedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "trial_metadata_properties": S("MetadataProperties") >> Bend(AwsSagemakerMetadataProperties.mapping),
    }
    trial_display_name: Optional[str] = field(default=None)
    trial_experiment_name: Optional[str] = field(default=None)
    trial_source: Optional[AwsSagemakerTrialSource] = field(default=None)
    trial_created_by: Optional[AwsSagemakerUserContext] = field(default=None)
    trial_last_modified_by: Optional[AwsSagemakerUserContext] = field(default=None)
    trial_metadata_properties: Optional[AwsSagemakerMetadataProperties] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for trial in json:
            trial_description = builder.client.get(
                "sagemaker",
                "describe-trial",
                None,
                TrialName=trial["TrialName"],
            )
            if trial_description:
                trial_instance = AwsSagemakerTrial.from_api(trial_description)
                builder.add_node(trial_instance, trial_description)


@define(eq=False, slots=False)
class AwsSagemakerGitConfig:
    kind: ClassVar[str] = "aws_sagemaker_git_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "repository_url": S("RepositoryUrl"),
        "branch": S("Branch"),
        "secret_arn": S("SecretArn"),
    }
    repository_url: Optional[str] = field(default=None)
    branch: Optional[str] = field(default=None)
    secret_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCodeRepository(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_code_repository"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-code-repositories", "CodeRepositorySummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CodeRepositoryName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("CodeRepositoryName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("CodeRepositoryArn"),
        "code_repository_git_config": S("GitConfig") >> Bend(AwsSagemakerGitConfig.mapping),
    }
    code_repository_git_config: Optional[AwsSagemakerGitConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDeployedImage:
    kind: ClassVar[str] = "aws_sagemaker_deployed_image"
    mapping: ClassVar[Dict[str, Bender]] = {
        "specified_image": S("SpecifiedImage"),
        "resolved_image": S("ResolvedImage"),
        "resolution_time": S("ResolutionTime"),
    }
    specified_image: Optional[str] = field(default=None)
    resolved_image: Optional[str] = field(default=None)
    resolution_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProductionVariantStatus:
    kind: ClassVar[str] = "aws_sagemaker_production_variant_status"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "status_message": S("StatusMessage"),
        "start_time": S("StartTime"),
    }
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProductionVariantServerlessConfig:
    kind: ClassVar[str] = "aws_sagemaker_production_variant_serverless_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "memory_size_in_mb": S("MemorySizeInMB"),
        "max_concurrency": S("MaxConcurrency"),
    }
    memory_size_in_mb: Optional[int] = field(default=None)
    max_concurrency: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProductionVariantSummary:
    kind: ClassVar[str] = "aws_sagemaker_production_variant_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "variant_name": S("VariantName"),
        "deployed_images": S("DeployedImages", default=[]) >> ForallBend(AwsSagemakerDeployedImage.mapping),
        "current_weight": S("CurrentWeight"),
        "desired_weight": S("DesiredWeight"),
        "current_instance_count": S("CurrentInstanceCount"),
        "desired_instance_count": S("DesiredInstanceCount"),
        "variant_status": S("VariantStatus", default=[]) >> ForallBend(AwsSagemakerProductionVariantStatus.mapping),
        "current_serverless_config": S("CurrentServerlessConfig")
        >> Bend(AwsSagemakerProductionVariantServerlessConfig.mapping),
        "desired_serverless_config": S("DesiredServerlessConfig")
        >> Bend(AwsSagemakerProductionVariantServerlessConfig.mapping),
    }
    variant_name: Optional[str] = field(default=None)
    deployed_images: List[AwsSagemakerDeployedImage] = field(factory=list)
    current_weight: Optional[float] = field(default=None)
    desired_weight: Optional[float] = field(default=None)
    current_instance_count: Optional[int] = field(default=None)
    desired_instance_count: Optional[int] = field(default=None)
    variant_status: List[AwsSagemakerProductionVariantStatus] = field(factory=list)
    current_serverless_config: Optional[AwsSagemakerProductionVariantServerlessConfig] = field(default=None)
    desired_serverless_config: Optional[AwsSagemakerProductionVariantServerlessConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDataCaptureConfigSummary:
    kind: ClassVar[str] = "aws_sagemaker_data_capture_config_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_capture": S("EnableCapture"),
        "capture_status": S("CaptureStatus"),
        "current_sampling_percentage": S("CurrentSamplingPercentage"),
        "destination_s3_uri": S("DestinationS3Uri"),
        "kms_key_id": S("KmsKeyId"),
    }
    enable_capture: Optional[bool] = field(default=None)
    capture_status: Optional[str] = field(default=None)
    current_sampling_percentage: Optional[int] = field(default=None)
    destination_s3_uri: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCapacitySize:
    kind: ClassVar[str] = "aws_sagemaker_capacity_size"
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "value": S("Value")}
    type: Optional[str] = field(default=None)
    value: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrafficRoutingConfig:
    kind: ClassVar[str] = "aws_sagemaker_traffic_routing_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("Type"),
        "wait_interval_in_seconds": S("WaitIntervalInSeconds"),
        "canary_size": S("CanarySize") >> Bend(AwsSagemakerCapacitySize.mapping),
        "linear_step_size": S("LinearStepSize") >> Bend(AwsSagemakerCapacitySize.mapping),
    }
    type: Optional[str] = field(default=None)
    wait_interval_in_seconds: Optional[int] = field(default=None)
    canary_size: Optional[AwsSagemakerCapacitySize] = field(default=None)
    linear_step_size: Optional[AwsSagemakerCapacitySize] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerBlueGreenUpdatePolicy:
    kind: ClassVar[str] = "aws_sagemaker_blue_green_update_policy"
    mapping: ClassVar[Dict[str, Bender]] = {
        "traffic_routing_configuration": S("TrafficRoutingConfiguration")
        >> Bend(AwsSagemakerTrafficRoutingConfig.mapping),
        "termination_wait_in_seconds": S("TerminationWaitInSeconds"),
        "maximum_execution_timeout_in_seconds": S("MaximumExecutionTimeoutInSeconds"),
    }
    traffic_routing_configuration: Optional[AwsSagemakerTrafficRoutingConfig] = field(default=None)
    termination_wait_in_seconds: Optional[int] = field(default=None)
    maximum_execution_timeout_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoRollbackConfig:
    kind: ClassVar[str] = "aws_sagemaker_auto_rollback_config"
    mapping: ClassVar[Dict[str, Bender]] = {"alarms": S("Alarms", default=[]) >> ForallBend(S("AlarmName"))}
    alarms: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerDeploymentConfig:
    kind: ClassVar[str] = "aws_sagemaker_deployment_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_update_policy": S("BlueGreenUpdatePolicy") >> Bend(AwsSagemakerBlueGreenUpdatePolicy.mapping),
        "auto_rollback_configuration": S("AutoRollbackConfiguration") >> Bend(AwsSagemakerAutoRollbackConfig.mapping),
    }
    blue_green_update_policy: Optional[AwsSagemakerBlueGreenUpdatePolicy] = field(default=None)
    auto_rollback_configuration: Optional[AwsSagemakerAutoRollbackConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAsyncInferenceNotificationConfig:
    kind: ClassVar[str] = "aws_sagemaker_async_inference_notification_config"
    mapping: ClassVar[Dict[str, Bender]] = {"success_topic": S("SuccessTopic"), "error_topic": S("ErrorTopic")}
    success_topic: Optional[str] = field(default=None)
    error_topic: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAsyncInferenceOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_async_inference_output_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "kms_key_id": S("KmsKeyId"),
        "s3_output_path": S("S3OutputPath"),
        "notification_config": S("NotificationConfig") >> Bend(AwsSagemakerAsyncInferenceNotificationConfig.mapping),
    }
    kms_key_id: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)
    notification_config: Optional[AwsSagemakerAsyncInferenceNotificationConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAsyncInferenceConfig:
    kind: ClassVar[str] = "aws_sagemaker_async_inference_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_config": S("ClientConfig", "MaxConcurrentInvocationsPerInstance"),
        "output_config": S("OutputConfig") >> Bend(AwsSagemakerAsyncInferenceOutputConfig.mapping),
    }
    client_config: Optional[int] = field(default=None)
    output_config: Optional[AwsSagemakerAsyncInferenceOutputConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerPendingProductionVariantSummary:
    kind: ClassVar[str] = "aws_sagemaker_pending_production_variant_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "variant_name": S("VariantName"),
        "deployed_images": S("DeployedImages", default=[]) >> ForallBend(AwsSagemakerDeployedImage.mapping),
        "current_weight": S("CurrentWeight"),
        "desired_weight": S("DesiredWeight"),
        "current_instance_count": S("CurrentInstanceCount"),
        "desired_instance_count": S("DesiredInstanceCount"),
        "instance_type": S("InstanceType"),
        "accelerator_type": S("AcceleratorType"),
        "variant_status": S("VariantStatus", default=[]) >> ForallBend(AwsSagemakerProductionVariantStatus.mapping),
        "current_serverless_config": S("CurrentServerlessConfig")
        >> Bend(AwsSagemakerProductionVariantServerlessConfig.mapping),
        "desired_serverless_config": S("DesiredServerlessConfig")
        >> Bend(AwsSagemakerProductionVariantServerlessConfig.mapping),
    }
    variant_name: Optional[str] = field(default=None)
    deployed_images: List[AwsSagemakerDeployedImage] = field(factory=list)
    current_weight: Optional[float] = field(default=None)
    desired_weight: Optional[float] = field(default=None)
    current_instance_count: Optional[int] = field(default=None)
    desired_instance_count: Optional[int] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    accelerator_type: Optional[str] = field(default=None)
    variant_status: List[AwsSagemakerProductionVariantStatus] = field(factory=list)
    current_serverless_config: Optional[AwsSagemakerProductionVariantServerlessConfig] = field(default=None)
    desired_serverless_config: Optional[AwsSagemakerProductionVariantServerlessConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerPendingDeploymentSummary:
    kind: ClassVar[str] = "aws_sagemaker_pending_deployment_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "endpoint_config_name": S("EndpointConfigName"),
        "production_variants": S("ProductionVariants", default=[])
        >> ForallBend(AwsSagemakerPendingProductionVariantSummary.mapping),
        "start_time": S("StartTime"),
    }
    endpoint_config_name: Optional[str] = field(default=None)
    production_variants: List[AwsSagemakerPendingProductionVariantSummary] = field(factory=list)
    start_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerClarifyInferenceConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_inference_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "features_attribute": S("FeaturesAttribute"),
        "content_template": S("ContentTemplate"),
        "max_record_count": S("MaxRecordCount"),
        "max_payload_in_mb": S("MaxPayloadInMB"),
        "probability_index": S("ProbabilityIndex"),
        "label_index": S("LabelIndex"),
        "probability_attribute": S("ProbabilityAttribute"),
        "label_attribute": S("LabelAttribute"),
        "label_headers": S("LabelHeaders", default=[]),
        "feature_headers": S("FeatureHeaders", default=[]),
        "feature_types": S("FeatureTypes", default=[]),
    }
    features_attribute: Optional[str] = field(default=None)
    content_template: Optional[str] = field(default=None)
    max_record_count: Optional[int] = field(default=None)
    max_payload_in_mb: Optional[int] = field(default=None)
    probability_index: Optional[int] = field(default=None)
    label_index: Optional[int] = field(default=None)
    probability_attribute: Optional[str] = field(default=None)
    label_attribute: Optional[str] = field(default=None)
    label_headers: List[str] = field(factory=list)
    feature_headers: List[str] = field(factory=list)
    feature_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerClarifyShapBaselineConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_shap_baseline_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mime_type": S("MimeType"),
        "shap_baseline": S("ShapBaseline"),
        "shap_baseline_uri": S("ShapBaselineUri"),
    }
    mime_type: Optional[str] = field(default=None)
    shap_baseline: Optional[str] = field(default=None)
    shap_baseline_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerClarifyTextConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_text_config"
    mapping: ClassVar[Dict[str, Bender]] = {"language": S("Language"), "granularity": S("Granularity")}
    language: Optional[str] = field(default=None)
    granularity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerClarifyShapConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_shap_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "shap_baseline_config": S("ShapBaselineConfig") >> Bend(AwsSagemakerClarifyShapBaselineConfig.mapping),
        "number_of_samples": S("NumberOfSamples"),
        "use_logit": S("UseLogit"),
        "seed": S("Seed"),
        "text_config": S("TextConfig") >> Bend(AwsSagemakerClarifyTextConfig.mapping),
    }
    shap_baseline_config: Optional[AwsSagemakerClarifyShapBaselineConfig] = field(default=None)
    number_of_samples: Optional[int] = field(default=None)
    use_logit: Optional[bool] = field(default=None)
    seed: Optional[int] = field(default=None)
    text_config: Optional[AwsSagemakerClarifyTextConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerClarifyExplainerConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_explainer_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_explanations": S("EnableExplanations"),
        "inference_config": S("InferenceConfig") >> Bend(AwsSagemakerClarifyInferenceConfig.mapping),
        "shap_config": S("ShapConfig") >> Bend(AwsSagemakerClarifyShapConfig.mapping),
    }
    enable_explanations: Optional[str] = field(default=None)
    inference_config: Optional[AwsSagemakerClarifyInferenceConfig] = field(default=None)
    shap_config: Optional[AwsSagemakerClarifyShapConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerExplainerConfig:
    kind: ClassVar[str] = "aws_sagemaker_explainer_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "clarify_explainer_config": S("ClarifyExplainerConfig") >> Bend(AwsSagemakerClarifyExplainerConfig.mapping)
    }
    clarify_explainer_config: Optional[AwsSagemakerClarifyExplainerConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEndpoint(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_endpoint"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-endpoints", "Endpoints")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("EndpointName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("EndpointName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("EndpointArn"),
        "endpoint_config_name": S("EndpointConfigName"),
        "endpoint_production_variants": S("ProductionVariants", default=[])
        >> ForallBend(AwsSagemakerProductionVariantSummary.mapping),
        "endpoint_data_capture_config": S("DataCaptureConfig") >> Bend(AwsSagemakerDataCaptureConfigSummary.mapping),
        "endpoint_status": S("EndpointStatus"),
        "endpoint_failure_reason": S("FailureReason"),
        "endpoint_last_deployment_config": S("LastDeploymentConfig") >> Bend(AwsSagemakerDeploymentConfig.mapping),
        "endpoint_async_inference_config": S("AsyncInferenceConfig") >> Bend(AwsSagemakerAsyncInferenceConfig.mapping),
        "endpoint_pending_deployment_summary": S("PendingDeploymentSummary")
        >> Bend(AwsSagemakerPendingDeploymentSummary.mapping),
        "endpoint_explainer_config": S("ExplainerConfig") >> Bend(AwsSagemakerExplainerConfig.mapping),
    }
    endpoint_config_name: Optional[str] = field(default=None)
    endpoint_production_variants: List[AwsSagemakerProductionVariantSummary] = field(factory=list)
    endpoint_data_capture_config: Optional[AwsSagemakerDataCaptureConfigSummary] = field(default=None)
    endpoint_status: Optional[str] = field(default=None)
    endpoint_failure_reason: Optional[str] = field(default=None)
    endpoint_last_deployment_config: Optional[AwsSagemakerDeploymentConfig] = field(default=None)
    endpoint_async_inference_config: Optional[AwsSagemakerAsyncInferenceConfig] = field(default=None)
    endpoint_pending_deployment_summary: Optional[AwsSagemakerPendingDeploymentSummary] = field(default=None)
    endpoint_explainer_config: Optional[AwsSagemakerExplainerConfig] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for endpoint in json:
            endpoint_description = builder.client.get(
                "sagemaker", "describe-endpoint", None, EndpointName=endpoint["EndpointName"]
            )
            if endpoint_description:
                endpoint_instance = AwsSagemakerEndpoint.from_api(endpoint_description)
                builder.add_node(endpoint_instance, endpoint_description)


@define(eq=False, slots=False)
class AwsSagemakerImage(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_image"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-images", "Images")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ImageName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ImageName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ImageArn"),
        "image_description": S("Description"),
        "image_display_name": S("DisplayName"),
        "image_failure_reason": S("FailureReason"),
        "image_image_status": S("ImageStatus"),
        "image_role_arn": S("RoleArn"),
    }
    image_description: Optional[str] = field(default=None)
    image_display_name: Optional[str] = field(default=None)
    image_failure_reason: Optional[str] = field(default=None)
    image_image_status: Optional[str] = field(default=None)
    image_role_arn: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for image in json:
            image_description = builder.client.get("sagemaker", "describe-image", None, ImageName=image["ImageName"])
            if image_description:
                image_instance = AwsSagemakerImage.from_api(image_description)
                builder.add_node(image_instance, image_description)


@define(eq=False, slots=False)
class AwsSagemakerArtifactSourceType:
    kind: ClassVar[str] = "aws_sagemaker_artifact_source_type"
    mapping: ClassVar[Dict[str, Bender]] = {"source_id_type": S("SourceIdType"), "value": S("Value")}
    source_id_type: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerArtifactSource:
    kind: ClassVar[str] = "aws_sagemaker_artifact_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_uri": S("SourceUri"),
        "source_types": S("SourceTypes", default=[]) >> ForallBend(AwsSagemakerArtifactSourceType.mapping),
    }
    source_uri: Optional[str] = field(default=None)
    source_types: List[AwsSagemakerArtifactSourceType] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerArtifact(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_artifact"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-artifacts", "ArtifactSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ArtifactName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ArtifactName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ArtifactArn"),
        "artifact_source": S("Source") >> Bend(AwsSagemakerArtifactSource.mapping),
        "artifact_artifact_type": S("ArtifactType"),
        "artifact_properties": S("Properties"),
        "artifact_created_by": S("CreatedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "artifact_last_modified_by": S("LastModifiedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "artifact_metadata_properties": S("MetadataProperties") >> Bend(AwsSagemakerMetadataProperties.mapping),
        "artifact_lineage_group_arn": S("LineageGroupArn"),
    }
    artifact_source: Optional[AwsSagemakerArtifactSource] = field(default=None)
    artifact_artifact_type: Optional[str] = field(default=None)
    artifact_properties: Optional[Dict[str, str]] = field(default=None)
    artifact_created_by: Optional[AwsSagemakerUserContext] = field(default=None)
    artifact_last_modified_by: Optional[AwsSagemakerUserContext] = field(default=None)
    artifact_metadata_properties: Optional[AwsSagemakerMetadataProperties] = field(default=None)
    artifact_lineage_group_arn: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for artifact in json:
            artifact_description = builder.client.get(
                "sagemaker", "describe-artifact", None, ArtifactArn=artifact["ArtifactArn"]
            )
            if artifact_description:
                artifact_instance = AwsSagemakerArtifact.from_api(artifact_description)
                builder.add_node(artifact_instance, artifact_description)


@define(eq=False, slots=False)
class AwsSagemakerUserProfile(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_user_profile"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-user-profiles", "UserProfiles")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserProfileName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("UserProfileName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "user_profile_domain_id": S("DomainId"),
        "user_profile_status": S("Status"),
    }
    user_profile_domain_id: Optional[str] = field(default=None)
    user_profile_status: Optional[str] = field(default=None)


resources: List[Type[AwsResource]] = [
    AwsSagemakerNotebook,
    AwsSagemakerAlgorithm,
    AwsSagemakerModel,
    AwsSagemakerApp,
    AwsSagemakerDomain,
    AwsSagemakerExperiment,
    AwsSagemakerTrial,
    AwsSagemakerCodeRepository,
    AwsSagemakerEndpoint,
    AwsSagemakerImage,
    AwsSagemakerArtifact,
    AwsSagemakerUserProfile,
]
