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


resources: List[Type[AwsResource]] = [AwsSagemakerNotebook, AwsSagemakerAlgorithm]
