from datetime import datetime
from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type, Any
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.athena import AwsAthenaDataCatalog, AwsAthenaWorkGroup
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from fix_plugin_aws.resource.cloudwatch import AwsCloudwatchAlarm
from fix_plugin_aws.resource.cognito import AwsCognitoGroup, AwsCognitoUserPool
from fix_plugin_aws.resource.ec2 import AwsEc2NetworkInterface, AwsEc2SecurityGroup, AwsEc2Subnet, AwsEc2Vpc
from fix_plugin_aws.resource.iam import AwsIamRole
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.lambda_ import AwsLambdaFunction
from fix_plugin_aws.resource.redshift import AwsRedshiftCluster
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.resource.sns import AwsSnsTopic
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json import value_in_path
from fixlib.json_bender import S, Bend, Bender, ForallBend, bend
from fixlib.types import Json

service_name = "sagemaker"


class SagemakerTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="add-tags",
                result_name=None,
                ResourceArn=self.arn,
                Tags=[{"Key": key, "Value": value}],
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="delete-tags",
                result_name=None,
                ResourceArn=self.arn,
                TagKeys=[key],
            )
            return True
        return False

    @staticmethod
    def add_tags(resource: AwsResource, builder: GraphBuilder) -> None:
        tags = builder.client.list(
            service_name,
            "list-tags",
            "Tags",
            ResourceArn=resource.arn,
        )
        if tags:
            resource.tags = bend(ToDict(), tags)

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "add-tags"),
            AwsApiSpec(service_name, "delete-tags"),
        ]


@define(eq=False, slots=False)
class AwsSagemakerNotebook(SagemakerTaggable, AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_notebook"
    kind_display: ClassVar[str] = "AWS SageMaker Notebook"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:notebook/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Notebooks are a fully managed service by AWS that provides a"
        " Jupyter notebook environment for data scientists and developers to build,"
        " train, and deploy machine learning models."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_ec2_subnet", "aws_ec2_security_group", "aws_iam_role", "aws_sagemaker_code_repository"],
            "delete": [
                "aws_iam_role",
                "aws_kms_key",
                "aws_ec2_network_interface",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
            ],
        },
        "successors": {
            "default": ["aws_kms_key", "aws_ec2_network_interface"],
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-notebook-instances", "NotebookInstances")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NotebookInstanceName"),
        "name": S("NotebookInstanceName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("NotebookInstanceArn"),
        "notebook_instance_status": S("NotebookInstanceStatus"),
        "notebook_failure_reason": S("FailureReason"),
        "notebook_url": S("Url"),
        "notebook_instance_type": S("InstanceType"),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-notebook-instance"),
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for notebook in json:
            notebook_description = builder.client.get(
                service_name, "describe-notebook-instance", None, NotebookInstanceName=notebook["NotebookInstanceName"]
            )
            if notebook_description and (
                notebook_instance := AwsSagemakerNotebook.from_api(notebook_description, builder)
            ):
                builder.add_node(notebook_instance, notebook_description)
                builder.submit_work(service_name, SagemakerTaggable.add_tags, notebook_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if subnet := value_in_path(source, "SubnetId"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet)
        if security_groups := value_in_path(source, "SecurityGroups"):
            for security_group in security_groups:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if key := value_in_path(source, "KmsKeyId"):
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(key))
        if nw_interface := value_in_path(source, "NetworkInterfaceId"):
            builder.dependant_node(self, clazz=AwsEc2NetworkInterface, id=nw_interface)
        code_repos = [self.notebook_default_code_repository] + self.notebook_additional_code_repositories
        for repo in code_repos:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerCodeRepository, name=repo)

    def pre_delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(service_name, "stop-notebook-instance", result_name=None, NotebookInstanceName=self.name)
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        if self.notebook_instance_status == "Stopped":
            client.call(
                aws_service=self.api_spec.service,
                action="delete-notebook-instance",
                result_name=None,
                NotebookInstanceName=self.name,
            )
            return True
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-notebook-instance")]


@define(eq=False, slots=False)
class AwsSagemakerParameterRangeSpecification:
    kind: ClassVar[str] = "aws_sagemaker_integer_parameter_range_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Integer Parameter Range Specification"
    kind_description: ClassVar[str] = (
        "The Integer Parameter Range Specification is a configuration option in AWS"
        " SageMaker that allows users to define a range of integer values for a"
        " hyperparameter when training machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"min_value": S("MinValue"), "max_value": S("MaxValue")}
    min_value: Optional[str] = field(default=None)
    max_value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerParameterRange:
    kind: ClassVar[str] = "aws_sagemaker_parameter_range"
    kind_display: ClassVar[str] = "AWS SageMaker Parameter Range"
    kind_description: ClassVar[str] = (
        "SageMaker Parameter Range is a feature of Amazon SageMaker that allows you"
        " to define the range of values for hyperparameters in your machine learning"
        " models, enabling you to fine-tune the performance of your models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "integer_parameter_range_specification": S("IntegerParameterRangeSpecification")
        >> Bend(AwsSagemakerParameterRangeSpecification.mapping),
        "continuous_parameter_range_specification": S("ContinuousParameterRangeSpecification")
        >> Bend(AwsSagemakerParameterRangeSpecification.mapping),
        "categorical_parameter_range_specification": S("CategoricalParameterRangeSpecification", "Values", default=[]),
    }
    integer_parameter_range_specification: Optional[AwsSagemakerParameterRangeSpecification] = field(default=None)
    continuous_parameter_range_specification: Optional[AwsSagemakerParameterRangeSpecification] = field(default=None)
    categorical_parameter_range_specification: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterSpecification:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Hyper Parameter Specification"
    kind_description: ClassVar[str] = (
        "SageMaker Hyper Parameter Specification is used to define a set of"
        " hyperparameters for training machine learning models with Amazon SageMaker,"
        " which is a fully-managed service that enables users to build, train, and"
        " deploy machine learning models at scale."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Metric Definition"
    kind_description: ClassVar[str] = (
        "SageMaker Metric Definitions are custom metrics that can be used to monitor"
        " and evaluate the performance of machine learning models trained on Amazon"
        " SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "regex": S("Regex")}
    name: Optional[str] = field(default=None)
    regex: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerChannelSpecification:
    kind: ClassVar[str] = "aws_sagemaker_channel_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Channel Specification"
    kind_description: ClassVar[str] = (
        "Sagemaker Channel Specifications are used to define the input data for a"
        " SageMaker training job, including the S3 location of the data and any data"
        " preprocessing configuration."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Hyperparameter Tuning Job Objective"
    kind_description: ClassVar[str] = (
        "The objective of a hyperparameter tuning job in Amazon SageMaker is to"
        " optimize machine learning models by searching for the best combination of"
        " hyperparameters to minimize or maximize a specific metric."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "metric_name": S("MetricName")}
    type: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrainingSpecification:
    kind: ClassVar[str] = "aws_sagemaker_training_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Training Specification"
    kind_description: ClassVar[str] = (
        "SageMaker Training Specification is a resource in AWS that provides the"
        " configuration details for training a machine learning model using Amazon"
        " SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Model Package Container Definition"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Model Package Container Definition is a configuration that"
        " describes how to run a machine learning model as a container in Amazon"
        " SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Inference Specification"
    kind_description: ClassVar[str] = (
        "SageMaker Inference Specification is a specification file that defines the"
        " input and output formats for deploying machine learning models on Amazon"
        " SageMaker for making predictions."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker S3 Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker S3 Data Source is a cloud resource in Amazon SageMaker that allows"
        " users to access and process data stored in Amazon S3 for machine learning"
        " tasks."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker File System Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker File System Data Source is a resource in AWS SageMaker that"
        " provides access to data stored in an Amazon Elastic File System (EFS) from"
        " your machine learning training job or processing job."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker Data Source is a resource in Amazon SageMaker that allows users to"
        " easily access and manage their data for machine learning tasks."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource") >> Bend(AwsSagemakerS3DataSource.mapping),
        "file_system_data_source": S("FileSystemDataSource") >> Bend(AwsSagemakerFileSystemDataSource.mapping),
    }
    s3_data_source: Optional[AwsSagemakerS3DataSource] = field(default=None)
    file_system_data_source: Optional[AwsSagemakerFileSystemDataSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerChannel:
    kind: ClassVar[str] = "aws_sagemaker_channel"
    kind_display: ClassVar[str] = "AWS SageMaker Channel"
    kind_description: ClassVar[str] = (
        "SageMaker Channels are data sources used for training machine learning"
        " models on Amazon SageMaker. They can be used to securely stream and"
        " preprocess data from various sources."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Output Data Config"
    kind_description: ClassVar[str] = (
        "SageMaker Output Data Config is a feature of Amazon SageMaker that allows"
        " users to specify where the output data from a training job should be stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"kms_key_id": S("KmsKeyId"), "s3_output_path": S("S3OutputPath")}
    kms_key_id: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerInstanceGroup:
    kind: ClassVar[str] = "aws_sagemaker_instance_group"
    kind_display: ClassVar[str] = "AWS SageMaker Instance Group"
    kind_description: ClassVar[str] = (
        "SageMaker Instance Groups are a collection of EC2 instances used for"
        " training and deploying machine learning models with Amazon SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Resource Config"
    kind_description: ClassVar[str] = (
        "SageMaker Resource Config is a configuration for AWS SageMaker, a fully"
        " managed machine learning service provided by Amazon Web Services, which"
        " allows users to build, train, and deploy machine learning models at scale."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Stopping Condition"
    kind_description: ClassVar[str] = (
        "Stopping condition for an AWS SageMaker training job, which defines the"
        " criteria for stopping the training process based on time, accuracy, or other"
        " metrics."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_runtime_in_seconds": S("MaxRuntimeInSeconds"),
        "max_wait_time_in_seconds": S("MaxWaitTimeInSeconds"),
    }
    max_runtime_in_seconds: Optional[int] = field(default=None)
    max_wait_time_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrainingJobDefinition:
    kind: ClassVar[str] = "aws_sagemaker_training_job_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Training Job Definition"
    kind_description: ClassVar[str] = (
        "SageMaker Training Job Definition is a configuration that specifies how a"
        " machine learning model should be trained using Amazon SageMaker, which is a"
        " fully-managed service that enables developers and data scientists to build,"
        " train, and deploy machine learning models quickly and easily."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Transform S3 Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker Transform S3 Data Source is a data source used in Amazon SageMaker"
        " to specify the location of the input data that needs to be transformed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"s3_data_type": S("S3DataType"), "s3_uri": S("S3Uri")}
    s3_data_type: Optional[str] = field(default=None)
    s3_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformDataSource:
    kind: ClassVar[str] = "aws_sagemaker_transform_data_source"
    kind_display: ClassVar[str] = "AWS SageMaker Transform Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker Transform Data Source is a resource in AWS SageMaker that provides"
        " the input data for a batch transform job, allowing users to preprocess and"
        " transform large datasets efficiently."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource") >> Bend(AwsSagemakerTransformS3DataSource.mapping)
    }
    s3_data_source: Optional[AwsSagemakerTransformS3DataSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformInput:
    kind: ClassVar[str] = "aws_sagemaker_transform_input"
    kind_display: ClassVar[str] = "AWS SageMaker Transform Input"
    kind_description: ClassVar[str] = (
        "SageMaker Transform Input is a resource in the AWS SageMaker service that"
        " represents input data for batch transform jobs. It is used to provide the"
        " data that needs to be processed by machine learning models."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Transform Output"
    kind_description: ClassVar[str] = (
        "SageMaker Transform Output is the result of a machine learning"
        " transformation job in Amazon SageMaker. It is the processed data generated"
        " by applying a trained model to input data."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Transform Resources"
    kind_description: ClassVar[str] = (
        "SageMaker Transform Resources are used in Amazon SageMaker for creating"
        " machine learning workflows to preprocess and transform data before making"
        " predictions or inferences."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Transform Job Definition"
    kind_description: ClassVar[str] = (
        "SageMaker Transform Job Definition is a configuration that defines how data"
        " transformation should be performed on input data using Amazon SageMaker's"
        " built-in algorithms or custom models."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Algorithm Validation Profile"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Algorithm Validation Profile is a configuration tool in AWS SageMaker"
        " that helps ensure your machine learning algorithms function correctly before deployment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "profile_name": S("ProfileName"),
        "training_job_definition": S("TrainingJobDefinition") >> Bend(AwsSagemakerTrainingJobDefinition.mapping),
        "transform_job_definition": S("TransformJobDefinition") >> Bend(AwsSagemakerTransformJobDefinition.mapping),
    }
    profile_name: Optional[str] = field(default=None)
    training_job_definition: Optional[AwsSagemakerTrainingJobDefinition] = field(default=None)
    transform_job_definition: Optional[AwsSagemakerTransformJobDefinition] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmStatusItem:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_status_item"
    kind_display: ClassVar[str] = "AWS SageMaker Algorithm Status Item"
    kind_description: ClassVar[str] = (
        "SageMaker Algorithm Status Item is a resource in AWS SageMaker that"
        " represents the status of an algorithm used for machine learning tasks."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Algorithm Status Details"
    kind_description: ClassVar[str] = (
        "SageMaker algorithm status details provide information about the status and"
        " progress of algorithms running on Amazon SageMaker, a fully managed machine"
        " learning service."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Algorithm"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:algorithm/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Algorithms are pre-built machine learning algorithms provided by"
        " Amazon SageMaker, which can be used to train and deploy predictive models."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_iam_role"], "delete": ["aws_iam_role"]}
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-algorithms", "AlgorithmSummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AlgorithmName"),
        "name": S("AlgorithmName"),
        "ctime": S("CreationTime"),
        "arn": S("AlgorithmArn"),
        "algorithm_description": S("AlgorithmDescription"),
        "algorithm_training_specification": S("TrainingSpecification")
        >> Bend(AwsSagemakerTrainingSpecification.mapping),
        "algorithm_inference_specification": S("InferenceSpecification")
        >> Bend(AwsSagemakerInferenceSpecification.mapping),
        "algorithm_validation_profiles": S("ValidationSpecification", "ValidationProfiles", default=[]),
        "algorithm_status": S("AlgorithmStatus"),
        "algorithm_status_details": S("AlgorithmStatusDetails") >> Bend(AwsSagemakerAlgorithmStatusDetails.mapping),
        "algorithm_product_id": S("ProductId"),
        "algorithm_certify_for_marketplace": S("CertifyForMarketplace"),
    }
    algorithm_description: Optional[str] = field(default=None)
    algorithm_training_specification: Optional[AwsSagemakerTrainingSpecification] = field(default=None)
    algorithm_inference_specification: Optional[AwsSagemakerInferenceSpecification] = field(default=None)
    algorithm_validation_profiles: List[AwsSagemakerAlgorithmValidationProfile] = field(factory=list)
    algorithm_status: Optional[str] = field(default=None)
    algorithm_status_details: Optional[AwsSagemakerAlgorithmStatusDetails] = field(default=None)
    algorithm_product_id: Optional[str] = field(default=None)
    algorithm_certify_for_marketplace: Optional[bool] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-algorithm")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for algorithm in json:
            algorithm_description = builder.client.get(
                service_name, "describe-algorithm", None, AlgorithmName=algorithm["AlgorithmName"]
            )
            if algorithm_description:
                if algorithm_instance := AwsSagemakerAlgorithm.from_api(algorithm_description, builder):
                    builder.add_node(algorithm_instance, algorithm_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if validation_role := value_in_path(source, ["ValidationSpecification", "ValidationRole"]):
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=validation_role
            )

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-algorithm", result_name=None, AlgorithmName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-algorithm")]


@define(eq=False, slots=False)
class AwsSagemakerImageConfig:
    kind: ClassVar[str] = "aws_sagemaker_image_config"
    kind_display: ClassVar[str] = "AWS SageMaker Image Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker Image Configuration is a resource in AWS SageMaker that allows you"
        " to define and package custom ML environments for training and inference."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "repository_access_mode": S("RepositoryAccessMode"),
        "repository_auth_config": S("RepositoryAuthConfig", "RepositoryCredentialsProviderArn"),
    }
    repository_access_mode: Optional[str] = field(default=None)
    repository_auth_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerContainerDefinition:
    kind: ClassVar[str] = "aws_sagemaker_container_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Container Definition"
    kind_description: ClassVar[str] = (
        "SageMaker Container Definition is a resource in AWS that allows you to"
        " define the container image and resources required to run your machine"
        " learning model in Amazon SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker VPC Config"
    kind_description: ClassVar[str] = (
        "SageMaker VPC Config is a configuration option in Amazon SageMaker that"
        " allows users to specify the VPC (Virtual Private Cloud) settings for"
        " training and deploying machine learning models in a private network"
        " environment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("SecurityGroupIds", default=[]),
        "subnets": S("Subnets", default=[]),
    }
    security_group_ids: List[str] = field(factory=list)
    subnets: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerModel(SagemakerTaggable, AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_model"
    kind_display: ClassVar[str] = "AWS SageMaker Model"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:model/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Models are machine learning models built and trained using Amazon"
        " SageMaker, a fully-managed machine learning service by Amazon Web Services."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
            "delete": ["aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_s3_bucket"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-models", "Models")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ModelName"),
        "name": S("ModelName"),
        "ctime": S("CreationTime"),
        "arn": S("ModelArn"),
        "model_primary_container": S("PrimaryContainer") >> Bend(AwsSagemakerContainerDefinition.mapping),
        "model_containers": S("Containers", default=[]) >> ForallBend(AwsSagemakerContainerDefinition.mapping),
        "model_inference_execution_config": S("InferenceExecutionConfig", "Mode"),
        "model_vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
        "model_enable_network_isolation": S("EnableNetworkIsolation"),
    }
    model_primary_container: Optional[AwsSagemakerContainerDefinition] = field(default=None)
    model_containers: List[AwsSagemakerContainerDefinition] = field(factory=list)
    model_inference_execution_config: Optional[str] = field(default=None)
    model_vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)
    model_enable_network_isolation: Optional[bool] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-model"), AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for model in json:
            if model_description := builder.client.get(
                service_name, "describe-model", None, ModelName=model["ModelName"]
            ):
                if model_instance := AwsSagemakerModel.from_api(model_description, builder):
                    builder.add_node(model_instance, model_description)
                    builder.submit_work(service_name, SagemakerTaggable.add_tags, model_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        model_data_buckets = [container.model_data_url for container in self.model_containers]
        if self.model_primary_container:
            model_data_buckets.append(self.model_primary_container.model_data_url)
        for bucket in model_data_buckets:
            if bucket:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(bucket))
        if role_arn := value_in_path(source, "ExecutionRoleArn"):
            builder.dependant_node(self, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if self.model_vpc_config:
            for security_group in self.model_vpc_config.security_group_ids:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
            for subnet in self.model_vpc_config.subnets:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-model", result_name=None, ModelName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-model")]


@define(eq=False, slots=False)
class AwsSagemakerResourceSpec:
    kind: ClassVar[str] = "aws_sagemaker_resource_spec"
    kind_display: ClassVar[str] = "AWS SageMaker Resource Spec"
    kind_description: ClassVar[str] = (
        "SageMaker Resource Spec is a specification for configuring the compute"
        " resources used in Amazon SageMaker for machine learning model training and"
        " deployment."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker App"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:app/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "The AWS SageMaker App facilitates the creation and management of machine learning applications, enabling"
        " users to engage in interactive model building and analysis. It provides a user-centric, customizable"
        " workspace, complete with monitoring of app health and activity."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_sagemaker_domain", "aws_sagemaker_user_profile"],
        },
        "successors": {"default": ["aws_sagemaker_image"], "delete": ["aws_sagemaker_user_profile"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-apps", "Apps")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AppName"),
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

    def _keys(self) -> tuple[str, str, str, str, str, str, Optional[str], Optional[str]]:
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.id,
            self.name,
            self.app_user_profile_name,
        )

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-app")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for app in json:
            # Don't collect Apps that are deleted
            if app.get("AppStatus") == "Deleted":
                continue
            elif app["UserProfileName"]:
                app_description = builder.client.get(
                    service_name,
                    "describe-app",
                    None,
                    UserProfileName=app["UserProfileName"],
                    DomainId=app["DomainId"],
                    AppType=app["AppType"],
                    AppName=app["AppName"],
                )
            elif app["SpaceName"]:
                app_description = builder.client.get(
                    service_name,
                    "describe-app",
                    None,
                    SpaceName=app["SpaceName"],
                    DomainId=app["DomainId"],
                    AppType=app["AppType"],
                    AppName=app["AppName"],
                )
            else:
                app_description = None
            if app_description:
                if app_instance := AwsSagemakerApp.from_api(app_description, builder):
                    builder.add_node(app_instance, app_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if domain := self.app_domain_id:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=domain)
        if image := value_in_path(source, ["ResourceSpec", "SageMakerImageArn"]):
            builder.add_edge(self, clazz=AwsSagemakerImage, arn=image)
        if user := self.app_user_profile_name:
            builder.dependant_node(self, reverse=True, clazz=AwsSagemakerUserProfile, name=user)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-app",
            result_name=None,
            DomainId=self.app_domain_id,
            AppType=self.app_type,
            AppName=self.name,
            UserProfileName=self.app_user_profile_name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-app")]


@define(eq=False, slots=False)
class AwsSagemakerSharingSettings:
    kind: ClassVar[str] = "aws_sagemaker_sharing_settings"
    kind_display: ClassVar[str] = "AWS SageMaker Sharing Settings"
    kind_description: ClassVar[str] = (
        "SageMaker Sharing Settings allow users to share their Amazon SageMaker"
        " resources, such as notebooks and training jobs, with other users or AWS"
        " accounts."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Jupyter Server App Settings"
    kind_description: ClassVar[str] = (
        "SageMaker Jupyter Server App Settings is a feature in AWS SageMaker that"
        " allows you to configure and customize the settings of your Jupyter server"
        " for machine learning development and training."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "lifecycle_config_arns": S("LifecycleConfigArns", default=[]),
        "code_repositories": S("CodeRepositories", default=[]),
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    lifecycle_config_arns: List[str] = field(factory=list)
    code_repositories: List[Dict[str, str]] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerCustomImage:
    kind: ClassVar[str] = "aws_sagemaker_custom_image"
    kind_display: ClassVar[str] = "AWS SageMaker Custom Image"
    kind_description: ClassVar[str] = (
        "SageMaker Custom Images allow you to create and manage custom machine"
        " learning images for Amazon SageMaker, providing a pre-configured environment"
        " for training and deploying machine learning models."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Kernel Gateway App Settings"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Kernel Gateway App Settings allows customization and optimization of the compute environment"
        " for Jupyter kernels, including specifying lifecycle configurations and using custom images."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Tensor Board App Settings"
    kind_description: ClassVar[str] = (
        "SageMaker Tensor Board App Settings is a feature provided by Amazon"
        " SageMaker to configure and customize the settings for TensorBoard, a"
        " visualization tool for training and testing machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping)
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRStudioServerProAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_r_studio_server_pro_app_settings"
    kind_display: ClassVar[str] = "AWS SageMaker RStudio Server Pro App Settings"
    kind_description: ClassVar[str] = (
        "SageMaker RStudio Server Pro App Settings is a feature in AWS SageMaker that"
        " allows configuring application settings for RStudio Server Pro, an"
        " integrated development environment for R programming language, running on"
        " SageMaker instances."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"access_status": S("AccessStatus"), "user_group": S("UserGroup")}
    access_status: Optional[str] = field(default=None)
    user_group: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRSessionAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_r_session_app_settings"
    kind_display: ClassVar[str] = "AWS SageMaker R Session App Settings"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker R Session App Settings facilitate the configuration of default resources and"
        " the use of custom images for R sessions within SageMaker Studio."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "default_resource_spec": S("DefaultResourceSpec") >> Bend(AwsSagemakerResourceSpec.mapping),
        "custom_images": S("CustomImages", default=[]) >> ForallBend(AwsSagemakerCustomImage.mapping),
    }
    default_resource_spec: Optional[AwsSagemakerResourceSpec] = field(default=None)
    custom_images: List[AwsSagemakerCustomImage] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerTimeSeriesForecastingSettings:
    kind: ClassVar[str] = "aws_sagemaker_time_series_forecasting_settings"
    kind_display: ClassVar[str] = "AWS SageMaker Time Series Forecasting Settings"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Time Series Forecasting Settings provide configurations and"
        " options for training time series forecasting models on Amazon SageMaker"
        " platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "amazon_forecast_role_arn": S("AmazonForecastRoleArn"),
    }
    status: Optional[str] = field(default=None)
    amazon_forecast_role_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCanvasAppSettings:
    kind: ClassVar[str] = "aws_sagemaker_canvas_app_settings"
    kind_display: ClassVar[str] = "AWS SageMaker Canvas App Settings"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Canvas App Settings facilitate the configuration of time series"
        " forecasting features within the SageMaker Canvas visual data preparation tool."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "time_series_forecasting_settings": S("TimeSeriesForecastingSettings")
        >> Bend(AwsSagemakerTimeSeriesForecastingSettings.mapping)
    }
    time_series_forecasting_settings: Optional[AwsSagemakerTimeSeriesForecastingSettings] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUserSettings:
    kind: ClassVar[str] = "aws_sagemaker_user_settings"
    kind_display: ClassVar[str] = "AWS SageMaker User Settings"
    kind_description: ClassVar[str] = (
        "SageMaker User Settings allows users to configure personal settings for"
        " Amazon SageMaker, a machine learning service provided by Amazon Web"
        " Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "execution_role": S("ExecutionRole"),
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
    kind_display: ClassVar[str] = "AWS SageMaker R Studio Server Pro Domain Settings"
    kind_description: ClassVar[str] = (
        "AWS SageMaker R Studio Server Pro Domain Settings are used to configure the execution role and set URLs for"
        " RStudio Connect and RStudio Package Manager within a domain, as well as to specify the default resources"
        " for the domain."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Domain Settings"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Domain Settings define the specific configurations and behaviors within a SageMaker Domain."
        " These settings can include the configuration for RStudio Server (a popular integrated development"
        " environment for R), security settings, and resource management policies. "
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Default Space Settings"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Default Space Settings are used to configure default workspace environments"
        " in SageMaker, encompassing aspects such as access, security, and operational behaviors for user workspaces."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Domain"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/sagemaker/home?region={region}#/studio/{id}", "arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:domain/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "A SageMaker Domain in AWS is a dedicated, managed environment within Amazon SageMaker that provides"
        " data scientists and developers with the necessary tools and permissions to build, train, and deploy"
        " machine learning models."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_iam_role",
                "aws_ec2_subnet",
                "aws_ec2_security_group",
                "aws_sagemaker_code_repository",
                "aws_ec2_vpc",
            ],
            "delete": ["aws_iam_role", "aws_ec2_vpc", "aws_kms_key", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_s3_bucket", "aws_sagemaker_image", "aws_kms_key"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-domains", "Domains")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DomainId"),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-domain")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for domain in json:
            domain_description = builder.client.get(
                service_name,
                "describe-domain",
                None,
                DomainId=domain["DomainId"],
            )
            if domain_description:
                if domain_instance := AwsSagemakerDomain.from_api(domain_description, builder):
                    builder.add_node(domain_instance, domain_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if dus := self.domain_default_user_settings:
            if dus.execution_role:
                builder.dependant_node(
                    self,
                    reverse=True,
                    delete_same_as_default=True,
                    clazz=AwsIamRole,
                    arn=self.domain_default_user_settings.execution_role,
                )
            if security_groups := value_in_path(source, ["DefaultUserSettings", "SecurityGroups"]):
                for security_group in security_groups:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                    )
            if shs := dus.sharing_settings:
                if shs.s3_output_path:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(shs.s3_output_path))
            if jup := dus.jupyter_server_app_settings:
                if drs := jup.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)
                for url in [repo["RepositoryUrl"] for repo in jup.code_repositories]:
                    builder.add_edge(self, reverse=True, clazz=AwsSagemakerCodeRepository, code_repository_url=url)
            if kgs := dus.kernel_gateway_app_settings:
                if drs := kgs.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)
            if tbs := dus.tensor_board_app_settings:
                if drs := tbs.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)
            if rsas := dus.r_session_app_settings:
                if drs := rsas.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)
            if cas := dus.canvas_app_settings:
                if tsf := cas.time_series_forecasting_settings:
                    if tsf.amazon_forecast_role_arn:
                        builder.dependant_node(
                            self,
                            reverse=True,
                            delete_same_as_default=True,
                            clazz=AwsIamRole,
                            arn=tsf.amazon_forecast_role_arn,
                        )

        if self.domain_home_efs_file_system_kms_key_id:
            builder.dependant_node(
                self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(self.domain_home_efs_file_system_kms_key_id)
            )
        for subnet in self.domain_subnet_ids:
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet)
        if self.domain_vpc_id:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=self.domain_vpc_id
            )
        if self.domain_kms_key_id:
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(self.domain_kms_key_id))

        if ds := self.domain_settings:
            for security_group in ds.security_group_ids:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
            if rss := ds.r_studio_server_pro_domain_settings:
                if rss.domain_execution_role_arn:
                    builder.dependant_node(
                        self,
                        reverse=True,
                        delete_same_as_default=True,
                        clazz=AwsIamRole,
                        arn=rss.domain_execution_role_arn,
                    )
                if drs := rss.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)

        if dss := self.domain_default_space_settings:
            if dss.execution_role:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=dss.execution_role
                )
            for security_group in dss.security_groups:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
            if jup := dss.jupyter_server_app_settings:
                if drs := jup.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)
                    for url in [repo["RepositoryUrl"] for repo in jup.code_repositories]:
                        builder.add_edge(self, reverse=True, clazz=AwsSagemakerCodeRepository, code_repository_url=url)
            if kgs := dss.kernel_gateway_app_settings:
                if drs := kgs.default_resource_spec:
                    if drs.sage_maker_image_arn:
                        builder.add_edge(self, clazz=AwsSagemakerImage, arn=drs.sage_maker_image_arn)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-domain", result_name=None, DomainId=self.id)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-domain")]


@define(eq=False, slots=False)
class AwsSagemakerExperimentSource:
    kind: ClassVar[str] = "aws_sagemaker_experiment_source"
    kind_display: ClassVar[str] = "AWS SageMaker Experiment Source"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Experiment Source tracks the origin and type of SageMaker resources,"
        " that contribute to a machine learning experiment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"source_arn": S("SourceArn"), "source_type": S("SourceType")}
    source_arn: Optional[str] = field(default=None)
    source_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerExperiment(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_experiment"
    kind_display: ClassVar[str] = "AWS SageMaker Experiment"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:experiment/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Experiment is a service in AWS that enables users to organize,"
        " track and compare machine learning experiments and their associated"
        " resources."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-experiments", "ExperimentSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ExperimentName"),
        "name": S("ExperimentName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ExperimentArn"),
        "experiment_display_name": S("DisplayName"),
        "experiment_source": S("ExperimentSource") >> Bend(AwsSagemakerExperimentSource.mapping),  # a job?
    }
    experiment_display_name: Optional[str] = field(default=None)
    experiment_source: Optional[AwsSagemakerExperimentSource] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-experiment", result_name=None, ExperimentName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-experiment")]


@define(eq=False, slots=False)
class AwsSagemakerTrialSource:
    kind: ClassVar[str] = "aws_sagemaker_trial_source"
    kind_display: ClassVar[str] = "AWS SageMaker Trial Source"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Trial Source defines the origin and type of a trial's data source,"
        " typically an ARN, indicating where the trial data is stored and what kind of data source it is."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"source_arn": S("SourceArn"), "source_type": S("SourceType")}
    source_arn: Optional[str] = field(default=None)
    source_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUserContext:
    kind: ClassVar[str] = "aws_sagemaker_user_context"
    kind_display: ClassVar[str] = "AWS SageMaker User Context"
    kind_description: ClassVar[str] = (
        "SageMaker User Context provides information and settings for an individual"
        " user's SageMaker environment in the AWS cloud."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Metadata Properties"
    kind_description: ClassVar[str] = (
        "SageMaker Metadata Properties provide a way to store additional metadata"
        " about machine learning models trained using Amazon SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "commit_id": S("CommitId"),
        "generated_by": S("GeneratedBy"),
    }
    commit_id: Optional[str] = field(default=None)
    generated_by: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrial(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_trial"
    kind_display: ClassVar[str] = "AWS SageMaker Trial"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:trial/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS SageMaker Trial represents a series of steps, known as trial components, which lead to the creation of"
        " a machine learning model. It is nested within a single SageMaker experiment for organizational"
        " and tracking purposes."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_sagemaker_experiment",
                "aws_sagemaker_user_profile",
                "aws_sagemaker_domain",
                "aws_sagemaker_code_repository",
                "aws_sagemaker_project",
            ],
        }
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-trials", "TrialSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TrialName"),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-trial")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for trial in json:
            trial_description = builder.client.get(
                service_name,
                "describe-trial",
                None,
                TrialName=trial["TrialName"],
            )
            if trial_description:
                if trial_instance := AwsSagemakerTrial.from_api(trial_description, builder):
                    builder.add_node(trial_instance, trial_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.trial_experiment_name:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerExperiment, name=self.trial_experiment_name)
        if c := self.trial_created_by:
            if c.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=c.user_profile_name)
            if c.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=c.domain_id)
        if m := self.trial_last_modified_by:
            if m.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=m.user_profile_name)
            if m.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=m.domain_id)
        if repository := value_in_path(source, ["MetadataProperties", "Repository"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerCodeRepository, name=repository)
            if project_id := value_in_path(source, ["MetadataProperties", "ProjectId"]):
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerProject, id=project_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-trial", result_name=None, TrialName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-trial")]


@define(eq=False, slots=False)
class AwsSagemakerProject(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_project"
    kind_display: ClassVar[str] = "AWS SageMaker Project"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:project/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Projects in AWS provide a collaborative environment for machine"
        " learning teams to manage and track their ML workflows, datasets, models, and"
        " code."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-projects", "ProjectSummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ProjectId"),
        "name": S("ProjectName"),
        "ctime": S("CreationTime"),
        "project_description": S("ProjectDescription"),
        "arn": S("ProjectArn"),
        "project_status": S("ProjectStatus"),
    }
    project_description: Optional[str] = field(default=None)
    arn: Optional[str] = field(default=None)
    project_status: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-project", result_name=None, ProjectName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-project")]


@define(eq=False, slots=False)
class AwsSagemakerGitConfig:
    kind: ClassVar[str] = "aws_sagemaker_git_config"
    kind_display: ClassVar[str] = "AWS SageMaker Git Config"
    kind_description: ClassVar[str] = (
        "SageMaker Git Config is a resource in AWS SageMaker that allows users to"
        " configure Git repositories for their machine learning projects."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "branch": S("Branch"),
        "secret_arn": S("SecretArn"),
    }
    repository_url: Optional[str] = field(default=None)
    branch: Optional[str] = field(default=None)
    secret_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCodeRepository(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_code_repository"
    kind_display: ClassVar[str] = "AWS SageMaker Code Repository"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:code-repository/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Code Repository is a managed Git-based code repository for storing and versioning"
        " your machine learning code, making it easy to maintain and share code within your SageMaker projects."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-code-repositories", "CodeRepositorySummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CodeRepositoryName"),
        "name": S("CodeRepositoryName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("CodeRepositoryArn"),
        "code_repository_url": S("GitConfig", "RepositoryUrl"),
        "code_repository_git_config": S("GitConfig") >> Bend(AwsSagemakerGitConfig.mapping),
    }
    code_repository_git_config: Optional[AwsSagemakerGitConfig] = field(default=None)
    code_repository_url: Optional[str] = field(default=None)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-code-repository",
            result_name=None,
            CodeRepositoryName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-code-repository")]


@define(eq=False, slots=False)
class AwsSagemakerDeployedImage:
    kind: ClassVar[str] = "aws_sagemaker_deployed_image"
    kind_display: ClassVar[str] = "AWS SageMaker Deployed Image"
    kind_description: ClassVar[str] = (
        "An image that has been deployed and is used for running machine learning models on Amazon SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Production Variant Status"
    kind_description: ClassVar[str] = (
        "SageMaker Production Variant Status represents the status of a production"
        " variant in Amazon SageMaker, which is a fully managed service that enables"
        " developers to build, train, and deploy machine learning models at scale."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Production Variant Serverless Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Production Variant Serverless Config is a configuration that specifies the memory"
        " allocation and the maximum number of concurrent invocations for a serverless deployment of a"
        " SageMaker model variant."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "memory_size_in_mb": S("MemorySizeInMB"),
        "max_concurrency": S("MaxConcurrency"),
    }
    memory_size_in_mb: Optional[int] = field(default=None)
    max_concurrency: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProductionVariantSummary:
    kind: ClassVar[str] = "aws_sagemaker_production_variant_summary"
    kind_display: ClassVar[str] = "AWS SageMaker Production Variant Summary"
    kind_description: ClassVar[str] = (
        "SageMaker Production Variant Summary provides an overview of the production"
        " variants in Amazon SageMaker, which are used for deploying ML models and"
        " serving predictions at scale."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Data Capture Config Summary"
    kind_description: ClassVar[str] = (
        "SageMaker Data Capture Config Summary provides a summary of the"
        " configuration settings for data capture in Amazon SageMaker, which enables"
        " you to continuously capture input and output data from your SageMaker"
        " endpoints for further analysis and monitoring."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Capacity Size"
    kind_description: ClassVar[str] = (
        "SageMaker Capacity Size refers to the amount of computing resources"
        " available for running machine learning models on Amazon SageMaker, a fully-"
        " managed service for building, training, and deploying machine learning"
        " models at scale."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "value": S("Value")}
    type: Optional[str] = field(default=None)
    value: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrafficRoutingConfig:
    kind: ClassVar[str] = "aws_sagemaker_traffic_routing_config"
    kind_display: ClassVar[str] = "AWS SageMaker Traffic Routing Config"
    kind_description: ClassVar[str] = (
        "SageMaker Traffic Routing Config is a feature of Amazon SageMaker that"
        " allows users to control the traffic distribution between different model"
        " variants deployed on SageMaker endpoints."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Blue-Green Update Policy"
    kind_description: ClassVar[str] = (
        "The SageMaker Blue-Green Update Policy is used to facilitate the deployment"
        " of machine learning models in a controlled manner, allowing for seamless"
        " updates and rollbacks of model versions."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Auto Rollback Configuration"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Auto Rollback Configuration automatically reverts"
        " a deployment if specified alarms are triggered."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"alarms": S("Alarms", default=[]) >> ForallBend(S("AlarmName"))}
    alarms: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerDeploymentConfig:
    kind: ClassVar[str] = "aws_sagemaker_deployment_config"
    kind_display: ClassVar[str] = "AWS SageMaker Deployment Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker Deployment Configuration in AWS is used to create and manage"
        " configurations for deploying machine learning models on SageMaker endpoints."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "blue_green_update_policy": S("BlueGreenUpdatePolicy") >> Bend(AwsSagemakerBlueGreenUpdatePolicy.mapping),
        "auto_rollback_configuration": S("AutoRollbackConfiguration") >> Bend(AwsSagemakerAutoRollbackConfig.mapping),
    }
    blue_green_update_policy: Optional[AwsSagemakerBlueGreenUpdatePolicy] = field(default=None)
    auto_rollback_configuration: Optional[AwsSagemakerAutoRollbackConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAsyncInferenceNotificationConfig:
    kind: ClassVar[str] = "aws_sagemaker_async_inference_notification_config"
    kind_display: ClassVar[str] = "AWS SageMaker Async Inference Notification Config"
    kind_description: ClassVar[str] = (
        "SageMaker Async Inference Notification Config is a feature in Amazon"
        " SageMaker that allows users to receive notifications when asynchronous"
        " inference is completed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"success_topic": S("SuccessTopic"), "error_topic": S("ErrorTopic")}
    success_topic: Optional[str] = field(default=None)
    error_topic: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAsyncInferenceOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_async_inference_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker Async Inference Output Config"
    kind_description: ClassVar[str] = (
        "SageMaker Async Inference Output Config is a configuration option in Amazon"
        " SageMaker that allows users to specify the location where the output data of"
        " asynchronous inference requests should be stored."
    )
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
    kind_display: ClassVar[str] = "AWS Sagemaker Async Inference Config"
    kind_description: ClassVar[str] = (
        "Sagemaker Async Inference Config is a feature in Amazon Sagemaker that"
        " allows you to configure asynchronous inference for your machine learning"
        " models, enabling efficient handling of high volumes of prediction requests."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "client_config": S("ClientConfig", "MaxConcurrentInvocationsPerInstance"),
        "output_config": S("OutputConfig") >> Bend(AwsSagemakerAsyncInferenceOutputConfig.mapping),
    }
    client_config: Optional[int] = field(default=None)
    output_config: Optional[AwsSagemakerAsyncInferenceOutputConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerPendingProductionVariantSummary:
    kind: ClassVar[str] = "aws_sagemaker_pending_production_variant_summary"
    kind_display: ClassVar[str] = "AWS SageMaker Pending Production Variant Summary"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Pending Production Variant Summary provides a snapshot of a SageMaker production"
        " variant's update status, detailing configurations about to be deployed, such as capacity and"
        " resource allocation changes."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Pending Deployment Summary"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Pending Deployment Summary provides details about an ongoing deployment process"
        " in SageMaker, including the configuration name, the variants being deployed, and the"
        " initiation time of the deployment."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Clarify Inference Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Clarify Inference Config is designed to configure inference requests and"
        " results for models, enabling users to understand predictions by specifying various attributes,"
        " such as the input features and the format of the output."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Clarify SHAP Baseline Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Clarify SHAP Baseline Config is a configuration for the"
        " SHAP (Shapley Additive exPlanations) baseline during model interpretability"
        " analysis in Amazon SageMaker. It allows users to specify a baseline dataset"
        " for calculating SHAP values, providing insights into feature importance and"
        " model behavior."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Clarify Text Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Clarify Text Config is a configuration setup that specifies the language"
        " and granularity for analyzing text data within SageMaker Clarify, facilitating natural"
        " language processing and understanding."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"language": S("Language"), "granularity": S("Granularity")}
    language: Optional[str] = field(default=None)
    granularity: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerClarifyShapConfig:
    kind: ClassVar[str] = "aws_sagemaker_clarify_shap_config"
    kind_display: ClassVar[str] = "AWS SageMaker Clarify SHAP Config"
    kind_description: ClassVar[str] = (
        "SageMaker Clarify SHAP Config is a configuration for Amazon SageMaker"
        " Clarify, a service that provides bias and explainability analysis for"
        " machine learning models using SHAP (SHapley Additive exPlanations) values."
    )
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
    kind_display: ClassVar[str] = "AWS SageMaker Clarify Explainer Config"
    kind_description: ClassVar[str] = (
        "SageMaker Clarify Explainer Config is a configuration resource in Amazon"
        " SageMaker that allows users to define configurations for explainability of"
        " machine learning models developed using SageMaker."
    )
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
    kind_display: ClassVar[str] = "AWS Sagemaker Explainer Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Explainer Config facilitates the configuration of Amazon SageMaker Clarify"
        " to provide explanations for the predictions made by machine learning models, helping to"
        " understand model behavior."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "clarify_explainer_config": S("ClarifyExplainerConfig") >> Bend(AwsSagemakerClarifyExplainerConfig.mapping)
    }
    clarify_explainer_config: Optional[AwsSagemakerClarifyExplainerConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEndpoint(SagemakerTaggable, AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_endpoint"
    kind_display: ClassVar[str] = "AWS SageMaker Endpoint"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:endpoint/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Endpoints are the locations where deployed machine learning models"
        " are hosted and can be accessed for making predictions or inferences."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "delete": ["aws_kms_key"],
        },
        "successors": {
            "default": ["aws_kms_key", "aws_s3_bucket", "aws_cloudwatch_alarm", "aws_sns_topic"],
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-endpoints", "Endpoints")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("EndpointName"),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-endpoint"), AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for endpoint in json:
            if endpoint_description := builder.client.get(
                service_name, "describe-endpoint", None, EndpointName=endpoint["EndpointName"]
            ):
                if endpoint_instance := AwsSagemakerEndpoint.from_api(endpoint_description, builder):
                    builder.add_node(endpoint_instance, endpoint_description)
                    builder.submit_work(service_name, SagemakerTaggable.add_tags, endpoint_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if dcc := self.endpoint_data_capture_config:
            if dcc.destination_s3_uri:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(dcc.destination_s3_uri))
            if dcc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(dcc.kms_key_id))
        if ldc := self.endpoint_last_deployment_config:
            if arc := ldc.auto_rollback_configuration:
                for alarm in arc.alarms:
                    builder.add_edge(self, clazz=AwsCloudwatchAlarm, name=alarm)
        if aic := self.endpoint_async_inference_config:
            if oc := aic.output_config:
                if oc.kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(oc.kms_key_id))
                if oc.s3_output_path:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(oc.s3_output_path))
                if nc := oc.notification_config:
                    if nc.success_topic:
                        builder.add_edge(self, clazz=AwsSnsTopic, arn=nc.success_topic)
                    if nc.error_topic:
                        builder.add_edge(self, clazz=AwsSnsTopic, arn=nc.error_topic)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-endpoint", result_name=None, EndpointName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-endpoint")]


@define(eq=False, slots=False)
class AwsSagemakerImage(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_image"
    kind_display: ClassVar[str] = "AWS SageMaker Image"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:image/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS SageMaker Images are pre-built machine learning environments that"
        " include all necessary frameworks and packages to train and deploy models"
        " using Amazon SageMaker."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role"],
            "delete": ["aws_iam_role"],
        }
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-images", "Images")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ImageName"),
        "name": S("ImageName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ImageArn"),
        "image_description": S("Description"),
        "image_display_name": S("DisplayName"),
        "image_failure_reason": S("FailureReason"),
        "image_image_status": S("ImageStatus"),
    }
    image_description: Optional[str] = field(default=None)
    image_display_name: Optional[str] = field(default=None)
    image_failure_reason: Optional[str] = field(default=None)
    image_image_status: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-image")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for image in json:
            image_description = builder.client.get(service_name, "describe-image", None, ImageName=image["ImageName"])
            if image_description:
                if image_instance := AwsSagemakerImage.from_api(image_description, builder):
                    builder.add_node(image_instance, image_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if role := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-image", result_name=None, ImageName=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-image")]


@define(eq=False, slots=False)
class AwsSagemakerArtifactSourceType:
    kind: ClassVar[str] = "aws_sagemaker_artifact_source_type"
    kind_display: ClassVar[str] = "AWS SageMaker Artifact Source Type"
    kind_description: ClassVar[str] = (
        "The Amazon SageMaker artifact source type identifies the origin of an artifact, such as a dataset"
        " or model, using a specific type and corresponding value to facilitate tracking and lineage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"source_id_type": S("SourceIdType"), "value": S("Value")}
    source_id_type: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerArtifactSource:
    kind: ClassVar[str] = "aws_sagemaker_artifact_source"
    kind_display: ClassVar[str] = "AWS SageMaker Artifact Source"
    kind_description: ClassVar[str] = (
        "SageMaker Artifact Source refers to the storage location for artifacts such"
        " as trained models and datasets in Amazon SageMaker, a managed service for"
        " building, training, and deploying machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "source_uri": S("SourceUri"),
        "source_types": S("SourceTypes", default=[]) >> ForallBend(AwsSagemakerArtifactSourceType.mapping),
    }
    source_uri: Optional[str] = field(default=None)
    source_types: List[AwsSagemakerArtifactSourceType] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerArtifact(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_artifact"
    kind_display: ClassVar[str] = "AWS SageMaker Artifact"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:artifact/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An Amazon SageMaker artifact is used for tracking the origin and usage of data"
        " or models within ML workflows, providing a clear history for auditing and reproducibility."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_sagemaker_user_profile",
                "aws_sagemaker_domain",
                "aws_sagemaker_code_repository",
                "aws_sagemaker_project",
            ],
        }
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-artifacts", "ArtifactSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ArtifactArn"),
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
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-artifact")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for artifact in json:
            if artifact_description := builder.client.get(
                service_name, "describe-artifact", None, ArtifactArn=artifact["ArtifactArn"]
            ):
                if artifact_instance := AwsSagemakerArtifact.from_api(artifact_description, builder):
                    builder.add_node(artifact_instance, artifact_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if c := self.artifact_created_by:
            if c.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=c.user_profile_name)
            if c.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=c.domain_id)
        if m := self.artifact_last_modified_by:
            if m.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=m.user_profile_name)
            if m.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=m.domain_id)
        if repository := value_in_path(source, ["MetadataProperties", "Repository"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerCodeRepository, name=repository)
        if project_id := value_in_path(source, ["MetadataProperties", "ProjectId"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerProject, id=project_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-artifact", result_name=None, ArtifactArn=self.arn)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-artifact")]


@define(eq=False, slots=False)
class AwsSagemakerUserProfile(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_user_profile"
    kind_display: ClassVar[str] = "AWS SageMaker User Profile"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:user-profile/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker User Profiles are user-specific configurations in Amazon SageMaker"
        " that define settings and permissions for users accessing the SageMaker"
        " Studio environment."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_sagemaker_domain"]},
        "successors": {"delete": ["aws_sagemaker_domain"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-user-profiles", "UserProfiles")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("UserProfileName"),
        "name": S("UserProfileName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "user_profile_domain_id": S("DomainId"),
        "user_profile_status": S("Status"),
    }
    user_profile_domain_id: Optional[str] = field(default=None)
    user_profile_status: Optional[str] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if domain_id := value_in_path(source, "DomainId"):
            builder.dependant_node(self, reverse=True, clazz=AwsSagemakerDomain, id=domain_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-user-profile",
            result_name=None,
            UserProfileName=self.name,
            DomainId=self.user_profile_domain_id,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-user-profile")]


@define(eq=False, slots=False)
class AwsSagemakerPipeline(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_pipeline"
    kind_display: ClassVar[str] = "AWS SageMaker Pipeline"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:pipeline/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Pipelines is a fully managed, easy-to-use CI/CD service for"
        " building, automating, and managing end-to-end machine learning workflows on"
        " Amazon SageMaker."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_sagemaker_user_profile", "aws_sagemaker_domain"],
            "delete": ["aws_iam_role"],
        }
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-pipelines", "PipelineSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("PipelineName"),
        "name": S("PipelineName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "atime": S("LastRunTime"),
        "arn": S("PipelineArn"),
        "pipeline_display_name": S("PipelineDisplayName"),
        "pipeline_definition": S("PipelineDefinition"),
        "pipeline_description": S("PipelineDescription"),
        "pipeline_status": S("PipelineStatus"),
        "pipeline_created_by": S("CreatedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "pipeline_last_modified_by": S("LastModifiedBy") >> Bend(AwsSagemakerUserContext.mapping),
        "pipeline_parallelism_configuration": S("ParallelismConfiguration", "MaxParallelExecutionSteps"),
    }
    pipeline_display_name: Optional[str] = field(default=None)
    pipeline_definition: Optional[str] = field(default=None)
    pipeline_description: Optional[str] = field(default=None)
    pipeline_status: Optional[str] = field(default=None)
    pipeline_created_by: Optional[AwsSagemakerUserContext] = field(default=None)
    pipeline_last_modified_by: Optional[AwsSagemakerUserContext] = field(default=None)
    pipeline_parallelism_configuration: Optional[int] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-pipeline")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for pipeline in json:
            if pipeline_description := builder.client.get(
                service_name, "describe-pipeline", None, PipelineName=pipeline["PipelineName"]
            ):
                if pipeline_instance := AwsSagemakerPipeline.from_api(pipeline_description, builder):
                    builder.add_node(pipeline_instance, pipeline_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if c := self.pipeline_created_by:
            if c.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=c.user_profile_name)
            if c.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=c.domain_id)
        if m := self.pipeline_last_modified_by:
            if m.user_profile_name:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerUserProfile, name=m.user_profile_name)
            if m.domain_id:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerDomain, id=m.domain_id)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-pipeline", result_name=None, PipelineName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-pipeline")]


@define(eq=False, slots=False)
class AwsSagemakerCognitoMemberDefinition:
    kind: ClassVar[str] = "aws_sagemaker_cognito_member_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Cognito Member Definition"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Cognito Member Definition refers to the configuration that integrates Amazon"
        " Cognito with SageMaker, allowing for the use of a Cognito User Pool to manage user access to"
        " SageMaker resources. This definition specifies which Cognito User Pool and group should be used for"
        " authenticating users, as well as the Client ID associated with the application within Cognito."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "user_pool": S("UserPool"),
        "user_group": S("UserGroup"),
        "client_id": S("ClientId"),
    }
    user_pool: Optional[str] = field(default=None)
    user_group: Optional[str] = field(default=None)
    client_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerOidcMemberDefinition:
    kind: ClassVar[str] = "aws_sagemaker_oidc_member_definition"
    kind_display: ClassVar[str] = "AWS SageMaker OIDC Member Definition"
    kind_description: ClassVar[str] = (
        "AWS SageMaker OIDC Member Definition is used for managing user access in SageMaker, typically"
        " specifying groups from an OpenID Connect (OIDC) identity provider that are allowed to perform"
        " certain actions or access specific resources within SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"groups": S("Groups", default=[])}
    groups: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerMemberDefinition:
    kind: ClassVar[str] = "aws_sagemaker_member_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Member Definition"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Member Definition defines the authentication information for individuals participating"
        " in a SageMaker work team. It specifies the type of member, such as users authenticated via Amazon"
        " Cognito or through an OpenID Connect (OIDC) identity provider. This setup is critical for managing"
        " user access and permissions within SageMaker projects and workstreams."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cognito_member_definition": S("CognitoMemberDefinition") >> Bend(AwsSagemakerCognitoMemberDefinition.mapping),
        "oidc_member_definition": S("OidcMemberDefinition") >> Bend(AwsSagemakerOidcMemberDefinition.mapping),
    }
    cognito_member_definition: Optional[AwsSagemakerCognitoMemberDefinition] = field(default=None)
    oidc_member_definition: Optional[AwsSagemakerOidcMemberDefinition] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerWorkteam(SagemakerTaggable, AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_workteam"
    kind_display: ClassVar[str] = "AWS SageMaker Workteam"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:workteam/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Workteam is a service in Amazon's cloud that allows organizations"
        " to create and manage teams of workers to label data for machine learning"
        " models."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_cognito_user_pool", "aws_cognito_group", "aws_sns_topic"],
        }
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-workteams", "Workteams", expected_errors=["UnknownOperationException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("WorkteamName"),
        "name": S("WorkteamName"),
        "ctime": S("CreateDate"),
        "mtime": S("LastUpdatedDate"),
        "arn": S("WorkteamArn"),
        "workteam_member_definitions": S("MemberDefinitions", default=[])
        >> ForallBend(AwsSagemakerMemberDefinition.mapping),
        "workteam_workforce_arn": S("WorkforceArn"),
        "workteam_product_listing_ids": S("ProductListingIds", default=[]),
        "workteam_description": S("Description"),
        "workteam_sub_domain": S("SubDomain"),
        "workteam_notification_configuration": S("NotificationConfiguration", "NotificationTopicArn"),
    }
    workteam_member_definitions: List[AwsSagemakerMemberDefinition] = field(factory=list)
    workteam_workforce_arn: Optional[str] = field(default=None)
    workteam_product_listing_ids: List[str] = field(factory=list)
    workteam_description: Optional[str] = field(default=None)
    workteam_sub_domain: Optional[str] = field(default=None)
    workteam_notification_configuration: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for workteam in json:
            if workteam_instance := AwsSagemakerWorkteam.from_api(workteam, builder):
                builder.add_node(workteam_instance, workteam)
                builder.submit_work(service_name, SagemakerTaggable.add_tags, workteam_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for member in self.workteam_member_definitions:
            if m := member.cognito_member_definition:
                if m.user_pool:
                    builder.add_edge(self, clazz=AwsCognitoUserPool, id=m.user_pool)  # TODO check if id or arn or name
                if m.user_group:
                    builder.add_edge(self, clazz=AwsCognitoGroup, id=m.user_group)  # TODO check if id or arn or name
        if self.workteam_notification_configuration:
            builder.add_edge(self, clazz=AwsSnsTopic, arn=self.workteam_notification_configuration)

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-workteam", result_name=None, WorkteamName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec(service_name, "delete-workteam")]


## Jobs
@define(eq=False, slots=False)
class AwsSagemakerJob(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_job"
    kind_display: ClassVar[str] = "AWS SageMaker Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:job/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Jobs in AWS are used to train and deploy machine learning models"
        " at scale, with built-in algorithms and frameworks provided by Amazon"
        " SageMaker."
    )


@define(eq=False, slots=False)
class AwsSagemakerAutoMLS3DataSource:
    kind: ClassVar[str] = "aws_sagemaker_auto_mls3_data_source"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML S3 Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML S3 Data Source is a service in AWS SageMaker that allows"
        " users to automatically select and preprocess data from an S3 bucket for"
        " machine learning model training."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"s3_data_type": S("S3DataType"), "s3_uri": S("S3Uri")}
    s3_data_type: Optional[str] = field(default=None)
    s3_uri: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLDataSource:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_data_source"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Data Source is a resource in Amazon SageMaker that allows"
        " users to specify the location of their training data for the automated"
        " machine learning process."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource") >> Bend(AwsSagemakerAutoMLS3DataSource.mapping)
    }
    s3_data_source: Optional[AwsSagemakerAutoMLS3DataSource] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLChannel:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_channel"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Channel"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Channel is a cloud resource in AWS SageMaker that allows"
        " you to define input data channels for training an AutoML model."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_source": S("DataSource") >> Bend(AwsSagemakerAutoMLDataSource.mapping),
        "compression_type": S("CompressionType"),
        "target_attribute_name": S("TargetAttributeName"),
        "content_type": S("ContentType"),
        "channel_type": S("ChannelType"),
    }
    data_source: Optional[AwsSagemakerAutoMLDataSource] = field(default=None)
    compression_type: Optional[str] = field(default=None)
    target_attribute_name: Optional[str] = field(default=None)
    content_type: Optional[str] = field(default=None)
    channel_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLOutputDataConfig:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_output_data_config"
    kind_display: ClassVar[str] = "AWS Sagemaker Auto ML Output Data Config"
    kind_description: ClassVar[str] = (
        "Sagemaker Auto ML Output Data Config is a feature of AWS Sagemaker that"
        " allows users to specify the location where the output data generated by the"
        " Auto ML job should be stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"kms_key_id": S("KmsKeyId"), "s3_output_path": S("S3OutputPath")}
    kms_key_id: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLJobCompletionCriteria:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_job_completion_criteria"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Job Completion Criteria"
    kind_description: ClassVar[str] = (
        "Sagemaker AutoML Job Completion Criteria represents the conditions based on"
        " which the automatic machine learning job will be considered complete."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_candidates": S("MaxCandidates"),
        "max_runtime_per_training_job_in_seconds": S("MaxRuntimePerTrainingJobInSeconds"),
        "max_auto_ml_job_runtime_in_seconds": S("MaxAutoMLJobRuntimeInSeconds"),
    }
    max_candidates: Optional[int] = field(default=None)
    max_runtime_per_training_job_in_seconds: Optional[int] = field(default=None)
    max_auto_ml_job_runtime_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLSecurityConfig:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_security_config"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Security Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker AutoML Security Config ensures the security of AutoML"
        " jobs with encryption and network settings."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "volume_kms_key_id": S("VolumeKmsKeyId"),
        "enable_inter_container_traffic_encryption": S("EnableInterContainerTrafficEncryption"),
        "vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
    }
    volume_kms_key_id: Optional[str] = field(default=None)
    enable_inter_container_traffic_encryption: Optional[bool] = field(default=None)
    vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLJobConfig:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_job_config"
    kind_display: ClassVar[str] = "AWS SageMaker Auto ML Job Config"
    kind_description: ClassVar[str] = (
        "SageMaker Auto ML Job Config provides a configuration for running automated"
        " machine learning jobs on AWS SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "completion_criteria": S("CompletionCriteria") >> Bend(AwsSagemakerAutoMLJobCompletionCriteria.mapping),
        "security_config": S("SecurityConfig") >> Bend(AwsSagemakerAutoMLSecurityConfig.mapping),
        "data_split_config": S("DataSplitConfig", "ValidationFraction"),
        "candidate_generation_config": S("CandidateGenerationConfig", "FeatureSpecificationS3Uri"),
        "mode": S("Mode"),
    }
    completion_criteria: Optional[AwsSagemakerAutoMLJobCompletionCriteria] = field(default=None)
    security_config: Optional[AwsSagemakerAutoMLSecurityConfig] = field(default=None)
    data_split_config: Optional[float] = field(default=None)
    candidate_generation_config: Optional[str] = field(default=None)
    mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerFinalAutoMLJobObjectiveMetric:
    kind: ClassVar[str] = "aws_sagemaker_final_auto_ml_job_objective_metric"
    kind_display: ClassVar[str] = "AWS SageMaker Final AutoML Job Objective Metric"
    kind_description: ClassVar[str] = (
        "The final objective metric value calculated at the end of an Amazon SageMaker AutoML job."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "metric_name": S("MetricName"), "value": S("Value")}
    type: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)
    value: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLCandidateStep:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_candidate_step"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Candidate Step"
    kind_description: ClassVar[str] = (
        "AWS SageMaker AutoML Candidate Step is a step in the SageMaker AutoML"
        " workflow that represents a candidate model trained by AutoML."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "candidate_step_type": S("CandidateStepType"),
        "candidate_step_arn": S("CandidateStepArn"),
        "candidate_step_name": S("CandidateStepName"),
    }
    candidate_step_type: Optional[str] = field(default=None)
    candidate_step_arn: Optional[str] = field(default=None)
    candidate_step_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLContainerDefinition:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_container_definition"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Container Definition"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Container Definition is a resource in AWS SageMaker that"
        " specifies the container image to be used for training and inference in an"
        " AutoML job."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "image": S("Image"),
        "model_data_url": S("ModelDataUrl"),
        "environment": S("Environment"),
    }
    image: Optional[str] = field(default=None)
    model_data_url: Optional[str] = field(default=None)
    environment: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCandidateArtifactLocations:
    kind: ClassVar[str] = "aws_sagemaker_candidate_artifact_locations"
    kind_display: ClassVar[str] = "AWS SageMaker Candidate Artifact Locations"
    kind_description: ClassVar[str] = (
        "SageMaker Candidate Artifact Locations are the locations in which candidate"
        " models generated during Amazon SageMaker training jobs are stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"explainability": S("Explainability"), "model_insights": S("ModelInsights")}
    explainability: Optional[str] = field(default=None)
    model_insights: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerMetricDatum:
    kind: ClassVar[str] = "aws_sagemaker_metric_datum"
    kind_display: ClassVar[str] = "AWS SageMaker Metric Datum"
    kind_description: ClassVar[str] = (
        "SageMaker Metric Datum is a unit of data used for tracking and monitoring"
        " machine learning metrics in Amazon SageMaker, a fully managed machine"
        " learning service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_name": S("MetricName"),
        "value": S("Value"),
        "set": S("Set"),
        "standard_metric_name": S("StandardMetricName"),
    }
    metric_name: Optional[str] = field(default=None)
    value: Optional[float] = field(default=None)
    set: Optional[str] = field(default=None)
    standard_metric_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCandidateProperties:
    kind: ClassVar[str] = "aws_sagemaker_candidate_properties"
    kind_display: ClassVar[str] = "AWS SageMaker Candidate Properties"
    kind_description: ClassVar[str] = (
        "SageMaker Candidate Properties are the attributes and characteristics of a"
        " machine learning model candidate that is trained and optimized using Amazon"
        " SageMaker, a fully-managed service for building, training, and deploying"
        " machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "candidate_artifact_locations": S("CandidateArtifactLocations")
        >> Bend(AwsSagemakerCandidateArtifactLocations.mapping),
        "candidate_metrics": S("CandidateMetrics", default=[]) >> ForallBend(AwsSagemakerMetricDatum.mapping),
    }
    candidate_artifact_locations: Optional[AwsSagemakerCandidateArtifactLocations] = field(default=None)
    candidate_metrics: List[AwsSagemakerMetricDatum] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLCandidate:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_candidate"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Candidate"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Candidates refer to the generated machine learning models"
        " during the automated machine learning process in Amazon SageMaker, where"
        " multiple models are trained and evaluated for a given dataset and objective."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "candidate_name": S("CandidateName"),
        "final_auto_ml_job_objective_metric": S("FinalAutoMLJobObjectiveMetric")
        >> Bend(AwsSagemakerFinalAutoMLJobObjectiveMetric.mapping),
        "objective_status": S("ObjectiveStatus"),
        "candidate_steps": S("CandidateSteps", default=[]) >> ForallBend(AwsSagemakerAutoMLCandidateStep.mapping),
        "candidate_status": S("CandidateStatus"),
        "inference_containers": S("InferenceContainers", default=[])
        >> ForallBend(AwsSagemakerAutoMLContainerDefinition.mapping),
        "creation_time": S("CreationTime"),
        "end_time": S("EndTime"),
        "last_modified_time": S("LastModifiedTime"),
        "failure_reason": S("FailureReason"),
        "candidate_properties": S("CandidateProperties") >> Bend(AwsSagemakerCandidateProperties.mapping),
    }
    candidate_name: Optional[str] = field(default=None)
    final_auto_ml_job_objective_metric: Optional[AwsSagemakerFinalAutoMLJobObjectiveMetric] = field(default=None)
    objective_status: Optional[str] = field(default=None)
    candidate_steps: List[AwsSagemakerAutoMLCandidateStep] = field(factory=list)
    candidate_status: Optional[str] = field(default=None)
    inference_containers: List[AwsSagemakerAutoMLContainerDefinition] = field(factory=list)
    creation_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    last_modified_time: Optional[datetime] = field(default=None)
    failure_reason: Optional[str] = field(default=None)
    candidate_properties: Optional[AwsSagemakerCandidateProperties] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLJobArtifacts:
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_job_artifacts"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Job Artifacts"
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Job Artifacts are the output files and artifacts generated"
        " during the AutoML job on Amazon SageMaker. These artifacts can include"
        " trained models, evaluation metrics, and other relevant information."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "candidate_definition_notebook_location": S("CandidateDefinitionNotebookLocation"),
        "data_exploration_notebook_location": S("DataExplorationNotebookLocation"),
    }
    candidate_definition_notebook_location: Optional[str] = field(default=None)
    data_exploration_notebook_location: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerResolvedAttributes:
    kind: ClassVar[str] = "aws_sagemaker_resolved_attributes"
    kind_display: ClassVar[str] = "AWS SageMaker Resolved Attributes"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Resolved Attributes define the objective and criteria for an AutoML job,"
        " determining how the model is optimized and when the job is complete."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_ml_job_objective": S("AutoMLJobObjective", "MetricName"),
        "problem_type": S("ProblemType"),
        "completion_criteria": S("CompletionCriteria") >> Bend(AwsSagemakerAutoMLJobCompletionCriteria.mapping),
    }
    auto_ml_job_objective: Optional[str] = field(default=None)
    problem_type: Optional[str] = field(default=None)
    completion_criteria: Optional[AwsSagemakerAutoMLJobCompletionCriteria] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerModelDeployConfig:
    kind: ClassVar[str] = "aws_sagemaker_model_deploy_config"
    kind_display: ClassVar[str] = "AWS SageMaker Model Deploy Config"
    kind_description: ClassVar[str] = (
        "SageMaker Model Deploy Config is a configuration for deploying machine"
        " learning models on Amazon SageMaker, a fully managed machine learning"
        " service by AWS."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_generate_endpoint_name": S("AutoGenerateEndpointName"),
        "endpoint_name": S("EndpointName"),
    }
    auto_generate_endpoint_name: Optional[bool] = field(default=None)
    endpoint_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAutoMLJob(AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_auto_ml_job"
    kind_display: ClassVar[str] = "AWS SageMaker AutoML Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:automl-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker AutoML Jobs in AWS provide automated machine learning"
        " capabilities, allowing users to automatically discover and build optimal"
        " machine learning models without manual intervention."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_security_group", "aws_ec2_subnet"],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {
            "default": [
                "aws_s3_bucket",
                "aws_kms_key",
                "aws_sagemaker_training_job",
                "aws_sagemaker_transform_job",
                "aws_sagemaker_processing_job",
            ]
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-auto-ml-jobs", "AutoMLJobSummaries", expected_errors=["UnknownOperationException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AutoMLJobName"),
        "name": S("AutoMLJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("AutoMLJobArn"),
        "auto_ml_job_input_data_config": S("InputDataConfig", default=[])
        >> ForallBend(AwsSagemakerAutoMLChannel.mapping),
        "auto_ml_job_output_data_config": S("OutputDataConfig") >> Bend(AwsSagemakerAutoMLOutputDataConfig.mapping),
        "auto_ml_job_objective": S("AutoMLJobObjective", "MetricName"),
        "auto_ml_job_problem_type": S("ProblemType"),
        "auto_ml_job_config": S("AutoMLJobConfig") >> Bend(AwsSagemakerAutoMLJobConfig.mapping),
        "auto_ml_job_end_time": S("EndTime"),
        "auto_ml_job_failure_reason": S("FailureReason"),
        "auto_ml_job_partial_failure_reasons": S("PartialFailureReasons", default=[])
        >> ForallBend(S("PartialFailureMessage")),
        "auto_ml_job_best_candidate": S("BestCandidate") >> Bend(AwsSagemakerAutoMLCandidate.mapping),
        "auto_ml_job_status": S("AutoMLJobStatus"),
        "auto_ml_job_secondary_status": S("AutoMLJobSecondaryStatus"),
        "auto_ml_job_generate_candidate_definitions_only": S("GenerateCandidateDefinitionsOnly"),
        "auto_ml_job_artifacts": S("AutoMLJobArtifacts") >> Bend(AwsSagemakerAutoMLJobArtifacts.mapping),
        "auto_ml_job_resolved_attributes": S("ResolvedAttributes") >> Bend(AwsSagemakerResolvedAttributes.mapping),
        "auto_ml_job_model_deploy_config": S("ModelDeployConfig") >> Bend(AwsSagemakerModelDeployConfig.mapping),
        "auto_ml_job_model_deploy_result": S("ModelDeployResult", "EndpointName"),
    }
    auto_ml_job_input_data_config: List[AwsSagemakerAutoMLChannel] = field(factory=list)
    auto_ml_job_output_data_config: Optional[AwsSagemakerAutoMLOutputDataConfig] = field(default=None)
    auto_ml_job_objective: Optional[str] = field(default=None)
    auto_ml_job_problem_type: Optional[str] = field(default=None)
    auto_ml_job_config: Optional[AwsSagemakerAutoMLJobConfig] = field(default=None)
    auto_ml_job_end_time: Optional[datetime] = field(default=None)
    auto_ml_job_failure_reason: Optional[str] = field(default=None)
    auto_ml_job_partial_failure_reasons: List[str] = field(factory=list)
    auto_ml_job_best_candidate: Optional[AwsSagemakerAutoMLCandidate] = field(default=None)
    auto_ml_job_status: Optional[str] = field(default=None)
    auto_ml_job_secondary_status: Optional[str] = field(default=None)
    auto_ml_job_generate_candidate_definitions_only: Optional[bool] = field(default=None)
    auto_ml_job_artifacts: Optional[AwsSagemakerAutoMLJobArtifacts] = field(default=None)
    auto_ml_job_resolved_attributes: Optional[AwsSagemakerResolvedAttributes] = field(default=None)
    auto_ml_job_model_deploy_config: Optional[AwsSagemakerModelDeployConfig] = field(default=None)
    auto_ml_job_model_deploy_result: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-auto-ml-job")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name, "describe-auto-ml-job", None, AutoMLJobName=job["AutoMLJobName"]
            )
            if job_description:
                if job_instance := AwsSagemakerAutoMLJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for config in self.auto_ml_job_input_data_config:
            if cds := config.data_source:
                if s3 := cds.s3_data_source:
                    if s3.s3_uri:
                        builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(s3.s3_uri))
        if odc := self.auto_ml_job_output_data_config:
            if odc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(odc.kms_key_id))
            if odc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(odc.s3_output_path))
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if jc := self.auto_ml_job_config:
            if sc := jc.security_config:
                if sc.volume_kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(sc.volume_kms_key_id))
                if vpc := sc.vpc_config:
                    for security_group in vpc.security_group_ids:
                        builder.dependant_node(
                            self,
                            reverse=True,
                            delete_same_as_default=True,
                            clazz=AwsEc2SecurityGroup,
                            id=security_group,
                        )
                    for subnet in vpc.subnets:
                        builder.dependant_node(
                            self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet
                        )
            if jc.candidate_generation_config:
                builder.add_edge(
                    self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(jc.candidate_generation_config)
                )
        if bc := self.auto_ml_job_best_candidate:
            for step in bc.candidate_steps:
                if step.candidate_step_type and step.candidate_step_arn:
                    if "TrainingJob" in step.candidate_step_type:
                        builder.add_edge(self, clazz=AwsSagemakerTrainingJob, arn=step.candidate_step_arn)
                    if "TransformJob" in step.candidate_step_type:
                        builder.add_edge(self, clazz=AwsSagemakerTransformJob, arn=step.candidate_step_arn)
                    if "ProcessingJob" in step.candidate_step_type:
                        builder.add_edge(self, clazz=AwsSagemakerProcessingJob, arn=step.candidate_step_arn)


@define(eq=False, slots=False)
class AwsSagemakerInputConfig:
    kind: ClassVar[str] = "aws_sagemaker_input_config"
    kind_display: ClassVar[str] = "AWS SageMaker Input Config"
    kind_description: ClassVar[str] = (
        "SageMaker Input Config is a configuration file that defines the input data"
        " to be used for training a machine learning model on Amazon SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_uri": S("S3Uri"),
        "data_input_config": S("DataInputConfig"),
        "framework": S("Framework"),
        "framework_version": S("FrameworkVersion"),
    }
    s3_uri: Optional[str] = field(default=None)
    data_input_config: Optional[str] = field(default=None)
    framework: Optional[str] = field(default=None)
    framework_version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTargetPlatform:
    kind: ClassVar[str] = "aws_sagemaker_target_platform"
    kind_display: ClassVar[str] = "AWS SageMaker Target Platform"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Target Platform specifies the operating system, architecture, and accelerator type for a model"
        " compiled with SageMaker Neo, allowing you to optimize the model for deployment on a specific hardware"
        " platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"os": S("Os"), "arch": S("Arch"), "accelerator": S("Accelerator")}
    os: Optional[str] = field(default=None)
    arch: Optional[str] = field(default=None)
    accelerator: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker Output Config"
    kind_description: ClassVar[str] = (
        "SageMaker Output Config is a resource in AWS SageMaker that allows users to"
        " configure the output location for trained machine learning models and"
        " associated results."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_output_location": S("S3OutputLocation"),
        "target_device": S("TargetDevice"),
        "target_platform": S("TargetPlatform") >> Bend(AwsSagemakerTargetPlatform.mapping),
        "compiler_options": S("CompilerOptions"),
        "kms_key_id": S("KmsKeyId"),
    }
    s3_output_location: Optional[str] = field(default=None)
    target_device: Optional[str] = field(default=None)
    target_platform: Optional[AwsSagemakerTargetPlatform] = field(default=None)
    compiler_options: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerNeoVpcConfig:
    kind: ClassVar[str] = "aws_sagemaker_neo_vpc_config"
    kind_display: ClassVar[str] = "AWS SageMaker Neo VPC Config"
    kind_description: ClassVar[str] = (
        "SageMaker Neo VPC Config is a configuration setting for Amazon SageMaker's"
        " Neo service, which allows you to optimize deep learning models for various"
        " hardware platforms."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "security_group_ids": S("SecurityGroupIds", default=[]),
        "subnets": S("Subnets", default=[]),
    }
    security_group_ids: List[str] = field(factory=list)
    subnets: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerCompilationJob(AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_compilation_job"
    kind_display: ClassVar[str] = "AWS SageMaker Compilation Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:compilation-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Compilation Job is a resource in Amazon SageMaker that allows"
        " users to compile machine learning models for deployment on edge devices or"
        " inference in the cloud."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_security_group", "aws_ec2_subnet"],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {
            "default": [
                "aws_s3_bucket",
                "aws_kms_key",
            ]
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-compilation-jobs", "CompilationJobSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CompilationJobName"),
        "name": S("CompilationJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("CompilationJobArn"),
        "compilation_job_status": S("CompilationJobStatus"),
        "compilation_job_start_time": S("CompilationStartTime"),
        "compilation_job_end_time": S("CompilationEndTime"),
        "compilation_job_stopping_condition": S("StoppingCondition") >> Bend(AwsSagemakerStoppingCondition.mapping),
        "compilation_job_inference_image": S("InferenceImage"),
        "compilation_job_model_package_version_arn": S("ModelPackageVersionArn"),
        "compilation_job_failure_reason": S("FailureReason"),
        "compilation_job_model_artifacts": S("ModelArtifacts", "S3ModelArtifacts"),
        "compilation_job_model_digests": S("ModelDigests", "ArtifactDigest"),
        "compilation_job_input_config": S("InputConfig") >> Bend(AwsSagemakerInputConfig.mapping),
        "compilation_job_output_config": S("OutputConfig") >> Bend(AwsSagemakerOutputConfig.mapping),
        "compilation_job_vpc_config": S("VpcConfig") >> Bend(AwsSagemakerNeoVpcConfig.mapping),
    }
    compilation_job_status: Optional[str] = field(default=None)
    compilation_job_start_time: Optional[datetime] = field(default=None)
    compilation_job_end_time: Optional[datetime] = field(default=None)
    compilation_job_stopping_condition: Optional[AwsSagemakerStoppingCondition] = field(default=None)
    compilation_job_inference_image: Optional[str] = field(default=None)
    compilation_job_model_package_version_arn: Optional[str] = field(default=None)
    compilation_job_failure_reason: Optional[str] = field(default=None)
    compilation_job_model_artifacts: Optional[str] = field(default=None)
    compilation_job_model_digests: Optional[str] = field(default=None)
    compilation_job_input_config: Optional[AwsSagemakerInputConfig] = field(default=None)
    compilation_job_output_config: Optional[AwsSagemakerOutputConfig] = field(default=None)
    compilation_job_vpc_config: Optional[AwsSagemakerNeoVpcConfig] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-compilation-job")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name, "describe-compilation-job", None, CompilationJobName=job["CompilationJobName"]
            )
            if job_description:
                if job_instance := AwsSagemakerCompilationJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.compilation_job_model_artifacts:
            builder.add_edge(
                self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(self.compilation_job_model_artifacts)
            )
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if ic := self.compilation_job_input_config:
            if ic.s3_uri:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ic.s3_uri))
        if oc := self.compilation_job_output_config:
            if oc.s3_output_location:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(oc.s3_output_location))
            if oc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(oc.kms_key_id))
        if vpc := self.compilation_job_vpc_config:
            for security_group in vpc.security_group_ids:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
            for subnet in vpc.subnets:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet)


@define(eq=False, slots=False)
class AwsSagemakerEdgeOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_edge_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker Edge Output Configuration"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Edge Output Configuration pertains to how models are deployed and managed on edge"
        " devices using Amazon SageMaker Edge Manager. It specifies where the model artifacts and other Edge"
        " Manager outputs will be stored, typically in an S3 bucket, and how they will be encrypted, using an"
        " optional AWS KMS key."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_output_location": S("S3OutputLocation"),
        "kms_key_id": S("KmsKeyId"),
        "preset_deployment_type": S("PresetDeploymentType"),
        "preset_deployment_config": S("PresetDeploymentConfig"),
    }
    s3_output_location: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    preset_deployment_type: Optional[str] = field(default=None)
    preset_deployment_config: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEdgePresetDeploymentOutput:
    kind: ClassVar[str] = "aws_sagemaker_edge_preset_deployment_output"
    kind_display: ClassVar[str] = "AWS SageMaker Edge Preset Deployment Output"
    kind_description: ClassVar[str] = (
        "The output of a deployment of an edge preset in Amazon SageMaker. It"
        " represents the processed data and predictions generated by a machine"
        " learning model that has been deployed to edge devices."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "type": S("Type"),
        "artifact": S("Artifact"),
        "status": S("Status"),
        "status_message": S("StatusMessage"),
    }
    type: Optional[str] = field(default=None)
    artifact: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    status_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEdgePackagingJob(AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_edge_packaging_job"
    kind_display: ClassVar[str] = "AWS SageMaker Edge Packaging Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:edge-packaging-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Edge Packaging Jobs allow users to package machine learning models"
        " and dependencies for deployment on edge devices using AWS SageMaker Edge"
        " Manager."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_sagemaker_model"],
            "delete": ["aws_kms_key", "aws_iam_role"],
        },
        "successors": {
            "default": [
                "aws_s3_bucket",
                "aws_kms_key",
            ],
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "list-edge-packaging-jobs",
        "EdgePackagingJobSummaries",
        expected_errors=["UnknownOperationException"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("EdgePackagingJobName"),
        "name": S("EdgePackagingJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("EdgePackagingJobArn"),
        "edge_packaging_job_compilation_job_name": S("CompilationJobName"),
        "edge_packaging_job_model_version": S("ModelVersion"),
        "edge_packaging_job_output_config": S("OutputConfig") >> Bend(AwsSagemakerEdgeOutputConfig.mapping),
        "edge_packaging_job_resource_key": S("ResourceKey"),
        "edge_packaging_job_status": S("EdgePackagingJobStatus"),
        "edge_packaging_job_status_message": S("EdgePackagingJobStatusMessage"),
        "edge_packaging_job_model_artifact": S("ModelArtifact"),
        "edge_packaging_job_model_signature": S("ModelSignature"),
        "edge_packaging_job_preset_deployment_output": S("PresetDeploymentOutput")
        >> Bend(AwsSagemakerEdgePresetDeploymentOutput.mapping),
    }
    edge_packaging_job_compilation_job_name: Optional[str] = field(default=None)
    edge_packaging_job_model_version: Optional[str] = field(default=None)
    edge_packaging_job_output_config: Optional[AwsSagemakerEdgeOutputConfig] = field(default=None)
    edge_packaging_job_resource_key: Optional[str] = field(default=None)
    edge_packaging_job_status: Optional[str] = field(default=None)
    edge_packaging_job_status_message: Optional[str] = field(default=None)
    edge_packaging_job_model_artifact: Optional[str] = field(default=None)
    edge_packaging_job_model_signature: Optional[str] = field(default=None)
    edge_packaging_job_preset_deployment_output: Optional[AwsSagemakerEdgePresetDeploymentOutput] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-edge-packaging-job")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name, "describe-edge-packaging-job", None, EdgePackagingJobName=job["EdgePackagingJobName"]
            )
            if job_description and (job_instance := AwsSagemakerEdgePackagingJob.from_api(job_description, builder)):
                builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if model_name := value_in_path(source, "ModelName"):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerModel, name=model_name)
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        if oc := self.edge_packaging_job_output_config:
            if oc.s3_output_location:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(oc.s3_output_location))
            if oc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(oc.kms_key_id))
        if self.edge_packaging_job_resource_key:
            builder.dependant_node(
                self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(self.edge_packaging_job_resource_key)
            )
        if self.edge_packaging_job_model_artifact:
            builder.add_edge(
                self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(self.edge_packaging_job_model_artifact)
            )


@define(eq=False, slots=False)
class AwsSagemakerHyperbandStrategyConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyperband_strategy_config"
    kind_display: ClassVar[str] = "AWS SageMaker Hyperband Strategy Config"
    kind_description: ClassVar[str] = (
        "SageMaker Hyperband Strategy Config is a configuration setting for the"
        " Hyperband strategy in Amazon SageMaker. It allows users to optimize their"
        " machine learning models by automatically tuning hyperparameters."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"min_resource": S("MinResource"), "max_resource": S("MaxResource")}
    min_resource: Optional[int] = field(default=None)
    max_resource: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningJobStrategyConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_job_strategy_config"
    kind_display: ClassVar[str] = "AWS Sagemaker Hyper Parameter Tuning Job Strategy Config"
    kind_description: ClassVar[str] = (
        "The AWS Sagemaker Hyper Parameter Tuning Job Strategy Config is a"
        " configuration that defines the strategy for searching hyperparameter"
        " combinations during hyperparameter tuning in Amazon Sagemaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hyperband_strategy_config": S("HyperbandStrategyConfig") >> Bend(AwsSagemakerHyperbandStrategyConfig.mapping)
    }
    hyperband_strategy_config: Optional[AwsSagemakerHyperbandStrategyConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerResourceLimits:
    kind: ClassVar[str] = "aws_sagemaker_resource_limits"
    kind_display: ClassVar[str] = "AWS SageMaker Resource Limits"
    kind_description: ClassVar[str] = (
        "SageMaker Resource Limits allows you to manage and control the amount of"
        " resources (such as compute instances, storage, and data transfer) that your"
        " SageMaker resources can consume in order to optimize cost and performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_number_of_training_jobs": S("MaxNumberOfTrainingJobs"),
        "max_parallel_training_jobs": S("MaxParallelTrainingJobs"),
    }
    max_number_of_training_jobs: Optional[int] = field(default=None)
    max_parallel_training_jobs: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerScalingParameterRange:
    kind: ClassVar[str] = "aws_sagemaker_scaling_parameter_range"
    kind_display: ClassVar[str] = "AWS SageMaker Scaling Parameter Range"
    kind_description: ClassVar[str] = (
        "SageMaker Scaling Parameter Range is a feature in AWS SageMaker, which"
        " allows users to define the range of scaling parameters for their machine"
        " learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "min_value": S("MinValue"),
        "max_value": S("MaxValue"),
        "scaling_type": S("ScalingType"),
    }
    name: Optional[str] = field(default=None)
    min_value: Optional[str] = field(default=None)
    max_value: Optional[str] = field(default=None)
    scaling_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCategoricalParameterRange:
    kind: ClassVar[str] = "aws_sagemaker_categorical_parameter_range"
    kind_display: ClassVar[str] = "AWS SageMaker Categorical Parameter Range"
    kind_description: ClassVar[str] = (
        "SageMaker Categorical Parameter Range is a cloud resource provided by AWS"
        " that allows users to define a range of categorical hyperparameters for"
        " machine learning models developed using Amazon SageMaker, which is a fully"
        " managed machine learning service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "values": S("Values", default=[])}
    name: Optional[str] = field(default=None)
    values: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerParameterRanges:
    kind: ClassVar[str] = "aws_sagemaker_parameter_ranges"
    kind_display: ClassVar[str] = "AWS SageMaker Parameter Ranges"
    kind_description: ClassVar[str] = (
        "SageMaker Parameter Ranges are set of possible values or ranges for"
        " hyperparameters used in training machine learning models with AWS SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "integer_parameter_ranges": S("IntegerParameterRanges", default=[])
        >> ForallBend(AwsSagemakerScalingParameterRange.mapping),
        "continuous_parameter_ranges": S("ContinuousParameterRanges", default=[])
        >> ForallBend(AwsSagemakerScalingParameterRange.mapping),
        "categorical_parameter_ranges": S("CategoricalParameterRanges", default=[])
        >> ForallBend(AwsSagemakerCategoricalParameterRange.mapping),
    }
    integer_parameter_ranges: List[AwsSagemakerScalingParameterRange] = field(factory=list)
    continuous_parameter_ranges: List[AwsSagemakerScalingParameterRange] = field(factory=list)
    categorical_parameter_ranges: List[AwsSagemakerCategoricalParameterRange] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningJobConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_job_config"
    kind_display: ClassVar[str] = "AWS SageMaker Hyper Parameter Tuning Job Config"
    kind_description: ClassVar[str] = (
        "SageMaker Hyper Parameter Tuning Job Config is a configuration resource in"
        " AWS SageMaker that helps to optimize the hyperparameters of machine learning"
        " models by systematically testing and fine-tuning their values."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "strategy": S("Strategy"),
        "strategy_config": S("StrategyConfig") >> Bend(AwsSagemakerHyperParameterTuningJobStrategyConfig.mapping),
        "hyper_parameter_tuning_job_objective": S("HyperParameterTuningJobObjective")
        >> Bend(AwsSagemakerHyperParameterTuningJobObjective.mapping),
        "resource_limits": S("ResourceLimits") >> Bend(AwsSagemakerResourceLimits.mapping),
        "parameter_ranges": S("ParameterRanges") >> Bend(AwsSagemakerParameterRanges.mapping),
        "training_job_early_stopping_type": S("TrainingJobEarlyStoppingType"),
        "tuning_job_completion_criteria": S("TuningJobCompletionCriteria", "TargetObjectiveMetricValue"),
    }
    strategy: Optional[str] = field(default=None)
    strategy_config: Optional[AwsSagemakerHyperParameterTuningJobStrategyConfig] = field(default=None)
    hyper_parameter_tuning_job_objective: Optional[AwsSagemakerHyperParameterTuningJobObjective] = field(default=None)
    resource_limits: Optional[AwsSagemakerResourceLimits] = field(default=None)
    parameter_ranges: Optional[AwsSagemakerParameterRanges] = field(default=None)
    training_job_early_stopping_type: Optional[str] = field(default=None)
    tuning_job_completion_criteria: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterAlgorithmSpecification:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_algorithm_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Hyper Parameter Algorithm Specification"
    kind_description: ClassVar[str] = (
        "SageMaker Hyper Parameter Algorithm Specification is a feature in AWS"
        " SageMaker that allows users to define and customize the hyperparameters for"
        " training machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "training_image": S("TrainingImage"),
        "training_input_mode": S("TrainingInputMode"),
        "algorithm_name": S("AlgorithmName"),
        "metric_definitions": S("MetricDefinitions", default=[]) >> ForallBend(AwsSagemakerMetricDefinition.mapping),
    }
    training_image: Optional[str] = field(default=None)
    training_input_mode: Optional[str] = field(default=None)
    algorithm_name: Optional[str] = field(default=None)
    metric_definitions: List[AwsSagemakerMetricDefinition] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerCheckpointConfig:
    kind: ClassVar[str] = "aws_sagemaker_checkpoint_config"
    kind_display: ClassVar[str] = "AWS SageMaker Checkpoint Config"
    kind_description: ClassVar[str] = (
        "SageMaker Checkpoint Config is a feature of Amazon SageMaker that allows you"
        " to automatically save and load model checkpoints during the training"
        " process, ensuring that the progress of the model is not lost in case of"
        " errors or interruptions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"s3_uri": S("S3Uri"), "local_path": S("LocalPath")}
    s3_uri: Optional[str] = field(default=None)
    local_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningInstanceConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_instance_config"
    kind_display: ClassVar[str] = "AWS SageMaker HyperParameter Tuning Instance Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker HyperParameter Tuning Instance Configuration is a resource used in"
        " the Amazon SageMaker service to configure the instance type and quantity for"
        " hyperparameter tuning of machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
    }
    instance_type: Optional[str] = field(default=None)
    instance_count: Optional[int] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningResourceConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_resource_config"
    kind_display: ClassVar[str] = "AWS SageMaker Hyper Parameter Tuning Resource Config"
    kind_description: ClassVar[str] = (
        "SageMaker Hyper Parameter Tuning Resource Config is a resource configuration"
        " used for optimizing machine learning models in the Amazon SageMaker cloud"
        " platform."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "volume_kms_key_id": S("VolumeKmsKeyId"),
        "allocation_strategy": S("AllocationStrategy"),
        "instance_configs": S("InstanceConfigs", default=[])
        >> ForallBend(AwsSagemakerHyperParameterTuningInstanceConfig.mapping),
    }
    instance_type: Optional[str] = field(default=None)
    instance_count: Optional[int] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)
    allocation_strategy: Optional[str] = field(default=None)
    instance_configs: List[AwsSagemakerHyperParameterTuningInstanceConfig] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTrainingJobDefinition:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_training_job_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Hyperparameter Training Job Definition"
    kind_description: ClassVar[str] = (
        "SageMaker Hyperparameter Training Job Definition is a configuration for"
        " running a training job in Amazon SageMaker, which allows the user to specify"
        " the hyperparameters, input data locations, and output data locations for the"
        " training job."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "definition_name": S("DefinitionName"),
        "tuning_objective": S("TuningObjective") >> Bend(AwsSagemakerHyperParameterTuningJobObjective.mapping),
        "hyper_parameter_ranges": S("HyperParameterRanges") >> Bend(AwsSagemakerParameterRanges.mapping),
        "static_hyper_parameters": S("StaticHyperParameters"),
        "algorithm_specification": S("AlgorithmSpecification")
        >> Bend(AwsSagemakerHyperParameterAlgorithmSpecification.mapping),
        "role_arn": S("RoleArn"),
        "input_data_config": S("InputDataConfig", default=[]) >> ForallBend(AwsSagemakerChannel.mapping),
        "vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
        "output_data_config": S("OutputDataConfig") >> Bend(AwsSagemakerOutputDataConfig.mapping),
        "resource_config": S("ResourceConfig") >> Bend(AwsSagemakerResourceConfig.mapping),
        "stopping_condition": S("StoppingCondition") >> Bend(AwsSagemakerStoppingCondition.mapping),
        "enable_network_isolation": S("EnableNetworkIsolation"),
        "enable_inter_container_traffic_encryption": S("EnableInterContainerTrafficEncryption"),
        "enable_managed_spot_training": S("EnableManagedSpotTraining"),
        "checkpoint_config": S("CheckpointConfig") >> Bend(AwsSagemakerCheckpointConfig.mapping),
        "retry_strategy": S("RetryStrategy", "MaximumRetryAttempts"),
        "hyper_parameter_tuning_resource_config": S("HyperParameterTuningResourceConfig")
        >> Bend(AwsSagemakerHyperParameterTuningResourceConfig.mapping),
    }
    definition_name: Optional[str] = field(default=None)
    tuning_objective: Optional[AwsSagemakerHyperParameterTuningJobObjective] = field(default=None)
    hyper_parameter_ranges: Optional[AwsSagemakerParameterRanges] = field(default=None)
    static_hyper_parameters: Optional[Dict[str, str]] = field(default=None)
    algorithm_specification: Optional[AwsSagemakerHyperParameterAlgorithmSpecification] = field(default=None)
    role_arn: Optional[str] = field(default=None)
    input_data_config: List[AwsSagemakerChannel] = field(factory=list)
    vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)
    output_data_config: Optional[AwsSagemakerOutputDataConfig] = field(default=None)
    resource_config: Optional[AwsSagemakerResourceConfig] = field(default=None)
    stopping_condition: Optional[AwsSagemakerStoppingCondition] = field(default=None)
    enable_network_isolation: Optional[bool] = field(default=None)
    enable_inter_container_traffic_encryption: Optional[bool] = field(default=None)
    enable_managed_spot_training: Optional[bool] = field(default=None)
    checkpoint_config: Optional[AwsSagemakerCheckpointConfig] = field(default=None)
    retry_strategy: Optional[int] = field(default=None)
    hyper_parameter_tuning_resource_config: Optional[AwsSagemakerHyperParameterTuningResourceConfig] = field(
        default=None
    )


@define(eq=False, slots=False)
class AwsSagemakerTrainingJobStatusCounters:
    kind: ClassVar[str] = "aws_sagemaker_training_job_status_counters"
    kind_display: ClassVar[str] = "AWS SageMaker Training Job Status Counters"
    kind_description: ClassVar[str] = (
        "SageMaker Training Job Status Counters represent the counts of training job"
        " statuses in AWS SageMaker, which is a service for training and deploying"
        " machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "completed": S("Completed"),
        "in_progress": S("InProgress"),
        "retryable_error": S("RetryableError"),
        "non_retryable_error": S("NonRetryableError"),
        "stopped": S("Stopped"),
    }
    completed: Optional[int] = field(default=None)
    in_progress: Optional[int] = field(default=None)
    retryable_error: Optional[int] = field(default=None)
    non_retryable_error: Optional[int] = field(default=None)
    stopped: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerObjectiveStatusCounters:
    kind: ClassVar[str] = "aws_sagemaker_objective_status_counters"
    kind_display: ClassVar[str] = "AWS SageMaker Objective Status Counters"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Objective Status Counters track the progress and outcomes of training jobs or"
        " hyperparameter tuning jobs by counting how many have succeeded, are still pending, or have failed."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"succeeded": S("Succeeded"), "pending": S("Pending"), "failed": S("Failed")}
    succeeded: Optional[int] = field(default=None)
    pending: Optional[int] = field(default=None)
    failed: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerFinalHyperParameterTuningJobObjectiveMetric:
    kind: ClassVar[str] = "aws_sagemaker_final_hyper_parameter_tuning_job_objective_metric"
    kind_display: ClassVar[str] = "AWS SageMaker Final Hyper Parameter Tuning Job Objective Metric"
    kind_description: ClassVar[str] = (
        "SageMaker is a fully managed machine learning service provided by AWS that"
        " enables developers to build, train, and deploy machine learning models. The"
        " Final Hyper Parameter Tuning Job Objective Metric is the metric used to"
        " evaluate the performance of a machine learning model after hyperparameter"
        " tuning."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"type": S("Type"), "metric_name": S("MetricName"), "value": S("Value")}
    type: Optional[str] = field(default=None)
    metric_name: Optional[str] = field(default=None)
    value: Optional[float] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTrainingJobSummary:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_training_job_summary"
    kind_display: ClassVar[str] = "AWS SageMaker Hyper Parameter Training Job Summary"
    kind_description: ClassVar[str] = (
        "SageMaker Hyper Parameter Training Job Summary provides a summary of"
        " hyperparameter training jobs in AWS SageMaker. It enables users to view key"
        " details and metrics of the training jobs for machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "training_job_definition_name": S("TrainingJobDefinitionName"),
        "training_job_name": S("TrainingJobName"),
        "training_job_arn": S("TrainingJobArn"),
        "tuning_job_name": S("TuningJobName"),
        "creation_time": S("CreationTime"),
        "training_start_time": S("TrainingStartTime"),
        "training_end_time": S("TrainingEndTime"),
        "training_job_status": S("TrainingJobStatus"),
        "tuned_hyper_parameters": S("TunedHyperParameters"),
        "failure_reason": S("FailureReason"),
        "final_hyper_parameter_tuning_job_objective_metric": S("FinalHyperParameterTuningJobObjectiveMetric")
        >> Bend(AwsSagemakerFinalHyperParameterTuningJobObjectiveMetric.mapping),
        "objective_status": S("ObjectiveStatus"),
    }
    training_job_definition_name: Optional[str] = field(default=None)
    training_job_name: Optional[str] = field(default=None)
    training_job_arn: Optional[str] = field(default=None)
    tuning_job_name: Optional[str] = field(default=None)
    creation_time: Optional[datetime] = field(default=None)
    training_start_time: Optional[datetime] = field(default=None)
    training_end_time: Optional[datetime] = field(default=None)
    training_job_status: Optional[str] = field(default=None)
    tuned_hyper_parameters: Optional[Dict[str, str]] = field(default=None)
    failure_reason: Optional[str] = field(default=None)
    final_hyper_parameter_tuning_job_objective_metric: Optional[
        AwsSagemakerFinalHyperParameterTuningJobObjectiveMetric
    ] = field(default=None)
    objective_status: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningJobWarmStartConfig:
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_job_warm_start_config"
    kind_display: ClassVar[str] = "AWS SageMaker Hyperparameter Tuning Job Warm Start Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Hyperparameter Tuning Job Warm Start Config allows you to"
        " reuse the results of previous tuning jobs in order to accelerate the"
        " optimization process for machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "parent_hyper_parameter_tuning_jobs": S("ParentHyperParameterTuningJobs", default=[])
        >> ForallBend(S("HyperParameterTuningJobName")),
        "warm_start_type": S("WarmStartType"),
    }
    parent_hyper_parameter_tuning_jobs: List[str] = field(factory=list)
    warm_start_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHyperParameterTuningJob(SagemakerTaggable, AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_hyper_parameter_tuning_job"
    kind_display: ClassVar[str] = "AWS SageMaker Hyperparameter Tuning Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:hyperparameter-tuning-job/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Hyperparameter Tuning Job is an automated process in Amazon"
        " SageMaker that helps optimize the hyperparameters of a machine learning"
        " model to achieve better performance."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_security_group", "aws_ec2_subnet"],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_s3_bucket", "aws_kms_key", "aws_sagemaker_training_job"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-hyper-parameter-tuning-jobs", "HyperParameterTuningJobSummaries"
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("HyperParameterTuningJobName"),
        "name": S("HyperParameterTuningJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("HyperParameterTuningJobArn"),
        "hyper_parameter_tuning_job_config": S("HyperParameterTuningJobConfig")
        >> Bend(AwsSagemakerHyperParameterTuningJobConfig.mapping),
        "hyper_parameter_tuning_job_training_job_definition": S("TrainingJobDefinition")
        >> Bend(AwsSagemakerHyperParameterTrainingJobDefinition.mapping),
        "hyper_parameter_tuning_job_training_job_definitions": S("TrainingJobDefinitions", default=[])
        >> ForallBend(AwsSagemakerHyperParameterTrainingJobDefinition.mapping),
        "hyper_parameter_tuning_job_status": S("HyperParameterTuningJobStatus"),
        "hyper_parameter_tuning_job_hyper_parameter_tuning_end_time": S("HyperParameterTuningEndTime"),
        "hyper_parameter_tuning_job_training_job_status_counters": S("TrainingJobStatusCounters")
        >> Bend(AwsSagemakerTrainingJobStatusCounters.mapping),
        "hyper_parameter_tuning_job_objective_status_counters": S("ObjectiveStatusCounters")
        >> Bend(AwsSagemakerObjectiveStatusCounters.mapping),
        "hyper_parameter_tuning_job_best_training_job": S("BestTrainingJob")
        >> Bend(AwsSagemakerHyperParameterTrainingJobSummary.mapping),
        "hyper_parameter_tuning_job_overall_best_training_job": S("OverallBestTrainingJob")
        >> Bend(AwsSagemakerHyperParameterTrainingJobSummary.mapping),
        "hyper_parameter_tuning_job_warm_start_config": S("WarmStartConfig")
        >> Bend(AwsSagemakerHyperParameterTuningJobWarmStartConfig.mapping),
        "hyper_parameter_tuning_job_failure_reason": S("FailureReason"),
    }
    hyper_parameter_tuning_job_config: Optional[AwsSagemakerHyperParameterTuningJobConfig] = field(default=None)
    hyper_parameter_tuning_job_training_job_definition: Optional[AwsSagemakerHyperParameterTrainingJobDefinition] = (
        field(default=None)
    )
    hyper_parameter_tuning_job_training_job_definitions: List[AwsSagemakerHyperParameterTrainingJobDefinition] = field(
        factory=list
    )
    hyper_parameter_tuning_job_status: Optional[str] = field(default=None)
    hyper_parameter_tuning_job_hyper_parameter_tuning_end_time: Optional[datetime] = field(default=None)
    hyper_parameter_tuning_job_training_job_status_counters: Optional[AwsSagemakerTrainingJobStatusCounters] = field(
        default=None
    )
    hyper_parameter_tuning_job_objective_status_counters: Optional[AwsSagemakerObjectiveStatusCounters] = field(
        default=None
    )
    hyper_parameter_tuning_job_best_training_job: Optional[AwsSagemakerHyperParameterTrainingJobSummary] = field(
        default=None
    )
    hyper_parameter_tuning_job_overall_best_training_job: Optional[AwsSagemakerHyperParameterTrainingJobSummary] = (
        field(default=None)
    )
    hyper_parameter_tuning_job_warm_start_config: Optional[AwsSagemakerHyperParameterTuningJobWarmStartConfig] = field(
        default=None
    )
    hyper_parameter_tuning_job_failure_reason: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "describe-hyper-parameter-tuning-job"),
            AwsApiSpec(service_name, "list-tags"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name,
                "describe-hyper-parameter-tuning-job",
                None,
                HyperParameterTuningJobName=job["HyperParameterTuningJobName"],
            )
            if job_description:
                if job_instance := AwsSagemakerHyperParameterTuningJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)
                    builder.submit_work(service_name, SagemakerTaggable.add_tags, job_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        job_definitions = []
        if self.hyper_parameter_tuning_job_training_job_definition is not None:
            job_definitions.append(self.hyper_parameter_tuning_job_training_job_definition)
        for jobdef in self.hyper_parameter_tuning_job_training_job_definitions:
            job_definitions.append(jobdef)
        for jobdef in job_definitions:
            if jobdef.role_arn:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=jobdef.role_arn
                )
            for config in jobdef.input_data_config:
                if ids := config.data_source:
                    if ids.s3_data_source:
                        if ids.s3_data_source.s3_uri:
                            builder.add_edge(
                                self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ids.s3_data_source.s3_uri)
                            )
            if vpc := jobdef.vpc_config:
                for security_group in vpc.security_group_ids:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                    )
                for subnet in vpc.subnets:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet
                    )
            if odc := jobdef.output_data_config:
                if odc.kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(odc.kms_key_id))
                if odc.s3_output_path:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(odc.s3_output_path))
            if rc := jobdef.resource_config:
                if rc.volume_kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(rc.volume_kms_key_id))
            if cc := jobdef.checkpoint_config:
                if cc.s3_uri:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(cc.s3_uri))
            if hptrc := jobdef.hyper_parameter_tuning_resource_config:
                if hptrc.volume_kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(hptrc.volume_kms_key_id))

        if btj := self.hyper_parameter_tuning_job_best_training_job:
            if btj.training_job_arn:
                builder.add_edge(self, clazz=AwsSagemakerTrainingJob, arn=btj.training_job_arn)
        if obtj := self.hyper_parameter_tuning_job_overall_best_training_job:
            if obtj.training_job_arn:
                builder.add_edge(self, clazz=AwsSagemakerTrainingJob, arn=obtj.training_job_arn)


@define(eq=False, slots=False)
class AwsSagemakerPhase:
    kind: ClassVar[str] = "aws_sagemaker_phase"
    kind_display: ClassVar[str] = "AWS SageMaker Phase"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Phase setting is used to control the traffic pattern or user ramp-up strategy for"
        " load testing in a SageMaker environment, defining the start size, how quickly to add users, and the"
        " duration of the test phase."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "initial_number_of_users": S("InitialNumberOfUsers"),
        "spawn_rate": S("SpawnRate"),
        "duration_in_seconds": S("DurationInSeconds"),
    }
    initial_number_of_users: Optional[int] = field(default=None)
    spawn_rate: Optional[int] = field(default=None)
    duration_in_seconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrafficPattern:
    kind: ClassVar[str] = "aws_sagemaker_traffic_pattern"
    kind_display: ClassVar[str] = "AWS SageMaker Traffic Pattern"
    kind_description: ClassVar[str] = (
        "SageMaker Traffic Pattern in AWS refers to the traffic distribution or"
        " routing rules for deploying machine learning models in Amazon SageMaker,"
        " allowing users to define how incoming requests are routed to the deployed"
        " models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "traffic_type": S("TrafficType"),
        "phases": S("Phases", default=[]) >> ForallBend(AwsSagemakerPhase.mapping),
    }
    traffic_type: Optional[str] = field(default=None)
    phases: List[AwsSagemakerPhase] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationJobResourceLimit:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_job_resource_limit"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Job Resource Limit"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Recommendation Job Resource Limit sets the maximum number of tests"
        " and the maximum number of parallel tests allowed for model evaluations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_number_of_tests": S("MaxNumberOfTests"),
        "max_parallel_of_tests": S("MaxParallelOfTests"),
    }
    max_number_of_tests: Optional[int] = field(default=None)
    max_parallel_of_tests: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEnvironmentParameterRanges:
    kind: ClassVar[str] = "aws_sagemaker_environment_parameter_ranges"
    kind_display: ClassVar[str] = "AWS SageMaker Environment Parameter Ranges"
    kind_description: ClassVar[str] = (
        "SageMaker Environment Parameter Ranges are a set of constraints or"
        " boundaries for the hyperparameters used in Amazon SageMaker. These ranges"
        " define the valid values that can be used for tuning machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "categorical_parameter_ranges": S("CategoricalParameterRanges", "Value", default=[])
    }
    categorical_parameter_ranges: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerEndpointInputConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_endpoint_input_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Endpoint Input Configuration"
    kind_description: ClassVar[str] = (
        "Input configuration for a SageMaker endpoint, which defines the data input"
        " format and location for real-time inference."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "inference_specification_name": S("InferenceSpecificationName"),
        "environment_parameter_ranges": S("EnvironmentParameterRanges")
        >> Bend(AwsSagemakerEnvironmentParameterRanges.mapping),
    }
    instance_type: Optional[str] = field(default=None)
    inference_specification_name: Optional[str] = field(default=None)
    environment_parameter_ranges: Optional[AwsSagemakerEnvironmentParameterRanges] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationJobPayloadConfig:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_job_payload_config"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Job Payload Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Recommendation Job Payload Config specifies the location of sample payloads"
        " and the content types that are supported for model evaluations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "sample_payload_url": S("SamplePayloadUrl"),
        "supported_content_types": S("SupportedContentTypes", default=[]),
    }
    sample_payload_url: Optional[str] = field(default=None)
    supported_content_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationJobContainerConfig:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_job_container_config"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Job Container Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Recommendation Job Container Config outlines the framework and version for machine"
        " learning tasks, including the domain and task type, as well as model and instance preferences."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain": S("Domain"),
        "task": S("Task"),
        "framework": S("Framework"),
        "framework_version": S("FrameworkVersion"),
        "payload_config": S("PayloadConfig") >> Bend(AwsSagemakerRecommendationJobPayloadConfig.mapping),
        "nearest_model_name": S("NearestModelName"),
        "supported_instance_types": S("SupportedInstanceTypes", default=[]),
    }
    domain: Optional[str] = field(default=None)
    task: Optional[str] = field(default=None)
    framework: Optional[str] = field(default=None)
    framework_version: Optional[str] = field(default=None)
    payload_config: Optional[AwsSagemakerRecommendationJobPayloadConfig] = field(default=None)
    nearest_model_name: Optional[str] = field(default=None)
    supported_instance_types: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationJobInputConfig:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_job_input_config"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Job Input Config"
    kind_description: ClassVar[str] = (
        "The input configuration for a recommendation job in Amazon SageMaker, which"
        " specifies the location of the input data for the recommendation model."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "model_package_version_arn": S("ModelPackageVersionArn"),
        "job_duration_in_seconds": S("JobDurationInSeconds"),
        "traffic_pattern": S("TrafficPattern") >> Bend(AwsSagemakerTrafficPattern.mapping),
        "resource_limit": S("ResourceLimit") >> Bend(AwsSagemakerRecommendationJobResourceLimit.mapping),
        "endpoint_configurations": S("EndpointConfigurations", default=[])
        >> ForallBend(AwsSagemakerEndpointInputConfiguration.mapping),
        "container_config": S("ContainerConfig") >> Bend(AwsSagemakerRecommendationJobContainerConfig.mapping),
        "endpoints": S("Endpoints", default=[]) >> ForallBend(S("EndpointName")),
        "vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
    }
    model_package_version_arn: Optional[str] = field(default=None)
    job_duration_in_seconds: Optional[int] = field(default=None)
    traffic_pattern: Optional[AwsSagemakerTrafficPattern] = field(default=None)
    resource_limit: Optional[AwsSagemakerRecommendationJobResourceLimit] = field(default=None)
    endpoint_configurations: List[AwsSagemakerEndpointInputConfiguration] = field(factory=list)
    container_config: Optional[AwsSagemakerRecommendationJobContainerConfig] = field(default=None)
    endpoints: List[str] = field(factory=list)
    vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerModelLatencyThreshold:
    kind: ClassVar[str] = "aws_sagemaker_model_latency_threshold"
    kind_display: ClassVar[str] = "AWS SageMaker Model Latency Threshold"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Model Latency Threshold setting is used to monitor the performance of a machine learning"
        " model by specifying the acceptable latency threshold in milliseconds for a given percentile of"
        " inference requests."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "percentile": S("Percentile"),
        "value_in_milliseconds": S("ValueInMilliseconds"),
    }
    percentile: Optional[str] = field(default=None)
    value_in_milliseconds: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationJobStoppingConditions:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_job_stopping_conditions"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Job Stopping Conditions"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Recommendation Job Stopping Conditions determine when a model evaluation"
        " job should be halted, based on the maximum number of model invocations or the threshold for model latency."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_invocations": S("MaxInvocations"),
        "model_latency_thresholds": S("ModelLatencyThresholds", default=[])
        >> ForallBend(AwsSagemakerModelLatencyThreshold.mapping),
    }
    max_invocations: Optional[int] = field(default=None)
    model_latency_thresholds: List[AwsSagemakerModelLatencyThreshold] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerRecommendationMetrics:
    kind: ClassVar[str] = "aws_sagemaker_recommendation_metrics"
    kind_display: ClassVar[str] = "AWS SageMaker Recommendation Metrics"
    kind_description: ClassVar[str] = (
        "SageMaker Recommendation Metrics are performance evaluation metrics used in"
        " Amazon SageMaker to measure the accuracy and effectiveness of recommendation"
        " algorithms."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cost_per_hour": S("CostPerHour"),
        "cost_per_inference": S("CostPerInference"),
        "max_invocations": S("MaxInvocations"),
        "model_latency": S("ModelLatency"),
    }
    cost_per_hour: Optional[float] = field(default=None)
    cost_per_inference: Optional[float] = field(default=None)
    max_invocations: Optional[int] = field(default=None)
    model_latency: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEndpointOutputConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_endpoint_output_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Endpoint Output Configuration"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Endpoint Output Configuration sets up the deployment of a model,"
        " specifying endpoint characteristics, hosting resources, and initial scale."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "endpoint_name": S("EndpointName"),
        "variant_name": S("VariantName"),
        "instance_type": S("InstanceType"),
        "initial_instance_count": S("InitialInstanceCount"),
    }
    endpoint_name: Optional[str] = field(default=None)
    variant_name: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    initial_instance_count: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEnvironmentParameter:
    kind: ClassVar[str] = "aws_sagemaker_environment_parameter"
    kind_display: ClassVar[str] = "AWS SageMaker Environment Parameter"
    kind_description: ClassVar[str] = (
        "SageMaker Environment Parameters are key-value pairs that can be used to"
        " pass environment variables to a training job or a hosting job in Amazon"
        " SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("Key"), "value_type": S("ValueType"), "value": S("Value")}
    key: Optional[str] = field(default=None)
    value_type: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerModelConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_model_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Model Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker Model Configuration is a resource in AWS that allows users to"
        " define and configure machine learning models for use in Amazon SageMaker, a"
        " fully managed machine learning service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "inference_specification_name": S("InferenceSpecificationName"),
        "environment_parameters": S("EnvironmentParameters", default=[])
        >> ForallBend(AwsSagemakerEnvironmentParameter.mapping),
    }
    inference_specification_name: Optional[str] = field(default=None)
    environment_parameters: List[AwsSagemakerEnvironmentParameter] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerInferenceRecommendation:
    kind: ClassVar[str] = "aws_sagemaker_inference_recommendation"
    kind_display: ClassVar[str] = "AWS SageMaker Inference Recommendation"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Inference Recommendation is a feature that provides optimized configurations"
        " and recommendations for deploying machine learning models in SageMaker, based on performance"
        " metrics and specific model requirements."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "metrics": S("Metrics") >> Bend(AwsSagemakerRecommendationMetrics.mapping),
        "endpoint_configuration": S("EndpointConfiguration") >> Bend(AwsSagemakerEndpointOutputConfiguration.mapping),
        "model_configuration": S("ModelConfiguration") >> Bend(AwsSagemakerModelConfiguration.mapping),
    }
    metrics: Optional[AwsSagemakerRecommendationMetrics] = field(default=None)
    endpoint_configuration: Optional[AwsSagemakerEndpointOutputConfiguration] = field(default=None)
    model_configuration: Optional[AwsSagemakerModelConfiguration] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerInferenceMetrics:
    kind: ClassVar[str] = "aws_sagemaker_inference_metrics"
    kind_display: ClassVar[str] = "AWS SageMaker Inference Metrics"
    kind_description: ClassVar[str] = (
        "SageMaker Inference Metrics provide performance metrics for machine learning"
        " models deployed on the SageMaker platform, allowing users to track the"
        " accuracy and efficiency of their model predictions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"max_invocations": S("MaxInvocations"), "model_latency": S("ModelLatency")}
    max_invocations: Optional[int] = field(default=None)
    model_latency: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerEndpointPerformance:
    kind: ClassVar[str] = "aws_sagemaker_endpoint_performance"
    kind_display: ClassVar[str] = "AWS SageMaker Endpoint Performance"
    kind_description: ClassVar[str] = (
        "SageMaker Endpoint Performance is a service provided by Amazon Web Services"
        " for monitoring and optimizing the performance of machine learning models"
        " deployed on SageMaker endpoints."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "metrics": S("Metrics") >> Bend(AwsSagemakerInferenceMetrics.mapping),
        "endpoint_info": S("EndpointInfo", "EndpointName"),
    }
    metrics: Optional[AwsSagemakerInferenceMetrics] = field(default=None)
    endpoint_info: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerInferenceRecommendationsJob(AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_inference_recommendations_job"
    kind_display: ClassVar[str] = "AWS SageMaker Inference Recommendations Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:transform-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS SageMaker Inference Recommendations Job evaluates different configurations for deploying machine"
        " learning models, providing suggestions to optimize performance and efficiency, along with monitoring"
        " job progress and outcomes."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role", "aws_ec2_security_group", "aws_ec2_subnet"],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {
            "default": ["aws_s3_bucket", "aws_kms_key", "aws_sagemaker_endpoint"],
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name,
        "list-inference-recommendations-jobs",
        "InferenceRecommendationsJobs",
        expected_errors=["UnknownOperationException"],
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("JobName"),
        "name": S("JobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("JobArn"),
        "inference_recommendations_job_description": S("JobDescription"),
        "inference_recommendations_job_type": S("JobType"),
        "inference_recommendations_job_status": S("Status"),
        "inference_recommendations_job_completion_time": S("CompletionTime"),
        "inference_recommendations_job_failure_reason": S("FailureReason"),
        "inference_recommendations_job_input_config": S("InputConfig")
        >> Bend(AwsSagemakerRecommendationJobInputConfig.mapping),
        "inference_recommendations_job_stopping_conditions": S("StoppingConditions")
        >> Bend(AwsSagemakerRecommendationJobStoppingConditions.mapping),
        "inference_recommendations_job_inference_recommendations": S("InferenceRecommendations", default=[])
        >> ForallBend(AwsSagemakerInferenceRecommendation.mapping),
        "inference_recommendations_job_endpoint_performances": S("EndpointPerformances", default=[])
        >> ForallBend(AwsSagemakerEndpointPerformance.mapping),
    }
    inference_recommendations_job_description: Optional[str] = field(default=None)
    inference_recommendations_job_type: Optional[str] = field(default=None)
    inference_recommendations_job_status: Optional[str] = field(default=None)
    inference_recommendations_job_completion_time: Optional[datetime] = field(default=None)
    inference_recommendations_job_failure_reason: Optional[str] = field(default=None)
    inference_recommendations_job_input_config: Optional[AwsSagemakerRecommendationJobInputConfig] = field(default=None)
    inference_recommendations_job_stopping_conditions: Optional[AwsSagemakerRecommendationJobStoppingConditions] = (
        field(default=None)
    )
    inference_recommendations_job_inference_recommendations: List[AwsSagemakerInferenceRecommendation] = field(
        factory=list
    )
    inference_recommendations_job_endpoint_performances: List[AwsSagemakerEndpointPerformance] = field(factory=list)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-inference-recommendations-job")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            if job_description := builder.client.get(
                service_name,
                "describe-inference-recommendations-job",
                None,
                JobName=job["JobName"],
            ):
                if job_instance := AwsSagemakerInferenceRecommendationsJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(
                self,
                reverse=True,
                delete_same_as_default=True,
                clazz=AwsIamRole,
                arn=role_arn,
            )
        if key := value_in_path(source, ["InputConfig", "VolumeKmsKeyId"]):
            builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(key))
        if ic := self.inference_recommendations_job_input_config:
            if cc := ic.container_config:
                if pc := cc.payload_config:
                    if pc.sample_payload_url:
                        builder.add_edge(
                            self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(pc.sample_payload_url)
                        )
            if vpc := ic.vpc_config:
                for security_group in vpc.security_group_ids:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                    )
                for subnet in vpc.subnets:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet
                    )
        for rec in self.inference_recommendations_job_inference_recommendations:
            if ec := rec.endpoint_configuration:
                if ec.endpoint_name:
                    builder.add_edge(self, clazz=AwsSagemakerEndpoint, name=ec.endpoint_name)
        for perf in self.inference_recommendations_job_endpoint_performances:
            if perf.endpoint_info:
                builder.add_edge(self, clazz=AwsSagemakerEndpoint, name=perf.endpoint_info)


@define(eq=False, slots=False)
class AwsSagemakerLabelCounters:
    kind: ClassVar[str] = "aws_sagemaker_label_counters"
    kind_display: ClassVar[str] = "AWS SageMaker Label Counters"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Label Counters provide metrics on the labeling process of a dataset, indicating the total"
        " number of items labeled, the split between human and machine labeling, any failures, and the"
        " number of items still unlabeled."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "total_labeled": S("TotalLabeled"),
        "human_labeled": S("HumanLabeled"),
        "machine_labeled": S("MachineLabeled"),
        "failed_non_retryable_error": S("FailedNonRetryableError"),
        "unlabeled": S("Unlabeled"),
    }
    total_labeled: Optional[int] = field(default=None)
    human_labeled: Optional[int] = field(default=None)
    machine_labeled: Optional[int] = field(default=None)
    failed_non_retryable_error: Optional[int] = field(default=None)
    unlabeled: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobDataSource:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_data_source"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Data Source"
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Job Data Source is a source of data used for machine"
        " learning labeling tasks in Amazon SageMaker. It can include various types of"
        " data such as text, images, or videos."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_data_source": S("S3DataSource", "ManifestS3Uri"),
        "sns_data_source": S("SnsDataSource", "SnsTopicArn"),
    }
    s3_data_source: Optional[str] = field(default=None)
    sns_data_source: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobInputConfig:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_input_config"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Input Config"
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Job Input Config is a configuration for specifying the"
        " input data for a labeling job in Amazon SageMaker. It includes information"
        " such as the input data source location and format."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "data_source": S("DataSource") >> Bend(AwsSagemakerLabelingJobDataSource.mapping),
        "data_attributes": S("DataAttributes", "ContentClassifiers", default=[]),
    }
    data_source: Optional[AwsSagemakerLabelingJobDataSource] = field(default=None)
    data_attributes: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Output Config"
    kind_description: ClassVar[str] = (
        "The output configuration for a labeling job in Amazon SageMaker. It"
        " specifies the location that the generated manifest file and labeled data"
        " objects will be saved to."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_output_path": S("S3OutputPath"),
        "kms_key_id": S("KmsKeyId"),
        "sns_topic_arn": S("SnsTopicArn"),
    }
    s3_output_path: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    sns_topic_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobStoppingConditions:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_stopping_conditions"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Stopping Conditions"
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Job Stopping Conditions is a feature in Amazon SageMaker"
        " that allows users to define conditions for stopping an active labeling job,"
        " such as when a certain number of data points have been labeled or when a"
        " certain level of accuracy has been achieved."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_human_labeled_object_count": S("MaxHumanLabeledObjectCount"),
        "max_percentage_of_input_dataset_labeled": S("MaxPercentageOfInputDatasetLabeled"),
    }
    max_human_labeled_object_count: Optional[int] = field(default=None)
    max_percentage_of_input_dataset_labeled: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobResourceConfig:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_resource_config"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Resource Config"
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Job Resource Config is used to configure the resources"
        " required to run a labeling job in Amazon SageMaker, which provides a fully"
        " managed machine learning service."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "volume_kms_key_id": S("VolumeKmsKeyId"),
        "vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
    }
    volume_kms_key_id: Optional[str] = field(default=None)
    vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobAlgorithmsConfig:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_algorithms_config"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Algorithms Config"
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Job Algorithms Config is a configuration that allows you"
        " to define the algorithms used in SageMaker labeling job."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "labeling_job_algorithm_specification_arn": S("LabelingJobAlgorithmSpecificationArn"),
        "initial_active_learning_model_arn": S("InitialActiveLearningModelArn"),
        "labeling_job_resource_config": S("LabelingJobResourceConfig")
        >> Bend(AwsSagemakerLabelingJobResourceConfig.mapping),
    }
    labeling_job_algorithm_specification_arn: Optional[str] = field(default=None)
    initial_active_learning_model_arn: Optional[str] = field(default=None)
    labeling_job_resource_config: Optional[AwsSagemakerLabelingJobResourceConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUiConfig:
    kind: ClassVar[str] = "aws_sagemaker_ui_config"
    kind_display: ClassVar[str] = "AWS SageMaker UI Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker UI Config refers to the configuration for user interfaces used in SageMaker,"
        " specifying the Amazon S3 location of the UI template and the Amazon Resource Name (ARN)"
        " for the human task user interface."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "ui_template_s3_uri": S("UiTemplateS3Uri"),
        "human_task_ui_arn": S("HumanTaskUiArn"),
    }
    ui_template_s3_uri: Optional[str] = field(default=None)
    human_task_ui_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerUSD:
    kind: ClassVar[str] = "aws_sagemaker_usd"
    kind_display: ClassVar[str] = "AWS SageMaker USD"
    kind_description: ClassVar[str] = (
        "SageMaker USD is a service offered by Amazon Web Services that allows"
        " machine learning developers to build, train, and deploy machine learning"
        " models using Universal Scene Description (USD) format."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "dollars": S("Dollars"),
        "cents": S("Cents"),
        "tenth_fractions_of_a_cent": S("TenthFractionsOfACent"),
    }
    dollars: Optional[int] = field(default=None)
    cents: Optional[int] = field(default=None)
    tenth_fractions_of_a_cent: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerPublicWorkforceTaskPrice:
    kind: ClassVar[str] = "aws_sagemaker_public_workforce_task_price"
    kind_display: ClassVar[str] = "AWS SageMaker Public Workforce Task Price"
    kind_description: ClassVar[str] = (
        "SageMaker Public Workforce Task Price is the cost associated with using"
        " Amazon SageMaker Public Workforce to create tasks for labeling and"
        " annotation of data."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"amount_in_usd": S("AmountInUsd") >> Bend(AwsSagemakerUSD.mapping)}
    amount_in_usd: Optional[AwsSagemakerUSD] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerHumanTaskConfig:
    kind: ClassVar[str] = "aws_sagemaker_human_task_config"
    kind_display: ClassVar[str] = "AWS SageMaker Human Task Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Human Task Config is a configuration that allows you to create"
        " and manage human annotation jobs on your data using Amazon SageMaker. It"
        " enables you to build, train, and deploy machine learning models with human"
        " intelligence."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "workteam_arn": S("WorkteamArn"),
        "ui_config": S("UiConfig") >> Bend(AwsSagemakerUiConfig.mapping),
        "pre_human_task_lambda_arn": S("PreHumanTaskLambdaArn"),
        "task_keywords": S("TaskKeywords", default=[]),
        "task_title": S("TaskTitle"),
        "task_description": S("TaskDescription"),
        "number_of_human_workers_per_data_object": S("NumberOfHumanWorkersPerDataObject"),
        "task_time_limit_in_seconds": S("TaskTimeLimitInSeconds"),
        "task_availability_lifetime_in_seconds": S("TaskAvailabilityLifetimeInSeconds"),
        "max_concurrent_task_count": S("MaxConcurrentTaskCount"),
        "annotation_consolidation_config": S("AnnotationConsolidationConfig", "AnnotationConsolidationLambdaArn"),
        "public_workforce_task_price": S("PublicWorkforceTaskPrice")
        >> Bend(AwsSagemakerPublicWorkforceTaskPrice.mapping),
    }
    workteam_arn: Optional[str] = field(default=None)
    ui_config: Optional[AwsSagemakerUiConfig] = field(default=None)
    pre_human_task_lambda_arn: Optional[str] = field(default=None)
    task_keywords: List[str] = field(factory=list)
    task_title: Optional[str] = field(default=None)
    task_description: Optional[str] = field(default=None)
    number_of_human_workers_per_data_object: Optional[int] = field(default=None)
    task_time_limit_in_seconds: Optional[int] = field(default=None)
    task_availability_lifetime_in_seconds: Optional[int] = field(default=None)
    max_concurrent_task_count: Optional[int] = field(default=None)
    annotation_consolidation_config: Optional[str] = field(default=None)
    public_workforce_task_price: Optional[AwsSagemakerPublicWorkforceTaskPrice] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJobOutput:
    kind: ClassVar[str] = "aws_sagemaker_labeling_job_output"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job Output"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Labeling Job Output refers to the storage location of datasets annotated during a labeling job"
        " and the ARN of the final machine learning model used if active learning was employed to assist humans in"
        " the labeling process."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_dataset_s3_uri": S("OutputDatasetS3Uri"),
        "final_active_learning_model_arn": S("FinalActiveLearningModelArn"),
    }
    output_dataset_s3_uri: Optional[str] = field(default=None)
    final_active_learning_model_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerLabelingJob(SagemakerTaggable, AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_labeling_job"
    kind_display: ClassVar[str] = "AWS SageMaker Labeling Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:labeling-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Labeling Jobs are used to annotate and label data for training"
        " machine learning models in Amazon SageMaker."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_iam_role",
                "aws_ec2_security_group",
                "aws_ec2_subnet",
                "aws_sagemaker_model",
                "aws_sagemaker_workteam",
            ],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
            # TODO lambda should have a dependency here, but it breaks the graph
            # investigate where circularity is being introduced
        },
        "successors": {"default": ["aws_s3_bucket", "aws_kms_key", "aws_sns_topic", "aws_lambda_function"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(
        service_name, "list-labeling-jobs", "LabelingJobSummaryList", expected_errors=["UnknownOperationException"]
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("LabelingJobName"),
        "name": S("LabelingJobName"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("LabelingJobArn"),
        "labeling_job_status": S("LabelingJobStatus"),
        "labeling_job_label_counters": S("LabelCounters") >> Bend(AwsSagemakerLabelCounters.mapping),
        "labeling_job_failure_reason": S("FailureReason"),
        "labeling_job_job_reference_code": S("JobReferenceCode"),
        "labeling_job_label_attribute_name": S("LabelAttributeName"),
        "labeling_job_input_config": S("InputConfig") >> Bend(AwsSagemakerLabelingJobInputConfig.mapping),
        "labeling_job_output_config": S("OutputConfig") >> Bend(AwsSagemakerLabelingJobOutputConfig.mapping),
        "labeling_job_role_arn": S("RoleArn"),
        "labeling_job_label_category_config_s3_uri": S("LabelCategoryConfigS3Uri"),
        "labeling_job_stopping_conditions": S("StoppingConditions")
        >> Bend(AwsSagemakerLabelingJobStoppingConditions.mapping),
        "labeling_job_algorithms_config": S("LabelingJobAlgorithmsConfig")
        >> Bend(AwsSagemakerLabelingJobAlgorithmsConfig.mapping),
        "labeling_job_human_task_config": S("HumanTaskConfig") >> Bend(AwsSagemakerHumanTaskConfig.mapping),
        "labeling_job_output": S("LabelingJobOutput") >> Bend(AwsSagemakerLabelingJobOutput.mapping),
    }
    labeling_job_status: Optional[str] = field(default=None)
    labeling_job_label_counters: Optional[AwsSagemakerLabelCounters] = field(default=None)
    labeling_job_failure_reason: Optional[str] = field(default=None)
    labeling_job_job_reference_code: Optional[str] = field(default=None)
    labeling_job_label_attribute_name: Optional[str] = field(default=None)
    labeling_job_input_config: Optional[AwsSagemakerLabelingJobInputConfig] = field(default=None)
    labeling_job_output_config: Optional[AwsSagemakerLabelingJobOutputConfig] = field(default=None)
    labeling_job_role_arn: Optional[str] = field(default=None)
    labeling_job_label_category_config_s3_uri: Optional[str] = field(default=None)
    labeling_job_stopping_conditions: Optional[AwsSagemakerLabelingJobStoppingConditions] = field(default=None)
    labeling_job_algorithms_config: Optional[AwsSagemakerLabelingJobAlgorithmsConfig] = field(default=None)
    labeling_job_human_task_config: Optional[AwsSagemakerHumanTaskConfig] = field(default=None)
    labeling_job_output: Optional[AwsSagemakerLabelingJobOutput] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-labeling-job"), AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name,
                "describe-labeling-job",
                None,
                LabelingJobName=job["LabelingJobName"],
            )
            if job_description and (job_instance := AwsSagemakerLabelingJob.from_api(job_description, builder)):
                builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if ic := self.labeling_job_input_config:
            if ds := ic.data_source:
                if ds.s3_data_source:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ds.s3_data_source))
                if ds.sns_data_source:
                    builder.add_edge(self, clazz=AwsSnsTopic, arn=ds.sns_data_source)
        if oc := self.labeling_job_output_config:
            if oc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(oc.s3_output_path))
            if oc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(oc.kms_key_id))
            if oc.sns_topic_arn:
                builder.add_edge(self, clazz=AwsSnsTopic, arn=oc.sns_topic_arn)
        if self.labeling_job_role_arn:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.labeling_job_role_arn
            )
        if self.labeling_job_label_category_config_s3_uri:
            builder.add_edge(
                self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(self.labeling_job_label_category_config_s3_uri)
            )
        if jac := self.labeling_job_algorithms_config:
            if jac.initial_active_learning_model_arn:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerModel, arn=jac.initial_active_learning_model_arn)
            if jrc := jac.labeling_job_resource_config:
                if jrc.volume_kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(jrc.volume_kms_key_id))
                if vpc := jrc.vpc_config:
                    for security_group in vpc.security_group_ids:
                        builder.dependant_node(
                            self,
                            reverse=True,
                            delete_same_as_default=True,
                            clazz=AwsEc2SecurityGroup,
                            id=security_group,
                        )
                    for subnet in vpc.subnets:
                        builder.dependant_node(
                            self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet
                        )
        if htc := self.labeling_job_human_task_config:
            if htc.workteam_arn:
                builder.add_edge(self, reverse=True, clazz=AwsSagemakerWorkteam, arn=htc.workteam_arn)
            if ui := htc.ui_config:
                if ui.ui_template_s3_uri:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ui.ui_template_s3_uri))
            if htc.pre_human_task_lambda_arn:
                builder.add_edge(self, clazz=AwsLambdaFunction, arn=htc.pre_human_task_lambda_arn)
                # TODO should be dependant_node, see reference_kinds
        if out := self.labeling_job_output:
            if out.output_dataset_s3_uri:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(out.output_dataset_s3_uri))


@define(eq=False, slots=False)
class AwsSagemakerProcessingS3Input:
    kind: ClassVar[str] = "aws_sagemaker_processing_s3_input"
    kind_display: ClassVar[str] = "AWS SageMaker Processing S3 Input"
    kind_description: ClassVar[str] = (
        "S3 Input is used in Amazon SageMaker Processing, a service that runs"
        " processing tasks on large volumes of data in a distributed and managed way"
        " on AWS SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_uri": S("S3Uri"),
        "local_path": S("LocalPath"),
        "s3_data_type": S("S3DataType"),
        "s3_input_mode": S("S3InputMode"),
        "s3_data_distribution_type": S("S3DataDistributionType"),
        "s3_compression_type": S("S3CompressionType"),
    }
    s3_uri: Optional[str] = field(default=None)
    local_path: Optional[str] = field(default=None)
    s3_data_type: Optional[str] = field(default=None)
    s3_input_mode: Optional[str] = field(default=None)
    s3_data_distribution_type: Optional[str] = field(default=None)
    s3_compression_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAthenaDatasetDefinition:
    kind: ClassVar[str] = "aws_sagemaker_athena_dataset_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Athena Dataset Definition"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Athena Dataset Definition specifies the configuration for"
        " querying data with Athena, detailing the output format and location in S3."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "catalog": S("Catalog"),
        "database": S("Database"),
        "query_string": S("QueryString"),
        "work_group": S("WorkGroup"),
        "output_s3_uri": S("OutputS3Uri"),
        "kms_key_id": S("KmsKeyId"),
        "output_format": S("OutputFormat"),
        "output_compression": S("OutputCompression"),
    }
    catalog: Optional[str] = field(default=None)
    database: Optional[str] = field(default=None)
    query_string: Optional[str] = field(default=None)
    work_group: Optional[str] = field(default=None)
    output_s3_uri: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    output_format: Optional[str] = field(default=None)
    output_compression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerRedshiftDatasetDefinition:
    kind: ClassVar[str] = "aws_sagemaker_redshift_dataset_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Redshift Dataset Definition"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Redshift Dataset Definition is a configuration that identifies a specific Redshift cluster"
        " and database to create datasets, defines the SQL query for data extraction, and sets the S3 storage and"
        " output format for SageMaker use."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_id": S("ClusterId"),
        "database": S("Database"),
        "db_user": S("DbUser"),
        "query_string": S("QueryString"),
        "cluster_role_arn": S("ClusterRoleArn"),
        "output_s3_uri": S("OutputS3Uri"),
        "kms_key_id": S("KmsKeyId"),
        "output_format": S("OutputFormat"),
        "output_compression": S("OutputCompression"),
    }
    cluster_id: Optional[str] = field(default=None)
    database: Optional[str] = field(default=None)
    db_user: Optional[str] = field(default=None)
    query_string: Optional[str] = field(default=None)
    cluster_role_arn: Optional[str] = field(default=None)
    output_s3_uri: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    output_format: Optional[str] = field(default=None)
    output_compression: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDatasetDefinition:
    kind: ClassVar[str] = "aws_sagemaker_dataset_definition"
    kind_display: ClassVar[str] = "AWS SageMaker Dataset Definition"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Dataset Definition specifies configurations for datasets used in SageMaker, including"
        " those from Athena and Redshift, along with local storage options, data distribution types, and the mode"
        " in which the dataset is inputted into SageMaker for processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "athena_dataset_definition": S("AthenaDatasetDefinition") >> Bend(AwsSagemakerAthenaDatasetDefinition.mapping),
        "redshift_dataset_definition": S("RedshiftDatasetDefinition")
        >> Bend(AwsSagemakerRedshiftDatasetDefinition.mapping),
        "local_path": S("LocalPath"),
        "data_distribution_type": S("DataDistributionType"),
        "input_mode": S("InputMode"),
    }
    athena_dataset_definition: Optional[AwsSagemakerAthenaDatasetDefinition] = field(default=None)
    redshift_dataset_definition: Optional[AwsSagemakerRedshiftDatasetDefinition] = field(default=None)
    local_path: Optional[str] = field(default=None)
    data_distribution_type: Optional[str] = field(default=None)
    input_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingInput:
    kind: ClassVar[str] = "aws_sagemaker_processing_input"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Input"
    kind_description: ClassVar[str] = (
        "SageMaker Processing Input is a resource in Amazon SageMaker that represents"
        " the input data for a processing job. It is used to provide data to be"
        " processed by SageMaker algorithms or custom code."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "input_name": S("InputName"),
        "app_managed": S("AppManaged"),
        "s3_input": S("S3Input") >> Bend(AwsSagemakerProcessingS3Input.mapping),
        "dataset_definition": S("DatasetDefinition") >> Bend(AwsSagemakerDatasetDefinition.mapping),
    }
    input_name: Optional[str] = field(default=None)
    app_managed: Optional[bool] = field(default=None)
    s3_input: Optional[AwsSagemakerProcessingS3Input] = field(default=None)
    dataset_definition: Optional[AwsSagemakerDatasetDefinition] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingS3Output:
    kind: ClassVar[str] = "aws_sagemaker_processing_s3_output"
    kind_display: ClassVar[str] = "AWS SageMaker Processing S3 Output"
    kind_description: ClassVar[str] = (
        "SageMaker Processing S3 Output is the output location in Amazon S3 for the"
        " output artifacts generated during the data processing tasks performed by"
        " Amazon SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_uri": S("S3Uri"),
        "local_path": S("LocalPath"),
        "s3_upload_mode": S("S3UploadMode"),
    }
    s3_uri: Optional[str] = field(default=None)
    local_path: Optional[str] = field(default=None)
    s3_upload_mode: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingOutput:
    kind: ClassVar[str] = "aws_sagemaker_processing_output"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Output"
    kind_description: ClassVar[str] = (
        "SageMaker Processing Output is the result of running data processing"
        " operations on the Amazon SageMaker platform, which is used for building,"
        " training, and deploying machine learning models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_name": S("OutputName"),
        "s3_output": S("S3Output") >> Bend(AwsSagemakerProcessingS3Output.mapping),
        "feature_store_output": S("FeatureStoreOutput", "FeatureGroupName"),
        "app_managed": S("AppManaged"),
    }
    output_name: Optional[str] = field(default=None)
    s3_output: Optional[AwsSagemakerProcessingS3Output] = field(default=None)
    feature_store_output: Optional[str] = field(default=None)
    app_managed: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_processing_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Output Config"
    kind_description: ClassVar[str] = (
        "SageMaker Processing Output Config is a configuration that specifies where"
        " and how the output of a SageMaker processing job should be stored."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "outputs": S("Outputs", default=[]) >> ForallBend(AwsSagemakerProcessingOutput.mapping),
        "kms_key_id": S("KmsKeyId"),
    }
    outputs: List[AwsSagemakerProcessingOutput] = field(factory=list)
    kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingClusterConfig:
    kind: ClassVar[str] = "aws_sagemaker_processing_cluster_config"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Cluster Config"
    kind_description: ClassVar[str] = (
        "SageMaker Processing Cluster Config provides configuration settings for"
        " creating and managing processing clusters in Amazon SageMaker. Processing"
        " clusters allow users to run data processing tasks on large datasets in a"
        " distributed and scalable manner."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_count": S("InstanceCount"),
        "instance_type": S("InstanceType"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "volume_kms_key_id": S("VolumeKmsKeyId"),
    }
    instance_count: Optional[int] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)
    volume_kms_key_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingResources:
    kind: ClassVar[str] = "aws_sagemaker_processing_resources"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Resources"
    kind_description: ClassVar[str] = (
        "SageMaker processing resources in AWS are used for running data processing"
        " workloads, allowing users to perform data transformations, feature"
        " engineering, and other preprocessing tasks efficiently."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_config": S("ClusterConfig") >> Bend(AwsSagemakerProcessingClusterConfig.mapping)
    }
    cluster_config: Optional[AwsSagemakerProcessingClusterConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerAppSpecification:
    kind: ClassVar[str] = "aws_sagemaker_app_specification"
    kind_display: ClassVar[str] = "AWS SageMaker App Specification"
    kind_description: ClassVar[str] = (
        "SageMaker App Specification is a resource in AWS that allows you to define"
        " the container environment and dependencies for running an application on"
        " Amazon SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "image_uri": S("ImageUri"),
        "container_entrypoint": S("ContainerEntrypoint", default=[]),
        "container_arguments": S("ContainerArguments", default=[]),
    }
    image_uri: Optional[str] = field(default=None)
    container_entrypoint: List[str] = field(factory=list)
    container_arguments: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerNetworkConfig:
    kind: ClassVar[str] = "aws_sagemaker_network_config"
    kind_display: ClassVar[str] = "AWS SageMaker Network Config"
    kind_description: ClassVar[str] = (
        "SageMaker Network Config is a configuration option in Amazon SageMaker that"
        " allows you to customize the network settings for your machine learning"
        " models, such as VPC configurations and security group configurations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "enable_inter_container_traffic_encryption": S("EnableInterContainerTrafficEncryption"),
        "enable_network_isolation": S("EnableNetworkIsolation"),
        "vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
    }
    enable_inter_container_traffic_encryption: Optional[bool] = field(default=None)
    enable_network_isolation: Optional[bool] = field(default=None)
    vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProcessingJob(AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_processing_job"
    kind_display: ClassVar[str] = "AWS SageMaker Processing Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:processing-job/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Processing Jobs provide a managed infrastructure for executing"
        " data processing tasks in Amazon SageMaker, enabling users to preprocess and"
        " analyze data efficiently."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_iam_role",
                "aws_ec2_security_group",
                "aws_ec2_subnet",
                "aws_athena_data_catalog",
                "aws_athena_work_group",
                "aws_redshift_cluster",
                "aws_sagemaker_experiment",
                "aws_sagemaker_trial",
            ],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_s3_bucket", "aws_kms_key", "aws_sagemaker_training_job"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-processing-jobs", "ProcessingJobSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ProcessingJobName"),
        "name": S("ProcessingJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("ProcessingJobArn"),
        "processing_job_processing_inputs": S("ProcessingInputs", default=[])
        >> ForallBend(AwsSagemakerProcessingInput.mapping),
        "processing_job_processing_output_config": S("ProcessingOutputConfig")
        >> Bend(AwsSagemakerProcessingOutputConfig.mapping),
        "processing_job_processing_resources": S("ProcessingResources")
        >> Bend(AwsSagemakerProcessingResources.mapping),
        "processing_job_stopping_condition": S("StoppingCondition", "MaxRuntimeInSeconds"),
        "processing_job_app_specification": S("AppSpecification") >> Bend(AwsSagemakerAppSpecification.mapping),
        "processing_job_environment": S("Environment"),
        "processing_job_network_config": S("NetworkConfig") >> Bend(AwsSagemakerNetworkConfig.mapping),
        "processing_job_role_arn": S("RoleArn"),
        "processing_job_trial_component_display_name": S("ExperimentConfig", "TrialComponentDisplayName"),
        "processing_job_status": S("ProcessingJobStatus"),
        "processing_job_exit_message": S("ExitMessage"),
        "processing_job_failure_reason": S("FailureReason"),
        "processing_job_processing_end_time": S("ProcessingEndTime"),
        "processing_job_processing_start_time": S("ProcessingStartTime"),
        "processing_job_monitoring_schedule_arn": S("MonitoringScheduleArn"),
        "processing_job_auto_ml_job_arn": S("AutoMLJobArn"),
    }
    processing_job_processing_inputs: List[AwsSagemakerProcessingInput] = field(factory=list)
    processing_job_processing_output_config: Optional[AwsSagemakerProcessingOutputConfig] = field(default=None)
    processing_job_processing_resources: Optional[AwsSagemakerProcessingResources] = field(default=None)
    processing_job_stopping_condition: Optional[int] = field(default=None)
    processing_job_app_specification: Optional[AwsSagemakerAppSpecification] = field(default=None)
    processing_job_environment: Optional[Dict[str, str]] = field(default=None)
    processing_job_network_config: Optional[AwsSagemakerNetworkConfig] = field(default=None)
    processing_job_role_arn: Optional[str] = field(default=None)
    processing_job_trial_component_display_name: Optional[str] = field(default=None)
    processing_job_status: Optional[str] = field(default=None)
    processing_job_exit_message: Optional[str] = field(default=None)
    processing_job_failure_reason: Optional[str] = field(default=None)
    processing_job_processing_end_time: Optional[datetime] = field(default=None)
    processing_job_processing_start_time: Optional[datetime] = field(default=None)
    processing_job_monitoring_schedule_arn: Optional[str] = field(default=None)
    processing_job_auto_ml_job_arn: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-processing-job")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name,
                "describe-processing-job",
                None,
                ProcessingJobName=job["ProcessingJobName"],
            )
            if job_description and (job_instance := AwsSagemakerProcessingJob.from_api(job_description, builder)):
                builder.add_node(job_instance, job_description)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for input in self.processing_job_processing_inputs:
            if input.s3_input:
                if input.s3_input.s3_uri:
                    builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(input.s3_input.s3_uri))
            if dd := input.dataset_definition:
                if ath := dd.athena_dataset_definition:
                    if ath.catalog:
                        builder.add_edge(self, reverse=True, clazz=AwsAthenaDataCatalog, name=ath.catalog)
                    if ath.work_group:
                        builder.add_edge(self, reverse=True, clazz=AwsAthenaWorkGroup, name=ath.work_group)
                    if ath.output_s3_uri:
                        builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ath.output_s3_uri))
                    if ath.kms_key_id:
                        builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(ath.kms_key_id))
                if red := dd.redshift_dataset_definition:
                    if red.cluster_id:
                        builder.add_edge(self, reverse=True, clazz=AwsRedshiftCluster, id=red.cluster_id)
                    if red.cluster_role_arn:
                        builder.dependant_node(
                            self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=red.cluster_role_arn
                        )
                    if red.output_s3_uri:
                        builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(red.output_s3_uri))
                    if red.kms_key_id:
                        builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(red.kms_key_id))
        if poc := self.processing_job_processing_output_config:
            for output in poc.outputs:
                if s3 := output.s3_output:
                    if s3.s3_uri:
                        builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(s3.s3_uri))
            if poc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(poc.kms_key_id))
        if pr := self.processing_job_processing_resources:
            if cc := pr.cluster_config:
                if cc.volume_kms_key_id:
                    builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(cc.volume_kms_key_id))
        if nc := self.processing_job_network_config:
            if vpc := nc.vpc_config:
                for security_group in vpc.security_group_ids:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                    )
                for subnet in vpc.subnets:
                    builder.dependant_node(
                        self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet
                    )
        if self.processing_job_role_arn:
            builder.dependant_node(
                self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.processing_job_role_arn
            )
        if experiment := value_in_path(source, ["ExperimentConfig", "ExperimentName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerExperiment, name=experiment)
        if trial := value_in_path(source, ["ExperimentConfig", "TrialName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerTrial, name=trial)
        if training_job := value_in_path(source, "TrainingJobArn"):
            builder.add_edge(self, clazz=AwsSagemakerTrainingJob, arn=training_job)


@define(eq=False, slots=False)
class AwsSagemakerAlgorithmSpecification:
    kind: ClassVar[str] = "aws_sagemaker_algorithm_specification"
    kind_display: ClassVar[str] = "AWS SageMaker Algorithm Specification"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Algorithm Specification is a specification that defines"
        " the characteristics and requirements of custom algorithms for Amazon"
        " SageMaker, a fully-managed machine learning service provided by Amazon Web"
        " Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "training_image": S("TrainingImage"),
        "algorithm_name": S("AlgorithmName"),
        "training_input_mode": S("TrainingInputMode"),
        "metric_definitions": S("MetricDefinitions", default=[]) >> ForallBend(AwsSagemakerMetricDefinition.mapping),
        "enable_sage_maker_metrics_time_series": S("EnableSageMakerMetricsTimeSeries"),
        "container_entrypoint": S("ContainerEntrypoint", default=[]),
        "container_arguments": S("ContainerArguments", default=[]),
    }
    training_image: Optional[str] = field(default=None)
    algorithm_name: Optional[str] = field(default=None)
    training_input_mode: Optional[str] = field(default=None)
    metric_definitions: List[AwsSagemakerMetricDefinition] = field(factory=list)
    enable_sage_maker_metrics_time_series: Optional[bool] = field(default=None)
    container_entrypoint: List[str] = field(factory=list)
    container_arguments: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerSecondaryStatusTransition:
    kind: ClassVar[str] = "aws_sagemaker_secondary_status_transition"
    kind_display: ClassVar[str] = "AWS SageMaker Secondary Status Transition"
    kind_description: ClassVar[str] = (
        "Secondary status transition in Amazon SageMaker represents the state of the"
        " training or processing job after reaching a certain status."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "start_time": S("StartTime"),
        "end_time": S("EndTime"),
        "status_message": S("StatusMessage"),
    }
    status: Optional[str] = field(default=None)
    start_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    status_message: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerMetricData:
    kind: ClassVar[str] = "aws_sagemaker_metric_data"
    kind_display: ClassVar[str] = "AWS SageMaker Metric Data"
    kind_description: ClassVar[str] = (
        "SageMaker Metric Data is a feature of AWS SageMaker that allows users to"
        " monitor and track machine learning model metrics during training and"
        " inference."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "metric_name": S("MetricName"),
        "value": S("Value"),
        "timestamp": S("Timestamp"),
    }
    metric_name: Optional[str] = field(default=None)
    value: Optional[float] = field(default=None)
    timestamp: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerCollectionConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_collection_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Collection Configuration"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Collection Configuration organizes machine learning resources or data"
        " by name and specified parameters within SageMaker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "collection_name": S("CollectionName"),
        "collection_parameters": S("CollectionParameters"),
    }
    collection_name: Optional[str] = field(default=None)
    collection_parameters: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDebugHookConfig:
    kind: ClassVar[str] = "aws_sagemaker_debug_hook_config"
    kind_display: ClassVar[str] = "AWS SageMaker Debug Hook Config"
    kind_description: ClassVar[str] = (
        "SageMaker Debug Hook Config is a feature of Amazon SageMaker, a fully"
        " managed service that enables developers to build, train, and deploy machine"
        " learning models. The Debug Hook Config allows for monitoring and debugging"
        " of the models during training."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "local_path": S("LocalPath"),
        "s3_output_path": S("S3OutputPath"),
        "hook_parameters": S("HookParameters"),
        "collection_configurations": S("CollectionConfigurations", default=[])
        >> ForallBend(AwsSagemakerCollectionConfiguration.mapping),
    }
    local_path: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)
    hook_parameters: Optional[Dict[str, str]] = field(default=None)
    collection_configurations: List[AwsSagemakerCollectionConfiguration] = field(factory=list)


@define(eq=False, slots=False)
class AwsSagemakerDebugRuleConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_debug_rule_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Debug Rule Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker Debug Rule Configuration is a feature in Amazon SageMaker that"
        " allows users to define debugging rules for machine learning models, helping"
        " to identify and fix issues in the training or deployment process."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_configuration_name": S("RuleConfigurationName"),
        "local_path": S("LocalPath"),
        "s3_output_path": S("S3OutputPath"),
        "rule_evaluator_image": S("RuleEvaluatorImage"),
        "instance_type": S("InstanceType"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "rule_parameters": S("RuleParameters"),
    }
    rule_configuration_name: Optional[str] = field(default=None)
    local_path: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)
    rule_evaluator_image: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)
    rule_parameters: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTensorBoardOutputConfig:
    kind: ClassVar[str] = "aws_sagemaker_tensor_board_output_config"
    kind_display: ClassVar[str] = "AWS SageMaker TensorBoard Output Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker TensorBoard Output Config sets up the storage location for TensorBoard"
        " data, allowing you to specify local file paths and an S3 bucket for output."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"local_path": S("LocalPath"), "s3_output_path": S("S3OutputPath")}
    local_path: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDebugRuleEvaluationStatus:
    kind: ClassVar[str] = "aws_sagemaker_debug_rule_evaluation_status"
    kind_display: ClassVar[str] = "AWS SageMaker Debug Rule Evaluation Status"
    kind_description: ClassVar[str] = (
        "SageMaker Debug Rule Evaluation Status represents the evaluation status of"
        " the debug rules in Amazon SageMaker, which helps in debugging and monitoring"
        " machine learning models during training and deployment."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_configuration_name": S("RuleConfigurationName"),
        "rule_evaluation_job_arn": S("RuleEvaluationJobArn"),
        "rule_evaluation_status": S("RuleEvaluationStatus"),
        "status_details": S("StatusDetails"),
        "last_modified_time": S("LastModifiedTime"),
    }
    rule_configuration_name: Optional[str] = field(default=None)
    rule_evaluation_job_arn: Optional[str] = field(default=None)
    rule_evaluation_status: Optional[str] = field(default=None)
    status_details: Optional[str] = field(default=None)
    last_modified_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProfilerConfig:
    kind: ClassVar[str] = "aws_sagemaker_profiler_config"
    kind_display: ClassVar[str] = "AWS SageMaker Profiler Configuration"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Profiler Configuration is used to set up the output location for profiling data,"
        " the frequency of profiling, and additional parameters for detailed control over the profiling"
        " behavior of SageMaker training jobs."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "s3_output_path": S("S3OutputPath"),
        "profiling_interval_in_milliseconds": S("ProfilingIntervalInMilliseconds"),
        "profiling_parameters": S("ProfilingParameters"),
    }
    s3_output_path: Optional[str] = field(default=None)
    profiling_interval_in_milliseconds: Optional[int] = field(default=None)
    profiling_parameters: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProfilerRuleConfiguration:
    kind: ClassVar[str] = "aws_sagemaker_profiler_rule_configuration"
    kind_display: ClassVar[str] = "AWS SageMaker Profiler Rule Configuration"
    kind_description: ClassVar[str] = (
        "SageMaker Profiler Rule Configuration is a feature provided by AWS SageMaker"
        " that allows defining rules for profiling machine learning models during"
        " training to identify potential performance and resource utilization issues."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_configuration_name": S("RuleConfigurationName"),
        "local_path": S("LocalPath"),
        "s3_output_path": S("S3OutputPath"),
        "rule_evaluator_image": S("RuleEvaluatorImage"),
        "instance_type": S("InstanceType"),
        "volume_size_in_gb": S("VolumeSizeInGB"),
        "rule_parameters": S("RuleParameters"),
    }
    rule_configuration_name: Optional[str] = field(default=None)
    local_path: Optional[str] = field(default=None)
    s3_output_path: Optional[str] = field(default=None)
    rule_evaluator_image: Optional[str] = field(default=None)
    instance_type: Optional[str] = field(default=None)
    volume_size_in_gb: Optional[int] = field(default=None)
    rule_parameters: Optional[Dict[str, str]] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerProfilerRuleEvaluationStatus:
    kind: ClassVar[str] = "aws_sagemaker_profiler_rule_evaluation_status"
    kind_display: ClassVar[str] = "AWS SageMaker Profiler Rule Evaluation Status"
    kind_description: ClassVar[str] = (
        "SageMaker Profiler Rule Evaluation Status is a feature in Amazon SageMaker"
        " that allows users to monitor and assess the performance of machine learning"
        " models by evaluating predefined rules."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "rule_configuration_name": S("RuleConfigurationName"),
        "rule_evaluation_job_arn": S("RuleEvaluationJobArn"),
        "rule_evaluation_status": S("RuleEvaluationStatus"),
        "status_details": S("StatusDetails"),
        "last_modified_time": S("LastModifiedTime"),
    }
    rule_configuration_name: Optional[str] = field(default=None)
    rule_evaluation_job_arn: Optional[str] = field(default=None)
    rule_evaluation_status: Optional[str] = field(default=None)
    status_details: Optional[str] = field(default=None)
    last_modified_time: Optional[datetime] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerWarmPoolStatus:
    kind: ClassVar[str] = "aws_sagemaker_warm_pool_status"
    kind_display: ClassVar[str] = "AWS SageMaker Warm Pool Status"
    kind_description: ClassVar[str] = (
        "SageMaker Warm Pool Status refers to the current state of a warm pool in AWS"
        " SageMaker, which is a collection of pre-initialized instances that can be"
        " used to speed up the deployment and inference process for machine learning"
        " models."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "status": S("Status"),
        "resource_retained_billable_time_in_seconds": S("ResourceRetainedBillableTimeInSeconds"),
        "reused_by_job": S("ReusedByJob"),
    }
    status: Optional[str] = field(default=None)
    resource_retained_billable_time_in_seconds: Optional[int] = field(default=None)
    reused_by_job: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTrainingJob(SagemakerTaggable, AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_training_job"
    kind_display: ClassVar[str] = "AWS SageMaker Training Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:sagemaker-training-job/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Training Job is a service provided by AWS that allows users to"
        " train machine learning models and build high-quality custom models."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_sagemaker_labeling_job",
                "aws_iam_role",
                "aws_ec2_security_group",
                "aws_ec2_subnet",
                "aws_sagemaker_experiment",
                "aws_sagemaker_trial",
            ],
            "delete": ["aws_kms_key", "aws_iam_role", "aws_ec2_subnet", "aws_ec2_security_group"],
        },
        "successors": {"default": ["aws_s3_bucket", "aws_kms_key", "aws_sagemaker_algorithm"]},
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-training-jobs", "TrainingJobSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TrainingJobName"),
        "name": S("TrainingJobName"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "arn": S("TrainingJobArn"),
        "training_job_tuning_job_arn": S("TuningJobArn"),
        "training_job_labeling_job_arn": S("LabelingJobArn"),
        "training_job_auto_ml_job_arn": S("AutoMLJobArn"),
        "training_job_model_artifacts": S("ModelArtifacts", "S3ModelArtifacts"),
        "training_job_training_job_status": S("TrainingJobStatus"),
        "training_job_secondary_status": S("SecondaryStatus"),
        "training_job_failure_reason": S("FailureReason"),
        "training_job_hyper_parameters": S("HyperParameters"),
        "training_job_algorithm_specification": S("AlgorithmSpecification")
        >> Bend(AwsSagemakerAlgorithmSpecification.mapping),
        "training_job_input_data_config": S("InputDataConfig", default=[]) >> ForallBend(AwsSagemakerChannel.mapping),
        "training_job_output_data_config": S("OutputDataConfig") >> Bend(AwsSagemakerOutputDataConfig.mapping),
        "training_job_resource_config": S("ResourceConfig") >> Bend(AwsSagemakerResourceConfig.mapping),
        "training_job_vpc_config": S("VpcConfig") >> Bend(AwsSagemakerVpcConfig.mapping),
        "training_job_stopping_condition": S("StoppingCondition") >> Bend(AwsSagemakerStoppingCondition.mapping),
        "training_job_training_start_time": S("TrainingStartTime"),
        "training_job_training_end_time": S("TrainingEndTime"),
        "training_job_secondary_status_transitions": S("SecondaryStatusTransitions", default=[])
        >> ForallBend(AwsSagemakerSecondaryStatusTransition.mapping),
        "training_job_final_metric_data_list": S("FinalMetricDataList", default=[])
        >> ForallBend(AwsSagemakerMetricData.mapping),
        "training_job_enable_network_isolation": S("EnableNetworkIsolation"),
        "training_job_enable_inter_container_traffic_encryption": S("EnableInterContainerTrafficEncryption"),
        "training_job_enable_managed_spot_training": S("EnableManagedSpotTraining"),
        "training_job_checkpoint_config": S("CheckpointConfig") >> Bend(AwsSagemakerCheckpointConfig.mapping),
        "training_job_training_time_in_seconds": S("TrainingTimeInSeconds"),
        "training_job_billable_time_in_seconds": S("BillableTimeInSeconds"),
        "training_job_debug_hook_config": S("DebugHookConfig") >> Bend(AwsSagemakerDebugHookConfig.mapping),
        "training_job_trial_component_display_name": S("ExperimentConfig", "TrialComponentDisplayName"),
        "training_job_debug_rule_configurations": S("DebugRuleConfigurations", default=[])
        >> ForallBend(AwsSagemakerDebugRuleConfiguration.mapping),
        "training_job_tensor_board_output_config": S("TensorBoardOutputConfig")
        >> Bend(AwsSagemakerTensorBoardOutputConfig.mapping),
        "training_job_debug_rule_evaluation_statuses": S("DebugRuleEvaluationStatuses", default=[])
        >> ForallBend(AwsSagemakerDebugRuleEvaluationStatus.mapping),
        "training_job_profiler_config": S("ProfilerConfig") >> Bend(AwsSagemakerProfilerConfig.mapping),
        "training_job_profiler_rule_configurations": S("ProfilerRuleConfigurations", default=[])
        >> ForallBend(AwsSagemakerProfilerRuleConfiguration.mapping),
        "training_job_profiler_rule_evaluation_statuses": S("ProfilerRuleEvaluationStatuses", default=[])
        >> ForallBend(AwsSagemakerProfilerRuleEvaluationStatus.mapping),
        "training_job_profiling_status": S("ProfilingStatus"),
        "training_job_retry_strategy": S("RetryStrategy", "MaximumRetryAttempts"),
        "training_job_environment": S("Environment"),
        "training_job_warm_pool_status": S("WarmPoolStatus") >> Bend(AwsSagemakerWarmPoolStatus.mapping),
    }
    training_job_tuning_job_arn: Optional[str] = field(default=None)
    training_job_labeling_job_arn: Optional[str] = field(default=None)
    training_job_auto_ml_job_arn: Optional[str] = field(default=None)
    training_job_model_artifacts: Optional[str] = field(default=None)
    training_job_training_job_status: Optional[str] = field(default=None)
    training_job_secondary_status: Optional[str] = field(default=None)
    training_job_failure_reason: Optional[str] = field(default=None)
    training_job_hyper_parameters: Optional[Dict[str, str]] = field(default=None)
    training_job_algorithm_specification: Optional[AwsSagemakerAlgorithmSpecification] = field(default=None)
    training_job_input_data_config: List[AwsSagemakerChannel] = field(factory=list)
    training_job_output_data_config: Optional[AwsSagemakerOutputDataConfig] = field(default=None)
    training_job_resource_config: Optional[AwsSagemakerResourceConfig] = field(default=None)
    training_job_vpc_config: Optional[AwsSagemakerVpcConfig] = field(default=None)
    training_job_stopping_condition: Optional[AwsSagemakerStoppingCondition] = field(default=None)
    training_job_training_start_time: Optional[datetime] = field(default=None)
    training_job_training_end_time: Optional[datetime] = field(default=None)
    training_job_secondary_status_transitions: List[AwsSagemakerSecondaryStatusTransition] = field(factory=list)
    training_job_final_metric_data_list: List[AwsSagemakerMetricData] = field(factory=list)
    training_job_enable_network_isolation: Optional[bool] = field(default=None)
    training_job_enable_inter_container_traffic_encryption: Optional[bool] = field(default=None)
    training_job_enable_managed_spot_training: Optional[bool] = field(default=None)
    training_job_checkpoint_config: Optional[AwsSagemakerCheckpointConfig] = field(default=None)
    training_job_training_time_in_seconds: Optional[int] = field(default=None)
    training_job_billable_time_in_seconds: Optional[int] = field(default=None)
    training_job_debug_hook_config: Optional[AwsSagemakerDebugHookConfig] = field(default=None)
    training_job_trial_component_display_name: Optional[str] = field(default=None)
    training_job_debug_rule_configurations: List[AwsSagemakerDebugRuleConfiguration] = field(factory=list)
    training_job_tensor_board_output_config: Optional[AwsSagemakerTensorBoardOutputConfig] = field(default=None)
    training_job_debug_rule_evaluation_statuses: List[AwsSagemakerDebugRuleEvaluationStatus] = field(factory=list)
    training_job_profiler_config: Optional[AwsSagemakerProfilerConfig] = field(default=None)
    training_job_profiler_rule_configurations: List[AwsSagemakerProfilerRuleConfiguration] = field(factory=list)
    training_job_profiler_rule_evaluation_statuses: List[AwsSagemakerProfilerRuleEvaluationStatus] = field(factory=list)
    training_job_profiling_status: Optional[str] = field(default=None)
    training_job_retry_strategy: Optional[int] = field(default=None)
    training_job_environment: Optional[Dict[str, str]] = field(default=None)
    training_job_warm_pool_status: Optional[AwsSagemakerWarmPoolStatus] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-training-job"), AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            job_description = builder.client.get(
                service_name,
                "describe-training-job",
                None,
                TrainingJobName=job["TrainingJobName"],
            )
            if job_description:
                if job_instance := AwsSagemakerTrainingJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)
                    builder.submit_work(service_name, SagemakerTaggable.add_tags, job_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.training_job_labeling_job_arn:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerLabelingJob, arn=self.training_job_labeling_job_arn)
        if self.training_job_model_artifacts:
            builder.add_edge(
                self,
                clazz=AwsS3Bucket,
                name=AwsS3Bucket.name_from_path(self.training_job_model_artifacts),
            )
        if tjas := self.training_job_algorithm_specification:
            if tjas.algorithm_name:
                builder.add_edge(self, clazz=AwsSagemakerAlgorithm, name=tjas.algorithm_name)
        if role_arn := value_in_path(source, "RoleArn"):
            builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=role_arn)
        for config in self.training_job_input_data_config:
            if ids := config.data_source:
                if ids.s3_data_source:
                    if ids.s3_data_source.s3_uri:
                        builder.add_edge(
                            self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(ids.s3_data_source.s3_uri)
                        )
        if odc := self.training_job_output_data_config:
            if odc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(odc.kms_key_id))
            if odc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(odc.s3_output_path))
        if rc := self.training_job_resource_config:
            if rc.volume_kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(rc.volume_kms_key_id))
        if vpc := self.training_job_vpc_config:
            for security_group in vpc.security_group_ids:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group
                )
            for subnet in vpc.subnets:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet)
        if cc := self.training_job_checkpoint_config:
            if cc.s3_uri:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(cc.s3_uri))
        if dhc := self.training_job_debug_hook_config:
            if dhc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(dhc.s3_output_path))
        if experiment := value_in_path(source, ["ExperimentConfig", "ExperimentName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerExperiment, name=experiment)
        if trial := value_in_path(source, ["ExperimentConfig", "TrialName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerTrial, name=trial)
        for rule in self.training_job_debug_rule_configurations:
            if rule.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(rule.s3_output_path))
        if tboc := self.training_job_tensor_board_output_config:
            if tboc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(tboc.s3_output_path))
        if tjpc := self.training_job_profiler_config:
            if tjpc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(tjpc.s3_output_path))
        for tjrc in self.training_job_profiler_rule_configurations:
            if tjrc.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(tjrc.s3_output_path))


@define(eq=False, slots=False)
class AwsSagemakerModelClientConfig:
    kind: ClassVar[str] = "aws_sagemaker_model_client_config"
    kind_display: ClassVar[str] = "AWS SageMaker Model Client Config"
    kind_description: ClassVar[str] = (
        "AWS SageMaker Model Client Config optimizes model inference by setting a timeout"
        " for prediction invocations and specifying the maximum number of retry attempts."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "invocations_timeout_in_seconds": S("InvocationsTimeoutInSeconds"),
        "invocations_max_retries": S("InvocationsMaxRetries"),
    }
    invocations_timeout_in_seconds: Optional[int] = field(default=None)
    invocations_max_retries: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerBatchDataCaptureConfig:
    kind: ClassVar[str] = "aws_sagemaker_batch_data_capture_config"
    kind_display: ClassVar[str] = "AWS SageMaker Batch Data Capture Config"
    kind_description: ClassVar[str] = (
        "The AWS SageMaker Batch Data Capture Config allows for the collection and storage of"
        " inference data, with options for encryption and inference ID generation, to an S3 location."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "destination_s3_uri": S("DestinationS3Uri"),
        "kms_key_id": S("KmsKeyId"),
        "generate_inference_id": S("GenerateInferenceId"),
    }
    destination_s3_uri: Optional[str] = field(default=None)
    kms_key_id: Optional[str] = field(default=None)
    generate_inference_id: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerDataProcessing:
    kind: ClassVar[str] = "aws_sagemaker_data_processing"
    kind_display: ClassVar[str] = "AWS SageMaker Data Processing"
    kind_description: ClassVar[str] = (
        "SageMaker Data Processing is a service offered by AWS that allows data"
        " scientists and developers to easily preprocess and transform large amounts"
        " of data for machine learning purposes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "input_filter": S("InputFilter"),
        "output_filter": S("OutputFilter"),
        "join_source": S("JoinSource"),
    }
    input_filter: Optional[str] = field(default=None)
    output_filter: Optional[str] = field(default=None)
    join_source: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsSagemakerTransformJob(SagemakerTaggable, AwsSagemakerJob):
    kind: ClassVar[str] = "aws_sagemaker_transform_job"
    kind_display: ClassVar[str] = "AWS SageMaker Transform Job"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:sagemaker:{region}:{account}:transform-job/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "SageMaker Transform Jobs are used in Amazon SageMaker to transform input"
        " data using a trained model, generating output results for further analysis"
        " or inference."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": [
                "aws_sagemaker_labeling_job",
                "aws_sagemaker_experiment",
                "aws_sagemaker_trial",
                "aws_sagemaker_model",
            ],
            "delete": ["aws_kms_key"],
        },
        "successors": {
            "default": ["aws_s3_bucket", "aws_kms_key"],
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-transform-jobs", "TransformJobSummaries")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("TransformJobName"),
        "name": S("TransformJobName"),
        "ctime": S("CreationTime"),
        "arn": S("TransformJobArn"),
        "transform_job_status": S("TransformJobStatus"),
        "transform_job_failure_reason": S("FailureReason"),
        "transform_job_model_name": S("ModelName"),
        "transform_job_max_concurrent_transforms": S("MaxConcurrentTransforms"),
        "transform_job_model_client_config": S("ModelClientConfig") >> Bend(AwsSagemakerModelClientConfig.mapping),
        "transform_job_max_payload_in_mb": S("MaxPayloadInMB"),
        "transform_job_batch_strategy": S("BatchStrategy"),
        "transform_job_environment": S("Environment"),
        "transform_job_transform_input": S("TransformInput") >> Bend(AwsSagemakerTransformInput.mapping),
        "transform_job_transform_output": S("TransformOutput") >> Bend(AwsSagemakerTransformOutput.mapping),
        "transform_job_data_capture_config": S("DataCaptureConfig") >> Bend(AwsSagemakerBatchDataCaptureConfig.mapping),
        "transform_job_transform_resources": S("TransformResources") >> Bend(AwsSagemakerTransformResources.mapping),
        "transform_job_transform_start_time": S("TransformStartTime"),
        "transform_job_transform_end_time": S("TransformEndTime"),
        "transform_job_labeling_job_arn": S("LabelingJobArn"),
        "transform_job_auto_ml_job_arn": S("AutoMLJobArn"),
        "transform_job_data_processing": S("DataProcessing") >> Bend(AwsSagemakerDataProcessing.mapping),
        "transform_job_trial_component_display_name": S("ExperimentConfig", "TrialComponentDisplayName"),
    }
    transform_job_status: Optional[str] = field(default=None)
    transform_job_failure_reason: Optional[str] = field(default=None)
    transform_job_model_name: Optional[str] = field(default=None)
    transform_job_max_concurrent_transforms: Optional[int] = field(default=None)
    transform_job_model_client_config: Optional[AwsSagemakerModelClientConfig] = field(default=None)
    transform_job_max_payload_in_mb: Optional[int] = field(default=None)
    transform_job_batch_strategy: Optional[str] = field(default=None)
    transform_job_environment: Optional[Dict[str, str]] = field(default=None)
    transform_job_transform_input: Optional[AwsSagemakerTransformInput] = field(default=None)
    transform_job_transform_output: Optional[AwsSagemakerTransformOutput] = field(default=None)
    transform_job_data_capture_config: Optional[AwsSagemakerBatchDataCaptureConfig] = field(default=None)
    transform_job_transform_resources: Optional[AwsSagemakerTransformResources] = field(default=None)
    transform_job_transform_start_time: Optional[datetime] = field(default=None)
    transform_job_transform_end_time: Optional[datetime] = field(default=None)
    transform_job_labeling_job_arn: Optional[str] = field(default=None)
    transform_job_auto_ml_job_arn: Optional[str] = field(default=None)
    transform_job_data_processing: Optional[AwsSagemakerDataProcessing] = field(default=None)
    transform_job_trial_component_display_name: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(service_name, "describe-transform-job"), AwsApiSpec(service_name, "list-tags")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for job in json:
            if job_description := builder.client.get(
                service_name,
                "describe-transform-job",
                None,
                TransformJobName=job["TransformJobName"],
            ):
                if job_instance := AwsSagemakerTransformJob.from_api(job_description, builder):
                    builder.add_node(job_instance, job_description)
                    builder.submit_work(service_name, SagemakerTaggable.add_tags, job_instance, builder)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if self.transform_job_model_name:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerModel, name=self.transform_job_model_name)
        if tin := self.transform_job_transform_input:
            if ds := tin.data_source:
                if s3 := ds.s3_data_source:
                    if s3.s3_uri:
                        builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(s3.s3_uri))
        if tout := self.transform_job_transform_output:
            if tout.s3_output_path:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(tout.s3_output_path))
            if tout.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(tout.kms_key_id))
        if dcc := self.transform_job_data_capture_config:
            if dcc.destination_s3_uri:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(dcc.destination_s3_uri))
            if dcc.kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(dcc.kms_key_id))
        if tr := self.transform_job_transform_resources:
            if tr.volume_kms_key_id:
                builder.dependant_node(self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(tr.volume_kms_key_id))
        if self.transform_job_labeling_job_arn:
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerLabelingJob, arn=self.transform_job_labeling_job_arn)
        if experiment := value_in_path(source, ["ExperimentConfig", "ExperimentName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerExperiment, name=experiment)
        if trial := value_in_path(source, ["ExperimentConfig", "TrialName"]):
            builder.add_edge(self, reverse=True, clazz=AwsSagemakerTrial, name=trial)


resources: List[Type[AwsResource]] = [
    AwsSagemakerNotebook,
    AwsSagemakerAlgorithm,
    AwsSagemakerModel,
    AwsSagemakerApp,
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
    # TODO SagemakerSpaces, deletion dependency for Sagemaker Domain!
]
