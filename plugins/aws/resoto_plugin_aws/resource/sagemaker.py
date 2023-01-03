from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resotolib.json_bender import S, Bender
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


resources: List[Type[AwsResource]] = [AwsSagemakerNotebook]
