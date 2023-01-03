from attrs import define, field
from typing import ClassVar, Dict, List, Optional, Type
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource
from resotolib.json_bender import S, Bender


@define(eq=False, slots=False)
class AwsSagemakerNotebook(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_notebook"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-notebook-instances", "NotebookInstances")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("NotebookInstanceArn"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("NotebookInstanceName"),
        "arn": S("NotebookInstanceArn"),
        "ctime": S("CreationTime"),
        "mtime": S("LastModifiedTime"),
        "notebook_instance_status": S("NotebookInstanceStatus"),
        "notebook_url": S("Url"),
        "notebook_instance_type": S("InstanceType"),
        "notebook_instance_lifecycle_config_name": S("NotebookInstanceLifecycleConfigName"),
        "notebook_default_code_repository": S("DefaultCodeRepository"),
        "notebook_additional_code_repositories": S("AdditionalCodeRepositories", default=[])
    }
    notebook_instance_status: Optional[str] = field(default=None)
    notebook_url: Optional[str] = field(default=None)
    notebook_instance_type: Optional[str] = field(default=None)
    notebook_instance_lifecycle_config_name: Optional[str] = field(default=None)
    notebook_default_code_repository: Optional[str] = field(default=None)
    notebook_additional_code_repositories: List[str] = field(factory=list)

    #edge to code repo


resources: List[Type[AwsResource]] = [AwsSagemakerNotebook]
