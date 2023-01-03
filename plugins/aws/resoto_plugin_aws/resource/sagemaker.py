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
        "notebook_additional_code_repositories": S("AdditionalCodeRepositories", default=[]),
    }
    notebook_instance_status: Optional[str] = field(default=None)
    notebook_url: Optional[str] = field(default=None)
    notebook_instance_type: Optional[str] = field(default=None)
    notebook_instance_lifecycle_config_name: Optional[str] = field(default=None)
    notebook_default_code_repository: Optional[str] = field(default=None)
    notebook_additional_code_repositories: List[str] = field(factory=list)

    # edge to code repo


@define(eq=False, slots=False)
class AwsSagemakerApp(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_app"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-apps", "Apps")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("AppName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("AppName"),
        "ctime": S("CreationTime"),
        "app_domain_id": S("DomainId"),
        "app_user_profile_name": S("UserProfileName"),
        "app_type": S("AppType"),
        "app_status": S("Status"),
    }
    app_domain_id: Optional[str] = field(default=None)
    app_user_profile_name: Optional[str] = field(default=None)
    app_type: Optional[str] = field(default=None)
    app_status: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for js in json:
            instance = cls.from_api(js)
            instance.set_arn(builder, resource=f"app/{instance.name}")
            builder.add_node(instance, js)

    # edge to domain


@define(eq=False, slots=False)
class AwsSagemakerModel(AwsResource):
    kind: ClassVar[str] = "aws_sagemaker_model"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("sagemaker", "list-models", "Models")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ModelName"),
        # "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("ModelName"),
        "arn": S("ModelArn"),
        "ctime": S("CreationTime"),
    }


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
        "domain_status": S("Status"),
        "domain_url": S("Url"),
    }
    domain_status: Optional[str] = field(default=None)
    domain_url: Optional[str] = field(default=None)


resources: List[Type[AwsResource]] = [AwsSagemakerNotebook, AwsSagemakerApp, AwsSagemakerModel, AwsSagemakerDomain]
