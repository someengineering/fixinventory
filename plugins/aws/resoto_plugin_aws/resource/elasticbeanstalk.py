from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.utils import ToDict
from resotolib.json_bender import Bender, S, Bend, ForallBend, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsBeanstalkMaxCountRule:
    kind: ClassVar[str] = "aws_beanstalk_max_count_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "max_count": S("MaxCount"),
        "delete_source_from_s3": S("DeleteSourceFromS3"),
    }
    enabled: Optional[bool] = field(default=None)
    max_count: Optional[int] = field(default=None)
    delete_source_from_s3: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkMaxAgeRule:
    kind: ClassVar[str] = "aws_beanstalk_max_age_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "max_age_in_days": S("MaxAgeInDays"),
        "delete_source_from_s3": S("DeleteSourceFromS3"),
    }
    enabled: Optional[bool] = field(default=None)
    max_age_in_days: Optional[int] = field(default=None)
    delete_source_from_s3: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplicationVersionLifecycleConfig:
    kind: ClassVar[str] = "aws_beanstalk_application_version_lifecycle_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_count_rule": S("MaxCountRule") >> Bend(AwsBeanstalkMaxCountRule.mapping),
        "max_age_rule": S("MaxAgeRule") >> Bend(AwsBeanstalkMaxAgeRule.mapping),
    }
    max_count_rule: Optional[AwsBeanstalkMaxCountRule] = field(default=None)
    max_age_rule: Optional[AwsBeanstalkMaxAgeRule] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplicationResourceLifecycleConfig:
    kind: ClassVar[str] = "aws_beanstalk_application_resource_lifecycle_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "service_role": S("ServiceRole"),
        "version_lifecycle_config": S("VersionLifecycleConfig")
        >> Bend(AwsBeanstalkApplicationVersionLifecycleConfig.mapping),
    }
    service_role: Optional[str] = field(default=None)
    version_lifecycle_config: Optional[AwsBeanstalkApplicationVersionLifecycleConfig] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplication(AwsResource):
    kind: ClassVar[str] = "aws_beanstalk_application"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("elasticbeanstalk", "describe-applications", "Applications")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("ApplicationName"),
        "name": S("ApplicationName"),
        "ctime": S("DateCreated"),
        "mtime": S("DateUpdated"),
        "arn": S("ApplicationArn"),
        "description": S("Description"),
        "versions": S("Versions", default=[]),
        "configuration_templates": S("ConfigurationTemplates", default=[]),
        "resource_lifecycle_config": S("ResourceLifecycleConfig")
        >> Bend(AwsBeanstalkApplicationResourceLifecycleConfig.mapping),
    }
    description: Optional[str] = field(default=None)
    versions: List[str] = field(factory=list)
    configuration_templates: List[str] = field(factory=list)
    resource_lifecycle_config: Optional[AwsBeanstalkApplicationResourceLifecycleConfig] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(app: AwsBeanstalkApplication) -> None:
            tags = builder.client.list("elasticbeanstalk", "list-tags-for-resource", "ResourceTags", ResourceArn=app.arn)
            if tags:
                app.tags = bend(ToDict(), tags)

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(add_tags, instance)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToAdd=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToRemove=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service=self.api_spec.service, action="delete-application", result_name=None, ApplicationName=self.name
        )
        return True


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentTier:
    kind: ClassVar[str] = "aws_beanstalk_environment_tier"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "type": S("Type"),
        "version": S("Version")
    }
    name: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)

@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentLink:
    kind: ClassVar[str] = "aws_beanstalk_environment_link"
    mapping: ClassVar[Dict[str, Bender]] = {
        "link_name": S("LinkName"),
        "environment_name": S("EnvironmentName")
    }
    link_name: Optional[str] = field(default=None)
    environment_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironment(AwsResource):
    kind: ClassVar[str] = "aws_beanstalk_environment"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("elasticbeanstalk", "describe-environments", "Environments")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("EnvironmentId"),
        "name": S("EnvironmentName"),
        "ctime": S("DateCreated"),
        "mtime": S("DateUpdated"),
        "arn": S("EnvironmentArn"),
        "application_name": S("ApplicationName"),
        "version_label": S("VersionLabel"),
        "solution_stack_name": S("SolutionStackName"),
        "platform_arn": S("PlatformArn"),
        "template_name": S("TemplateName"),
        "description": S("Description"),
        "endpoint_url": S("EndpointURL"),
        "cname": S("CNAME"),
        "status": S("Status"),
        "abortable_operation_in_progress": S("AbortableOperationInProgress"),
        "health": S("Health"),
        "health_status": S("HealthStatus"),
        "resources": [],
        "tier": S("Tier") >> Bend(AwsBeanstalkEnvironmentTier.mapping),
        "environment_links": S("EnvironmentLinks", default=[]) >> ForallBend(AwsBeanstalkEnvironmentLink.mapping),
        "operations_role": S("OperationsRole")
    }
    application_name: Optional[str] = field(default=None)
    version_label: Optional[str] = field(default=None)
    solution_stack_name: Optional[str] = field(default=None)
    platform_arn: Optional[str] = field(default=None)
    template_name: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    endpoint_url: Optional[str] = field(default=None)
    cname: Optional[str] = field(default=None)
    status: Optional[str] = field(default=None)
    abortable_operation_in_progress: Optional[bool] = field(default=None)
    health: Optional[str] = field(default=None)
    health_status: Optional[str] = field(default=None)
    resources: Optional[list] = field(default=None)  # List[Type[AwsResource]]?
    tier: Optional[AwsBeanstalkEnvironmentTier] = field(default=None)
    environment_links: List[AwsBeanstalkEnvironmentLink] = field(factory=list)
    operations_role: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(env: AwsBeanstalkEnvironment) -> None:
            tags = builder.client.list("elasticbeanstalk", "list-tags-for-resource", "ResourceTags", ResourceArn=env.arn)
            if tags:
                env.tags = bend(ToDict(), tags)

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(add_tags, instance)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToAdd=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToRemove=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            service=self.api_spec.service, action="terminate-environment", result_name=None, EnvironmentName=self.name
        )
        return True

resources: List[Type[AwsResource]] = [AwsBeanstalkApplication, AwsBeanstalkEnvironment]
