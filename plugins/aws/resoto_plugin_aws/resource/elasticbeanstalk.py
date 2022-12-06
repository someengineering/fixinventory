from typing import ClassVar, Dict, List, Optional, Type
from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resoto_plugin_aws.resource.ec2 import AwsEc2Instance
from resoto_plugin_aws.resource.elbv2 import AwsAlb
from resoto_plugin_aws.resource.sqs import AwsSqsQueue
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, ForallBend, bend
from resotolib.types import Json
from resotolib.json import from_json


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
        "beanstalk_versions": S("Versions", default=[]),
        "beanstalk_configuration_templates": S("ConfigurationTemplates", default=[]),
        "beanstalk_resource_lifecycle_config": S("ResourceLifecycleConfig")
        >> Bend(AwsBeanstalkApplicationResourceLifecycleConfig.mapping),
    }
    description: Optional[str] = field(default=None)
    beanstalk_versions: List[str] = field(factory=list)
    beanstalk_configuration_templates: List[str] = field(factory=list)
    beanstalk_resource_lifecycle_config: Optional[AwsBeanstalkApplicationResourceLifecycleConfig] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec(cls.api_spec.service, "list-tags-for-resource")]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(app: AwsBeanstalkApplication) -> None:
            tags = builder.client.list(
                "elasticbeanstalk", "list-tags-for-resource", "ResourceTags", ResourceArn=app.arn
            )
            if tags:
                app.tags = bend(ToDict(), tags)

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(add_tags, instance)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToAdd=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToRemove=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-application", result_name=None, ApplicationName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("elasticbeanstalk", "update-tags-for-resource"),
            AwsApiSpec("elasticbeanstalk", "delete-application"),
        ]


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentTier:
    kind: ClassVar[str] = "aws_beanstalk_environment_tier"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "type": S("Type"), "version": S("Version")}
    name: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentLink:
    kind: ClassVar[str] = "aws_beanstalk_environment_link"
    mapping: ClassVar[Dict[str, Bender]] = {"link_name": S("LinkName"), "environment_name": S("EnvironmentName")}
    link_name: Optional[str] = field(default=None)
    environment_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkAutoScalingGroupDescription:
    kind: ClassVar[str] = "aws_beanstalk_auto_scaling_group_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_scaling_group_name": S("Name"),
    }
    auto_scaling_group_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkInstancesDescription:
    kind: ClassVar[str] = "aws_beanstalk_instances_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_id": S("Id"),
    }
    instance_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkLoadBalancerDescription:
    kind: ClassVar[str] = "aws_beanstalk_load_balancer_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer_name": S("Name"),
    }
    load_balancer_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkQueueDescription:
    kind: ClassVar[str] = "aws_beanstalk_queue_description"
    mapping: ClassVar[Dict[str, Bender]] = {
        "queue_name": S("Name"),
        "queue_url": S("URL"),
    }
    queue_name: Optional[str] = field(default=None)
    queue_url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentResourcesDescription:
    kind: ClassVar[str] = "aws_beanstalk_environment_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_scaling_groups": S("AutoScalingGroups") >> ForallBend(AwsBeanstalkAutoScalingGroupDescription.mapping),
        "instances": S("Instances") >> ForallBend(AwsBeanstalkInstancesDescription.mapping),
        "load_balancers": S("LoadBalancers") >> ForallBend(AwsBeanstalkLoadBalancerDescription.mapping),
        "queues": S("Queues") >> ForallBend(AwsBeanstalkQueueDescription.mapping),
    }
    auto_scaling_groups: Optional[List[AwsBeanstalkAutoScalingGroupDescription]] = field(default=None)
    instances: Optional[List[AwsBeanstalkInstancesDescription]] = field(default=None)
    load_balancers: Optional[List[AwsBeanstalkLoadBalancerDescription]] = field(default=None)
    queues: Optional[List[AwsBeanstalkQueueDescription]] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironment(AwsResource):
    kind: ClassVar[str] = "aws_beanstalk_environment"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("elasticbeanstalk", "describe-environments", "Environments")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_beanstalk_application"],
            "delete": ["aws_autoscaling_group", "aws_ec2_instance", "aws_alb", "aws_sqs_queue"],
        },
        "successors": {
            "default": ["aws_autoscaling_group", "aws_ec2_instance", "aws_alb", "aws_sqs_queue"],
            "delete": ["aws_beanstalk_application"],
        },
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("EnvironmentId"),
        "name": S("EnvironmentName"),
        "ctime": S("DateCreated"),
        "mtime": S("DateUpdated"),
        "arn": S("EnvironmentArn"),
        "description": S("Description"),
        "beanstalk_application_name": S("ApplicationName"),
        "beanstalk_version_label": S("VersionLabel"),
        "beanstalk_solution_stack_name": S("SolutionStackName"),
        "beanstalk_platform_arn": S("PlatformArn"),
        "beanstalk_template_name": S("TemplateName"),
        "beanstalk_endpoint_url": S("EndpointURL"),
        "beanstalk_cname": S("CNAME"),
        "beanstalk_status": S("Status"),
        "beanstalk_abortable_operation_in_progress": S("AbortableOperationInProgress"),
        "beanstalk_health": S("Health"),
        "beanstalk_health_status": S("HealthStatus"),
        "beanstalk_tier": S("Tier") >> Bend(AwsBeanstalkEnvironmentTier.mapping),
        "beanstalk_environment_links": S("EnvironmentLinks", default=[])
        >> ForallBend(AwsBeanstalkEnvironmentLink.mapping),
        "beanstalk_operations_role": S("OperationsRole"),
    }
    description: Optional[str] = field(default=None)
    beanstalk_application_name: Optional[str] = field(default=None)
    beanstalk_version_label: Optional[str] = field(default=None)
    beanstalk_solution_stack_name: Optional[str] = field(default=None)
    beanstalk_platform_arn: Optional[str] = field(default=None)
    beanstalk_template_name: Optional[str] = field(default=None)
    beanstalk_endpoint_url: Optional[str] = field(default=None)
    beanstalk_cname: Optional[str] = field(default=None)
    beanstalk_status: Optional[str] = field(default=None)
    beanstalk_abortable_operation_in_progress: Optional[bool] = field(default=None)
    beanstalk_health: Optional[str] = field(default=None)
    beanstalk_health_status: Optional[str] = field(default=None)
    beanstalk_resources: Optional[AwsBeanstalkEnvironmentResourcesDescription] = field(default=None)
    beanstalk_tier: Optional[AwsBeanstalkEnvironmentTier] = field(default=None)
    beanstalk_environment_links: List[AwsBeanstalkEnvironmentLink] = field(factory=list)
    beanstalk_operations_role: Optional[str] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(cls.api_spec.service, "describe-environment-resources"),
            AwsApiSpec(cls.api_spec.service, "list-tags-for-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(env: AwsBeanstalkEnvironment) -> None:
            tags = builder.client.list(
                "elasticbeanstalk", "list-tags-for-resource", "ResourceTags", ResourceArn=env.arn
            )
            if tags:
                env.tags = bend(ToDict(), tags)

        def add_resources(env: AwsBeanstalkEnvironment) -> None:
            resources_description = builder.client.get(
                "elasticbeanstalk", "describe-environment-resources", "EnvironmentResources", EnvironmentId=env.id
            )
            if resources_description:
                env.beanstalk_resources = from_json(
                    bend(AwsBeanstalkEnvironmentResourcesDescription.mapping, resources_description),
                    AwsBeanstalkEnvironmentResourcesDescription,
                )

        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)
            builder.submit_work(add_tags, instance)
            builder.submit_work(add_resources, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        builder.dependant_node(
            self,
            reverse=True,
            clazz=AwsBeanstalkApplication,
            name=self.beanstalk_application_name,
        )
        res = self.beanstalk_resources
        if not res:
            return
        if res.auto_scaling_groups:
            for group in res.auto_scaling_groups:
                if group.auto_scaling_group_name:
                    builder.dependant_node(
                        self,
                        clazz=AwsAutoScalingGroup,
                        name=group.auto_scaling_group_name,
                    )
        if res.instances:
            for instance in res.instances:
                if instance.instance_id:
                    builder.dependant_node(
                        self,
                        clazz=AwsEc2Instance,
                        id=instance.instance_id,
                    )
        if res.load_balancers:
            for lb in res.load_balancers:
                if lb.load_balancer_name:
                    builder.dependant_node(
                        self,
                        clazz=AwsAlb,
                        name=lb.load_balancer_name,
                    )
        if res.queues:
            for queue in res.queues:
                if queue.queue_name:
                    builder.dependant_node(
                        self,
                        clazz=AwsSqsQueue,
                        name=queue.queue_name,
                    )

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToAdd=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="update-tags-for-resource",
            result_name=None,
            ResourceArn=self.arn,
            TagsToRemove=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="terminate-environment",
            result_name=None,
            EnvironmentName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("elasticbeanstalk", "update-tags-for-resource"),
            AwsApiSpec("elasticbeanstalk", "terminate-environment"),
        ]


resources: List[Type[AwsResource]] = [AwsBeanstalkApplication, AwsBeanstalkEnvironment]
