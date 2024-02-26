from typing import ClassVar, Dict, List, Optional, Type, Any
from attrs import define, field
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder, parse_json
from fix_plugin_aws.resource.ec2 import AwsEc2Instance
from fix_plugin_aws.resource.elbv2 import AwsAlb
from fix_plugin_aws.resource.sqs import AwsSqsQueue
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend, bend
from fixlib.types import Json

service_name = "elasticbeanstalk"


@define(eq=False, slots=False)
class AwsBeanstalkMaxCountRule:
    kind: ClassVar[str] = "aws_beanstalk_max_count_rule"
    kind_display: ClassVar[str] = "AWS Beanstalk Max Count Rule"
    kind_description: ClassVar[str] = (
        "AWS Beanstalk Max Count Rule is a rule that can be set on an AWS Elastic"
        " Beanstalk environment to limit the maximum number of instances that can be"
        " running at a given time."
    )
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
    kind_display: ClassVar[str] = "AWS Beanstalk Max Age Rule"
    kind_description: ClassVar[str] = (
        "A rule that defines the maximum age of the environments in AWS Elastic"
        " Beanstalk, which allows automatic termination of environments after a"
        " specified time period."
    )
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
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Application Version Lifecycle Configuration"
    kind_description: ClassVar[str] = (
        "An AWS Elastic Beanstalk Application Version Lifecycle Configuration allows"
        " you to define rules for automatically deploying, updating, and deleting"
        " application versions on your Elastic Beanstalk environments."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_count_rule": S("MaxCountRule") >> Bend(AwsBeanstalkMaxCountRule.mapping),
        "max_age_rule": S("MaxAgeRule") >> Bend(AwsBeanstalkMaxAgeRule.mapping),
    }
    max_count_rule: Optional[AwsBeanstalkMaxCountRule] = field(default=None)
    max_age_rule: Optional[AwsBeanstalkMaxAgeRule] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkApplicationResourceLifecycleConfig:
    kind: ClassVar[str] = "aws_beanstalk_application_resource_lifecycle_config"
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Application Resource Lifecycle Configuration"
    kind_description: ClassVar[str] = (
        "The AWS Elastic Beanstalk Application Resource Lifecycle Configuration"
        " allows users to define and manage the lifecycle of resources used in an"
        " Elastic Beanstalk application."
    )
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
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Application"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/elasticbeanstalk/home?region={region}#/application/overview?applicationName={name}", "arn_tpl": "arn:{partition}:elasticbeanstalk:{region}:{account}:application/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Elastic Beanstalk is a fully managed service that makes it easy to deploy"
        " and run applications in multiple languages."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-applications", "Applications")
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
                service_name,
                "list-tags-for-resource",
                "ResourceTags",
                ResourceArn=app.arn,
                expected_errors=["ResourceNotFoundException"],
            )
            if tags:
                app.tags = bend(ToDict(), tags)

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)

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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=self.api_spec.service, action="delete-application", result_name=None, ApplicationName=self.name
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "update-tags-for-resource"),
            AwsApiSpec(service_name, "delete-application"),
        ]


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentTier:
    kind: ClassVar[str] = "aws_beanstalk_environment_tier"
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Environment Tier"
    kind_description: ClassVar[str] = (
        "The environment tier in AWS Elastic Beanstalk determines the resources and"
        " features available for an Elastic Beanstalk environment. It can be either"
        " WebServer or Worker."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "type": S("Type"), "version": S("Version")}
    name: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentLink:
    kind: ClassVar[str] = "aws_beanstalk_environment_link"
    kind_display: ClassVar[str] = "AWS Beanstalk Environment Link"
    kind_description: ClassVar[str] = (
        "AWS Beanstalk Environment Link is a reference to an AWS Elastic Beanstalk"
        " environment which provides a URL to access the deployed application."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"link_name": S("LinkName"), "environment_name": S("EnvironmentName")}
    link_name: Optional[str] = field(default=None)
    environment_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkAutoScalingGroupDescription:
    kind: ClassVar[str] = "aws_beanstalk_auto_scaling_group_description"
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Auto Scaling Group Description"
    kind_description: ClassVar[str] = (
        "AWS Elastic Beanstalk Auto Scaling Group Description is a feature of AWS"
        " Elastic Beanstalk that allows dynamic scaling of resources based on the"
        " demand of your application to ensure optimal performance."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_scaling_group_name": S("Name"),
    }
    auto_scaling_group_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkInstancesDescription:
    kind: ClassVar[str] = "aws_beanstalk_instances_description"
    kind_display: ClassVar[str] = "AWS Beanstalk Instances Description"
    kind_description: ClassVar[str] = (
        "Beanstalk is a fully managed service by AWS that makes it easy to deploy,"
        " run, and scale applications in the cloud. Beanstalk instances are the"
        " virtual servers on which applications are deployed and run in AWS Beanstalk."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_id": S("Id"),
    }
    instance_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkLoadBalancerDescription:
    kind: ClassVar[str] = "aws_beanstalk_load_balancer_description"
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Load Balancer Description"
    kind_description: ClassVar[str] = (
        "AWS Elastic Beanstalk Load Balancer Description is a string representing the"
        " description of the load balancer in the Elastic Beanstalk service provided"
        " by Amazon Web Services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "load_balancer_name": S("Name"),
    }
    load_balancer_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkQueueDescription:
    kind: ClassVar[str] = "aws_beanstalk_queue_description"
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Queue Description"
    kind_description: ClassVar[str] = (
        "AWS Elastic Beanstalk Queue Description outlines the details of a message queue, such as Amazon Simple"
        " Queue Service (SQS), that's integrated with an Elastic Beanstalk application, providing information on"
        " the queue's configurations and attributes for message processing."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "queue_name": S("Name"),
        "queue_url": S("URL"),
    }
    queue_name: Optional[str] = field(default=None)
    queue_url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsBeanstalkEnvironmentResourcesDescription:
    kind: ClassVar[str] = "aws_beanstalk_environment_resources"
    kind_display: ClassVar[str] = "AWS Beanstalk Environment Resources"
    kind_description: ClassVar[str] = (
        "Beanstalk Environment Resources refer to the compute, storage, and"
        " networking resources allocated to an application environment in AWS Elastic"
        " Beanstalk, a fully managed service for deploying and scaling web"
        " applications."
    )
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
    kind_display: ClassVar[str] = "AWS Elastic Beanstalk Environment"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/elasticbeanstalk/home?region={region}#/environment/dashboard?environmentId={id}", "arn_tpl": "arn:{partition}:elasticbeanstalk:{region}:{account}:environment/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "An AWS Elastic Beanstalk environment is a collection of AWS resources running an application version."
        " It includes an application server, server instances, load balancers, and optionally, a database."
        " Each environment runs only one application and one version of that application at a time."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "describe-environments", "Environments")
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
                service_name,
                "list-tags-for-resource",
                "ResourceTags",
                ResourceArn=env.arn,
                expected_errors=["ResourceNotFoundException"],
            )
            if tags:
                env.tags = bend(ToDict(), tags)

        def add_resources(env: AwsBeanstalkEnvironment) -> None:
            resources_description = builder.client.get(
                service_name,
                "describe-environment-resources",
                "EnvironmentResources",
                EnvironmentId=env.id,
                expected_errors=["InvalidParameterValue"],
            )
            if resources_description:
                env.beanstalk_resources = parse_json(
                    bend(AwsBeanstalkEnvironmentResourcesDescription.mapping, resources_description),
                    AwsBeanstalkEnvironmentResourcesDescription,
                    builder,
                )

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)
                builder.submit_work(service_name, add_resources, instance)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        builder.dependant_node(
            self,
            reverse=True,
            delete_same_as_default=True,
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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        # If the environment is already terminated, we don't need to do anything
        if self.beanstalk_status == "Terminated":
            return True
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
            AwsApiSpec(service_name, "update-tags-for-resource"),
            AwsApiSpec(service_name, "terminate-environment"),
        ]


resources: List[Type[AwsResource]] = [AwsBeanstalkApplication, AwsBeanstalkEnvironment]
