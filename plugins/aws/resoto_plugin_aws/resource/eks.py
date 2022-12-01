from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, cast

from attrs import define, field

from resoto_plugin_aws.resource.autoscaling import AwsAutoScalingGroup
from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.iam import AwsIamRole
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, ForallBend
from resotolib.types import Json
from resoto_plugin_aws.aws_client import AwsClient


# noinspection PyUnresolvedReferences
class EKSTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="tag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tags={key: value},
                )
                return True
            return False
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            if spec := self.api_spec:
                client.call(
                    aws_service=spec.service,
                    action="untag-resource",
                    result_name=None,
                    resourceArn=self.arn,
                    tagKeys=[key],
                )
                return True
            return False
        return False

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec("eks", "tag-resource"), AwsApiSpec("eks", "untag-resource")]


@define(eq=False, slots=False)
class AwsEksNodegroupScalingConfig:
    kind: ClassVar[str] = "aws_eks_nodegroup_scaling_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "min_size": S("minSize"),
        "max_size": S("maxSize"),
        "desired_size": S("desiredSize"),
    }
    min_size: Optional[int] = field(default=None)
    max_size: Optional[int] = field(default=None)
    desired_size: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEksRemoteAccessConfig:
    kind: ClassVar[str] = "aws_eks_remote_access_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ec2_ssh_key": S("ec2SshKey"),
        "source_security_groups": S("sourceSecurityGroups", default=[]),
    }
    ec2_ssh_key: Optional[str] = field(default=None)
    source_security_groups: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEksTaint:
    kind: ClassVar[str] = "aws_eks_taint"
    mapping: ClassVar[Dict[str, Bender]] = {"key": S("key"), "value": S("value"), "effect": S("effect")}
    key: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)
    effect: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksNodegroupResources:
    kind: ClassVar[str] = "aws_eks_nodegroup_resources"
    mapping: ClassVar[Dict[str, Bender]] = {
        "auto_scaling_groups": S("autoScalingGroups", default=[]) >> ForallBend(S("name")),
        "remote_access_security_group": S("remoteAccessSecurityGroup"),
    }
    auto_scaling_groups: List[str] = field(factory=list)
    remote_access_security_group: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksIssue:
    kind: ClassVar[str] = "aws_eks_issue"
    mapping: ClassVar[Dict[str, Bender]] = {
        "code": S("code"),
        "message": S("message"),
        "resource_ids": S("resourceIds", default=[]),
    }
    code: Optional[str] = field(default=None)
    message: Optional[str] = field(default=None)
    resource_ids: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEksNodegroupHealth:
    kind: ClassVar[str] = "aws_eks_nodegroup_health"
    mapping: ClassVar[Dict[str, Bender]] = {"issues": S("issues", default=[]) >> ForallBend(AwsEksIssue.mapping)}
    issues: List[AwsEksIssue] = field(factory=list)


@define(eq=False, slots=False)
class AwsEksNodegroupUpdateConfig:
    kind: ClassVar[str] = "aws_eks_nodegroup_update_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "max_unavailable": S("maxUnavailable"),
        "max_unavailable_percentage": S("maxUnavailablePercentage"),
    }
    max_unavailable: Optional[int] = field(default=None)
    max_unavailable_percentage: Optional[int] = field(default=None)


@define(eq=False, slots=False)
class AwsEksLaunchTemplateSpecification:
    kind: ClassVar[str] = "aws_eks_launch_template_specification"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("name"), "version": S("version"), "id": S("id")}
    name: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)
    id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksNodegroup(EKSTaggable, AwsResource):
    # Note: this resource is collected via AwsEksCluster
    kind: ClassVar[str] = "aws_eks_nodegroup"
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_eks_cluster"], "delete": ["aws_eks_cluster", "aws_autoscaling_group"]},
        "successors": {"default": ["aws_autoscaling_group"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("nodegroupName"),
        "name": S("nodegroupName"),
        "tags": S("tags", default={}),
        "cluster_name": S("clusterName"),
        "ctime": S("createdAt"),
        "arn": S("nodegroupArn"),
        "version": S("version"),
        "group_release_version": S("releaseVersion"),
        "group_modified_at": S("modifiedAt"),
        "group_status": S("status"),
        "group_capacity_type": S("capacityType"),
        "group_scaling_config": S("scalingConfig") >> Bend(AwsEksNodegroupScalingConfig.mapping),
        "group_instance_types": S("instanceTypes", default=[]),
        "group_subnets": S("subnets", default=[]),
        "group_remote_access": S("remoteAccess") >> Bend(AwsEksRemoteAccessConfig.mapping),
        "group_ami_type": S("amiType"),
        "group_node_role": S("nodeRole"),
        "group_labels": S("labels"),
        "group_taints": S("taints", default=[]) >> ForallBend(AwsEksTaint.mapping),
        "group_resources": S("resources") >> Bend(AwsEksNodegroupResources.mapping),
        "group_disk_size": S("diskSize"),
        "group_health": S("health") >> Bend(AwsEksNodegroupHealth.mapping),
        "group_update_config": S("updateConfig") >> Bend(AwsEksNodegroupUpdateConfig.mapping),
        "group_launch_template": S("launchTemplate") >> Bend(AwsEksLaunchTemplateSpecification.mapping),
    }
    cluster_name: Optional[str] = field(default=None)
    group_nodegroup_arn: Optional[str] = field(default=None)
    group_version: Optional[str] = field(default=None)
    group_release_version: Optional[str] = field(default=None)
    group_modified_at: Optional[datetime] = field(default=None)
    group_status: Optional[str] = field(default=None)
    group_capacity_type: Optional[str] = field(default=None)
    group_scaling_config: Optional[AwsEksNodegroupScalingConfig] = field(default=None)
    group_instance_types: List[str] = field(factory=list)
    group_subnets: List[str] = field(factory=list)
    group_remote_access: Optional[AwsEksRemoteAccessConfig] = field(default=None)
    group_ami_type: Optional[str] = field(default=None)
    group_node_role: Optional[str] = field(default=None)
    group_labels: Optional[Dict[str, str]] = field(default=None)
    group_taints: List[AwsEksTaint] = field(factory=list)
    group_resources: Optional[AwsEksNodegroupResources] = field(default=None)
    group_disk_size: Optional[int] = field(default=None)
    group_health: Optional[AwsEksNodegroupHealth] = field(default=None)
    group_update_config: Optional[AwsEksNodegroupUpdateConfig] = field(default=None)
    group_launch_template: Optional[AwsEksLaunchTemplateSpecification] = field(default=None)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cluster_name := self.cluster_name:
            builder.dependant_node(
                self, clazz=AwsEksCluster, reverse=True, delete_same_as_default=True, name=cluster_name
            )
        if self.group_resources:
            for arn in self.group_resources.auto_scaling_groups:
                builder.dependant_node(self, clazz=AwsAutoScalingGroup, arn=arn)

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service="eks",
            action="delete-nodegroup",
            result_name=None,
            clusterName=self.cluster_name,
            nodegroupName=self.name,
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("eks", "delete-nodegroup")]


@define(eq=False, slots=False)
class AwsEksVpcConfigResponse:
    kind: ClassVar[str] = "aws_eks_vpc_config_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "subnet_ids": S("subnetIds", default=[]),
        "security_group_ids": S("securityGroupIds", default=[]),
        "cluster_security_group_id": S("clusterSecurityGroupId"),
        "vpc_id": S("vpcId"),
        "endpoint_public_access": S("endpointPublicAccess"),
        "endpoint_private_access": S("endpointPrivateAccess"),
        "public_access_cidrs": S("publicAccessCidrs", default=[]),
    }
    subnet_ids: List[str] = field(factory=list)
    security_group_ids: List[str] = field(factory=list)
    cluster_security_group_id: Optional[str] = field(default=None)
    vpc_id: Optional[str] = field(default=None)
    endpoint_public_access: Optional[bool] = field(default=None)
    endpoint_private_access: Optional[bool] = field(default=None)
    public_access_cidrs: List[str] = field(factory=list)


@define(eq=False, slots=False)
class AwsEksKubernetesNetworkConfigResponse:
    kind: ClassVar[str] = "aws_eks_kubernetes_network_config_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "service_ipv4_cidr": S("serviceIpv4Cidr"),
        "service_ipv6_cidr": S("serviceIpv6Cidr"),
        "ip_family": S("ipFamily"),
    }
    service_ipv4_cidr: Optional[str] = field(default=None)
    service_ipv6_cidr: Optional[str] = field(default=None)
    ip_family: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksLogSetup:
    kind: ClassVar[str] = "aws_eks_log_setup"
    mapping: ClassVar[Dict[str, Bender]] = {"types": S("types", default=[]), "enabled": S("enabled")}
    types: List[str] = field(factory=list)
    enabled: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsEksLogging:
    kind: ClassVar[str] = "aws_eks_logging"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cluster_logging": S("clusterLogging", default=[]) >> ForallBend(AwsEksLogSetup.mapping)
    }
    cluster_logging: List[AwsEksLogSetup] = field(factory=list)


@define(eq=False, slots=False)
class AwsEksIdentity:
    kind: ClassVar[str] = "aws_eks_identity"
    mapping: ClassVar[Dict[str, Bender]] = {"oidc": S("oidc", "issuer")}
    oidc: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksEncryptionConfig:
    kind: ClassVar[str] = "aws_eks_encryption_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "resources": S("resources", default=[]),
        "provider": S("provider", "keyArn"),
    }
    resources: List[str] = field(factory=list)
    provider: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksConnectorConfig:
    kind: ClassVar[str] = "aws_eks_connector_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "activation_id": S("activationId"),
        "activation_code": S("activationCode"),
        "activation_expiry": S("activationExpiry"),
        "provider": S("provider"),
        "role_arn": S("roleArn"),
    }
    activation_id: Optional[str] = field(default=None)
    activation_code: Optional[str] = field(default=None)
    activation_expiry: Optional[datetime] = field(default=None)
    provider: Optional[str] = field(default=None)
    role_arn: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsEksCluster(EKSTaggable, AwsResource):
    kind: ClassVar[str] = "aws_eks_cluster"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("eks", "list-clusters", "clusters")
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {
            "default": ["aws_iam_role"],
            "delete": ["aws_iam_role"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name"),
        "tags": S("tags", default={}),
        "name": S("name"),
        "arn": S("arn"),
        "ctime": S("createdAt"),
        "cluster_version": S("version"),
        "cluster_endpoint": S("endpoint"),
        "cluster_role_arn": S("roleArn"),
        "cluster_resources_vpc_config": S("resourcesVpcConfig") >> Bend(AwsEksVpcConfigResponse.mapping),
        "cluster_kubernetes_network_config": S("kubernetesNetworkConfig")
        >> Bend(AwsEksKubernetesNetworkConfigResponse.mapping),
        "cluster_logging": S("logging") >> Bend(AwsEksLogging.mapping),
        "cluster_identity": S("identity") >> Bend(AwsEksIdentity.mapping),
        "cluster_status": S("status"),
        "cluster_certificate_authority": S("certificateAuthority", "data"),
        "cluster_client_request_token": S("clientRequestToken"),
        "cluster_platform_version": S("platformVersion"),
        "cluster_encryption_config": S("encryptionConfig", default=[]) >> ForallBend(AwsEksEncryptionConfig.mapping),
        "cluster_connector_config": S("connectorConfig") >> Bend(AwsEksConnectorConfig.mapping),
    }
    cluster_version: Optional[str] = field(default=None)
    cluster_endpoint: Optional[str] = field(default=None)
    cluster_role_arn: Optional[str] = field(default=None)
    cluster_resources_vpc_config: Optional[AwsEksVpcConfigResponse] = field(default=None)
    cluster_kubernetes_network_config: Optional[AwsEksKubernetesNetworkConfigResponse] = field(default=None)
    cluster_logging: Optional[AwsEksLogging] = field(default=None)
    cluster_identity: Optional[AwsEksIdentity] = field(default=None)
    cluster_status: Optional[str] = field(default=None)
    cluster_certificate_authority: Optional[str] = field(default=None)
    cluster_client_request_token: Optional[str] = field(default=None)
    cluster_platform_version: Optional[str] = field(default=None)
    cluster_encryption_config: List[AwsEksEncryptionConfig] = field(factory=list)
    cluster_connector_config: Optional[AwsEksConnectorConfig] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("eks", "describe-cluster"),
            AwsApiSpec("eks", "list-nodegroups"),
            AwsApiSpec("eks", "describe-nodegroup"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        for name in cast(List[str], json):
            cluster_json = builder.client.get("eks", "describe-cluster", "cluster", name=name)
            if cluster_json is not None:
                cluster = AwsEksCluster.from_api(cluster_json)
                builder.add_node(cluster, cluster_json)
                for ng_name in builder.client.list("eks", "list-nodegroups", "nodegroups", clusterName=name):
                    ng_json = builder.client.get(
                        "eks", "describe-nodegroup", "nodegroup", clusterName=name, nodegroupName=ng_name
                    )
                    if ng_json is not None:
                        ng = AwsEksNodegroup.from_api(ng_json)
                        builder.add_node(ng, ng_json)

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        builder.dependant_node(
            self, reverse=True, delete_same_as_default=True, clazz=AwsIamRole, arn=self.cluster_role_arn
        )

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service=self.api_spec.service, action="delete-cluster", result_name=None, name=self.name)
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return super().called_mutator_apis() + [AwsApiSpec("eks", "delete-cluster")]


resources: List[Type[AwsResource]] = [AwsEksNodegroup, AwsEksCluster]
