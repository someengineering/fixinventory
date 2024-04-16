from __future__ import annotations

import logging
import re
from urllib.parse import quote_plus as urlquote
from abc import ABC
from concurrent.futures import Future
from datetime import datetime, timezone, timedelta
from functools import lru_cache
from typing import Any, Callable, ClassVar, Dict, Iterator, List, Optional, Type, TypeVar, Tuple

from math import ceil

from attr import evolve
from attrs import define
from boto3.exceptions import Boto3Error

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.configuration import AwsConfig
from fix_plugin_aws.resource.pricing import AwsPricingPrice
from fix_plugin_aws.utils import arn_partition
from fixlib.utils import utc
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    BaseVolumeType,
    Cloud,
    EdgeType,
    ModelReference,
)
from fixlib.config import Config, current_config
from fixlib.core.actions import CoreFeedback, SuppressWithFeedback
from fixlib.graph import ByNodeId, BySearchCriteria, EdgeKey, Graph, NodeSelector
from fixlib.json import from_json, value_in_path
from fixlib.json_bender import Bender, bend
from fixlib.lock import RWLock
from fixlib.proc import set_thread_name
from fixlib.threading import ExecutorQueue
from fixlib.types import Json
from fixinventorydata.cloud import instances as cloud_instance_data, regions as cloud_region_data

log = logging.getLogger("fix.plugins.aws")


def get_client(config: Config, resource: BaseResource) -> AwsClient:
    account = resource.account()
    assert isinstance(account, AwsAccount)
    return AwsClient(config.aws, account.id, role=account.role, profile=account.profile, region=resource.region().id)


T = TypeVar("T")
TemplateRE = re.compile("[{]([^}]+)[}]")
TemplateFn: Dict[str, Callable[[AwsResource], Optional[str]]] = {
    "id": lambda n: n.id,
    "name": lambda n: n.safe_name,
    "arn": lambda n: n.arn,
    "account": lambda n: n.account().id,
    "region": lambda n: n.region().safe_name,
    "region_id": lambda n: n.region().id,
}


def parse_json(
    json: Json, clazz: Type[T], builder: GraphBuilder, mapping: Optional[Dict[str, Bender]] = None
) -> Optional[T]:
    """
    Use this method to parse json into a class. If the json can not be parsed, the error is reported to the core.
    Based on configuration, either the exception is raised or None is returned.
    :param json: the json to parse.
    :param clazz: the class to parse into.
    :param builder: the graph builder.
    :param mapping: the optional mapping to apply before parsing.
    :return: The parsed object or None.
    """
    try:
        mapped = bend(mapping, json) if mapping is not None else json
        return from_json(mapped, clazz)
    except Exception as e:
        # report and log the error
        builder.core_feedback.error(f"Failed to parse json into {clazz.__name__}: {e}. Source: {json}", log)
        # based on the strict flag, either raise the exception or return None
        if builder.config.discard_account_on_resource_error:
            raise
        return None


@define
class AwsApiSpec:
    """
    Specifications for the AWS API to call and the expected response.
    """

    service: str
    api_action: str
    result_property: Optional[str] = None
    parameter: Optional[Dict[str, Any]] = None
    expected_errors: Optional[List[str]] = None
    override_iam_permission: Optional[str] = None  # only set if the permission can not be derived

    def iam_permission(self) -> str:
        if self.override_iam_permission:
            return self.override_iam_permission
        else:
            action = "".join(word.title() for word in self.api_action.split("-"))
            return f"{self.service}:{action}"


@define(eq=False, slots=False)
class AwsResource(BaseResource, ABC):
    """
    Base class for all AWS resources.
    Override kind, mapping and api_spec for every resource that is collected in AWS.
    """

    # The name of the kind of all resources. Needs to be globally unique.
    kind: ClassVar[str] = "aws_resource"
    kind_display: ClassVar[str] = "AWS Resource"
    kind_description: ClassVar[str] = "AWS Resource is a generic term used to refer to any type of resource available in Amazon Web Services cloud."  # fmt: skip
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[AwsApiSpec]] = None

    # The AWS specific identifier of the resource. If not set, it is created from template in GraphBuilder.
    arn: Optional[str] = None

    def _keys(self) -> Tuple[Any, ...]:
        if self.arn is not None:
            return tuple(list(super()._keys()) + [self.arn])
        return super()._keys()

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        return False

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        log.info(f"Delete not implemented for {self.kind}.")
        return False

    # legacy interface
    def update_tag(self, key: str, value: str) -> bool:
        return self.update_resource_tag(get_client(current_config(), self), key, value)

    # legacy interface
    def delete_tag(self, key: str) -> bool:
        return self.delete_resource_tag(get_client(current_config(), self), key)

    # legacy interface
    def delete(self, graph: Graph) -> bool:
        return self.delete_resource(get_client(current_config(), self), graph)

    @classmethod
    def service_name(cls) -> Optional[str]:
        """
        By default, every resource has an api_spec and the service name is derived from it.
        For resources with custom handling, you need to override this method and define the service name explicitly.
        """
        return cls.api_spec.service if cls.api_spec else None

    def set_arn(
        self,
        builder: GraphBuilder,
        region: Optional[str] = None,
        service: Optional[str] = None,
        account: Optional[str] = None,
        resource: str = "",
    ) -> None:
        aws_region = builder.region
        partition = arn_partition(aws_region)
        if region is None:
            region = aws_region.id
        if service is None and self.api_spec:
            service = self.api_spec.service
        if account is None:
            account = builder.account.id
        self.arn = f"arn:{partition}:{service}:{region}:{account}:{resource}"

    @staticmethod
    def id_from_arn(arn: str) -> str:
        if "/" in arn:
            return arn.rsplit("/")[-1]
        return arn.rsplit(":")[-1]

    @classmethod
    def from_api(cls: Type[AwsResourceType], json: Json, builder: GraphBuilder) -> Optional[AwsResourceType]:
        return parse_json(json, cls, builder, cls.mapping)

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        if spec := cls.api_spec:
            try:
                kwargs = spec.parameter or {}
                items = builder.client.list(
                    aws_service=spec.service,
                    action=spec.api_action,
                    result_name=spec.result_property,
                    expected_errors=spec.expected_errors,
                    **kwargs,
                )
                cls.collect(items, builder)
                if builder.config.collect_usage_metrics:
                    try:
                        cls.collect_usage_metrics(builder)
                    except Exception as e:
                        log.warning(f"Failed to collect usage metrics for {cls.__name__}: {e}")
            except Boto3Error as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.error(msg, log)
                raise
            except Exception as e:
                msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
                builder.core_feedback.info(msg, log)
                raise

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        for js in json:
            if instance := cls.from_api(js, builder):
                # post process
                instance.post_process(builder, js)
                builder.add_node(instance, js)

    @classmethod
    def collect_usage_metrics(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        # Default behavior: do nothing
        pass

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        # The default implementation will return the defined api_spec if defined, otherwise an empty list.
        # In case your resource needs more than this api call, please override this method and return the proper list.
        if spec := cls.api_spec:
            return [spec]
        else:
            return []

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return []

    def post_process(self, builder: GraphBuilder, source: Json) -> None:
        # Default behavior: do nothing
        pass

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        # Default behavior: add resource to the namespace
        pass

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


AwsResourceType = TypeVar("AwsResourceType", bound=AwsResource)


# derived from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
@define(eq=False)
class AwsAccount(BaseAccount, AwsResource):
    kind: ClassVar[str] = "aws_account"
    kind_display: ClassVar[str] = "AWS Account"
    kind_description: ClassVar[str] = (
        "An AWS Account is a container for AWS resources, such as EC2 instances, S3"
        " buckets, and RDS databases. It allows users to access and manage their"
        " resources on the Amazon Web Services platform."
    )
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/billing/home?region={region}#/account"}  # fmt: skip
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_region"]}}

    account_alias: Optional[str] = ""
    role: Optional[str] = None
    profile: Optional[str] = None
    partition: str = "aws"
    users: Optional[int] = 0
    groups: Optional[int] = 0
    account_mfa_enabled: Optional[int] = 0
    account_access_keys_present: Optional[int] = 0
    account_signing_certificates_present: Optional[int] = 0
    mfa_devices: Optional[int] = 0
    mfa_devices_in_use: Optional[int] = 0
    policies: Optional[int] = 0
    policy_versions_in_use: Optional[int] = 0
    global_endpoint_token_version: Optional[int] = 0
    server_certificates: Optional[int] = 0
    minimum_password_length: Optional[int] = None
    require_symbols: Optional[bool] = None
    require_numbers: Optional[bool] = None
    require_uppercase_characters: Optional[bool] = None
    require_lowercase_characters: Optional[bool] = None
    allow_users_to_change_password: Optional[bool] = None
    expire_passwords: Optional[bool] = None
    max_password_age: Optional[int] = 0
    password_reuse_prevention: Optional[int] = 0
    hard_expiry: Optional[bool] = None
    is_organization_member: bool = False
    is_organization_master: bool = False
    organization_id: Optional[str] = None
    organization_arn: Optional[str] = None


default_ctime = datetime(2006, 3, 19, tzinfo=timezone.utc)  # AWS public launch date


@define(eq=False)
class AwsRegion(BaseRegion, AwsResource):
    kind: ClassVar[str] = "aws_region"
    kind_display: ClassVar[str] = "AWS Region"
    kind_description: ClassVar[str] = (
        "An AWS Region is a physical location where AWS has multiple data centers,"
        " allowing users to choose the geographic area in which their resources are"
        " located."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "aws_vpc_peering_connection",
                "aws_vpc_endpoint",
                "aws_vpc",
                "aws_service_quota",
                "aws_s3_bucket",
                "aws_rds_instance",
                "aws_iam_server_certificate",
                "aws_iam_role",
                "aws_iam_policy",
                "aws_iam_instance_profile",
                "aws_iam_group",
                "aws_elb",
                "aws_eks_cluster",
                "aws_ec2_volume_type",
                "aws_ec2_volume",
                "aws_iam_user",
                "aws_ec2_subnet",
                "aws_ec2_snapshot",
                "aws_ec2_security_group",
                "aws_ec2_route_table",
                "aws_ec2_network_interface",
                "aws_ec2_network_acl",
                "aws_ec2_nat_gateway",
                "aws_ec2_keypair",
                "aws_ec2_internet_gateway",
                "aws_ec2_instance_type",
                "aws_ec2_instance",
                "aws_ec2_elastic_ip",
                "aws_cloudwatch_alarm",
                "aws_cloudformation_stack",
                "aws_cloudformation_stack_set",
                "aws_autoscaling_group",
                "aws_alb_target_group",
                "aws_alb",
            ]
        }
    }
    ctime: Optional[datetime] = default_ctime

    def __attrs_post_init__(self) -> None:
        super().__attrs_post_init__()
        self.long_name = cloud_region_data.get("aws", {}).get(self.id, {}).get("long_name")
        self.latitude = cloud_region_data.get("aws", {}).get(self.id, {}).get("latitude")
        self.longitude = cloud_region_data.get("aws", {}).get(self.id, {}).get("longitude")


@define(eq=False, slots=False)
class AwsEc2VolumeType(AwsResource, BaseVolumeType):
    kind: ClassVar[str] = "aws_ec2_volume_type"
    kind_display: ClassVar[str] = "AWS EC2 Volume Type"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": None, "arn_tpl": "arn:{partition}:ec2:{region}:{account}:volume/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "EC2 Volume Types are different storage options for Amazon Elastic Block"
        " Store (EBS) volumes, such as General Purpose (SSD) and Magnetic."
    )


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        account: AwsAccount,
        region: AwsRegion,
        client: AwsClient,
        executor: ExecutorQueue,
        core_feedback: CoreFeedback,
        global_instance_types: Optional[Dict[str, Any]] = None,
        graph_nodes_access: Optional[RWLock] = None,
        graph_edges_access: Optional[RWLock] = None,
        last_run_started_at: Optional[datetime] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.region = region
        self.client = client
        self.executor = executor
        self.name = f"AWS:{account.name}:{region.name}"
        self.global_instance_types: Dict[str, Any] = global_instance_types if global_instance_types is not None else {}
        self.core_feedback = core_feedback
        self.graph_nodes_access = graph_nodes_access or RWLock()
        self.graph_edges_access = graph_edges_access or RWLock()
        self.last_run_started_at = last_run_started_at
        self.created_at = utc()

        if last_run_started_at:
            now = utc()

            # limit the metrics to the last hour
            if now - last_run_started_at > timedelta(hours=2):
                start = now - timedelta(hours=2)
            else:
                start = last_run_started_at

            delta = now - start
            # AWS requires period to be a muliple of 60, ceil because we want to overlap when in doubt
            delta = timedelta(seconds=ceil(delta.total_seconds() / 60) * 60)
            min_delta = max(delta, timedelta(seconds=600))
            # in case the last collection happened too quickly, raise the metrics timedelta to 600s,
            # otherwise we get no results from AWS
            if min_delta != delta:
                start = now - min_delta
                delta = min_delta
        else:
            now = utc()
            delta = timedelta(hours=1)
            start = now - delta

        self.metrics_start = start
        self.metrics_delta = delta

    def suppress(self, message: str) -> SuppressWithFeedback:
        return SuppressWithFeedback(message, self.core_feedback, log)

    def submit_work(self, service: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        """
        Use this method for work that can be done in parallel.
        Note: the executor pool is shared between all regions and only allows the configured number of tasks per key.
              Key: RegionId:Service in the same region and the same service start only the configured number of tasks
        """

        def fn_wrapper() -> T:
            set_thread_name(f"aws_{self.account.id}_{self.region.id}_{service}")
            return fn(*args, **kwargs)

        return self.executor.submit_work(self.region.id + ":" + service, fn_wrapper)

    @property
    def config(self) -> AwsConfig:
        return self.client.config

    def node(self, clazz: Optional[Type[AwsResourceType]] = None, **node: Any) -> Optional[AwsResourceType]:
        if isinstance(nd := node.get("node"), AwsResource):
            return nd  # type: ignore
        with self.graph_nodes_access.read_access:
            for n in self.graph:
                is_clazz = isinstance(n, clazz) if clazz else True
                if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                    return n  # type: ignore
        return None

    def nodes(self, clazz: Optional[Type[AwsResourceType]] = None, **node: Any) -> Iterator[AwsResourceType]:
        with self.graph_nodes_access.read_access:
            for n in self.graph:
                is_clazz = isinstance(n, clazz) if clazz else True
                if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                    yield n

    def add_node(
        self, node: AwsResourceType, source: Optional[Json] = None, region: Optional[AwsRegion] = None
    ) -> AwsResourceType:
        """
        Add a node to the graph.
        :param node: the node to add.
        :param source: the source json data.
        :param region: only define the region in case it is different from the region of the graph builder.
        :return: the added node
        """
        log.debug(f"Added node {node.kdname}")
        node._cloud = self.cloud
        node._account = self.account
        node._region = region or self.region

        meta = getattr(type(node), "aws_metadata", None) or {}
        # if there is no arn: try to create one from template
        if node.arn is None and (arn_tpl := meta.get("arn_tpl")):
            try:
                node.arn = arn_tpl.format(
                    partition=self.account.partition,
                    id=node.id,
                    name=node.name,
                    account=self.account.id,
                    region=self.region.name,
                )
            except Exception as e:
                log.warning(f"Can not compute ARN for {node} with template: {arn_tpl}: {e}")

        # If there is no provider_link: try to create one from template.
        # The template can use the complete src json, plus some base attributes.
        if node._metadata.get("provider_link") is None and (link_tpl := meta.get("provider_link_tpl")):
            try:
                all_params = True
                link = link_tpl
                for placeholder in TemplateRE.findall(link_tpl):
                    value = (
                        fn(node)
                        if (fn := TemplateFn.get(placeholder))
                        else (value_in_path(source, placeholder) or getattr(node, placeholder, None))
                    )
                    if value is None:
                        all_params = False
                        break
                    else:
                        link = link.replace("{" + placeholder + "}", urlquote(str(value)))
                if all_params:
                    node._metadata["provider_link"] = link
            except Exception as e:
                log.warning(f"Can not compute provider_link for {node} with template: {link_tpl}: {e}")

        with self.graph_nodes_access.write_access:
            self.graph.add_node(node, source=source or {})
        return node

    def add_edge(
        self, from_node: BaseResource, edge_type: EdgeType = EdgeType.default, reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            with self.graph_edges_access.write_access:
                self.graph.add_edge(start, end, edge_type=edge_type)

    def add_deferred_edge(
        self, from_node: BaseResource, edge_type: EdgeType, to_node: str, reverse: bool = False
    ) -> None:
        node1: NodeSelector = ByNodeId(from_node.chksum)
        node2: NodeSelector = BySearchCriteria(to_node)
        start, end = (node2, node1) if reverse else (node1, node2)
        self.graph.add_deferred_edge(start, end, edge_type)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_same_as_default: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            with self.graph_edges_access.write_access:
                self.graph.add_edge(start, end, edge_type=EdgeType.default)
                if delete_same_as_default:
                    start, end = end, start
                log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
                self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[AwsResourceType]) -> List[AwsResourceType]:
        with self.graph_nodes_access.read_access:
            return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    def edges_of(
        self, from_type: Type[AwsResource], to_type: Type[AwsResource], edge_type: EdgeType = EdgeType.default
    ) -> List[EdgeKey]:
        with self.graph_edges_access.read_access:
            return [
                key
                for (from_node, to_node, key) in self.graph.edges
                if isinstance(from_node, from_type) and isinstance(to_node, to_type) and key.edge_type == edge_type
            ]

    @lru_cache(maxsize=None)
    def instance_type(self, region: AwsRegion, instance_type: str) -> Optional[Any]:
        if (it := self.global_instance_types.get(instance_type)) is None:
            return None  # instance type not found

        price = value_in_path(cloud_instance_data, ["aws", instance_type, "pricing", region.id, "linux", "ondemand"])
        physical_processor = value_in_path(cloud_instance_data, ["aws", instance_type, "physical_processor"])
        gpu_model = value_in_path(cloud_instance_data, ["aws", instance_type, "GPU_model"])
        pretty_name = value_in_path(cloud_instance_data, ["aws", instance_type, "pretty_name"])
        ecu = value_in_path(cloud_instance_data, ["aws", instance_type, "ECU"])
        ecu = float(ecu) if isinstance(ecu, (int, float)) else None
        result = evolve(it, region=region, ondemand_cost=price, pretty_name=pretty_name, ecu=ecu)
        if getattr(result, "instance_type_processor_info", None):
            result.instance_type_processor_info.physical_processor = physical_processor
        if getattr(result, "instance_type_gpu_info", None):
            result.instance_type_gpu_info.gpu_model = gpu_model
        # add this instance type to the graph
        self.add_node(result, region=region)
        self.add_edge(region, node=result)
        return result

    @lru_cache(maxsize=None)
    def volume_type(self, volume_type: str) -> Optional[Any]:
        price = AwsPricingPrice.volume_type_price(self.client, volume_type, self.region.safe_name)
        vt = AwsEc2VolumeType(
            id=volume_type,
            name=volume_type,
            volume_type=volume_type,
            ondemand_cost=price.on_demand_price_usd if price else None,
            region=self.region,
        )
        self.add_node(vt, {})
        return vt

    def for_region(self, region: AwsRegion) -> GraphBuilder:
        return GraphBuilder(
            self.graph,
            self.cloud,
            self.account,
            region,
            self.client.for_region(region.safe_name),
            self.executor,
            self.core_feedback,
            self.global_instance_types,
            self.graph_nodes_access,
            self.graph_edges_access,
            self.last_run_started_at,
        )
