from __future__ import annotations

import concurrent
import logging
from concurrent.futures import Executor, Future
from datetime import datetime, timezone
from functools import lru_cache
from threading import Lock
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar, Callable

from attr import evolve
from attrs import define
from boto3.exceptions import Boto3Error

from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.pricing import AwsPricingPrice
from resotolib.baseresources import BaseResource, EdgeType, Cloud, BaseAccount, BaseRegion, BaseVolumeType
from resotolib.graph import Graph
from resotolib.json import to_json as to_js, from_json as from_js
from resotolib.json_bender import Bender, bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")


@define
class AwsApiSpec:
    """
    Specifications for the AWS API to call and the expected response.
    """

    service: str
    api_action: str
    result_property: Optional[str] = None
    parameter: Optional[Dict[str, Any]] = None


@define(eq=False, slots=False)
class AwsResource(BaseResource):
    """
    Base class for all AWS resources.
    Override kind, mapping and api_spec for every resource that is collected in AWS.
    """

    # The name of the kind of all resources. Needs to be globally unique.
    kind: ClassVar[str] = "aws_resource"
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[AwsApiSpec]] = None

    # The AWS specific identifier of the resource. Not available for all resources.
    arn: Optional[str] = None

    # TODO: implement me
    def update_tag(self, key: str, value: str) -> bool:
        pass

    # TODO: implement me
    def delete_tag(self, key: str) -> bool:
        pass

    # TODO: implement me
    def delete(self, graph: Graph) -> bool:
        return False

    def to_json(self) -> Json:
        return to_js(
            self,
            strip_attr=(
                "mapping",
                "phantom",
                "reference_kinds",
                "parent_resource",
                "usage_percentage",
                "dname",
                "kdname",
                "rtdname",
                "changes",
                "event_log",
                "str_event_log",
                "chksum",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "_graph",
                "graph",
                "max_graph_depth",
                "resource_type",
                "age",
                "last_access",
                "last_update",
                "clean",
                "cleaned",
                "protected",
                "uuid",
                "kind",
                "api_spec",
            ),
        )

    @classmethod
    def from_json(cls: Type[AwsResourceType], json: Json) -> AwsResourceType:
        return from_js(json, cls)

    @classmethod
    def from_api(cls: Type[AwsResourceType], json: Json) -> AwsResourceType:
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        if spec := cls.api_spec:
            try:
                kwargs = spec.parameter or {}
                items = builder.client.list(spec.service, spec.api_action, spec.result_property, **kwargs)
                cls.collect(items, builder)
            except Boto3Error as e:
                log.error(f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}")
                raise

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)

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
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [],
        "delete": ["aws_ec2_instance"],
    }

    account_alias: Optional[str] = ""
    role: Optional[str] = None
    profile: Optional[str] = None
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


default_ctime = datetime(2006, 3, 19, tzinfo=timezone.utc)  # AWS public launch date


@define(eq=False)
class AwsRegion(BaseRegion, AwsResource):
    kind: ClassVar[str] = "aws_region"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": [
            "aws_vpc_quota",
            "aws_vpc_peering_connection",
            "aws_vpc_endpoint",
            "aws_vpc",
            "aws_s3_bucket_quota",
            "aws_s3_bucket",
            "aws_rds_instance",
            "aws_iam_server_certificate_quota",
            "aws_iam_server_certificate",
            "aws_iam_role",
            "aws_iam_policy",
            "aws_iam_instance_profile",
            "aws_iam_group",
            "aws_elb_quota",
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
            "aws_ec2_internet_gateway_quota",
            "aws_ec2_internet_gateway",
            "aws_ec2_instance_type",
            "aws_ec2_instance_quota",
            "aws_ec2_instance",
            "aws_ec2_elastic_ip",
            "aws_cloudwatch_alarm",
            "aws_cloudformation_stack",
            "aws_cloudformation_stack_set",
            "aws_autoscaling_group",
            "aws_alb_target_group",
            "aws_alb_quota",
            "aws_alb",
        ]
    }
    ctime: Optional[datetime] = default_ctime


@define(eq=False, slots=False)
class AwsEc2VolumeType(AwsResource, BaseVolumeType):
    kind: ClassVar[str] = "aws_ec2_volume_type"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_volume"],
        "delete": [],
    }


@define
class ExecutorQueue:
    executor: Executor
    name: str
    futures: List[Future[Any]] = []
    _lock: Lock = Lock()

    def submit_work(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> Future[Any]:
        future = self.executor.submit(fn, *args, **kwargs)
        with self._lock:
            self.futures.append(future)
        return future

    def wait_for_submitted_work(self) -> None:
        # wait until all futures are complete
        with self._lock:
            to_wait = self.futures
            self.futures = []
        for future in concurrent.futures.as_completed(to_wait):
            try:
                future.result()
            except Exception as ex:
                log.exception(f"Unhandled exception in account {self.name}: {ex}")
                raise


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        account: AwsAccount,
        region: AwsRegion,
        client: AwsClient,
        executor: ExecutorQueue,
        global_instance_types: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.region = region
        self.client = client
        self.executor = executor
        self.name = f"AWS:{account.name}:{region.name}"
        self.global_instance_types: Dict[str, Any] = global_instance_types or {}

    def submit_work(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> Future[Any]:
        return self.executor.submit_work(fn, *args, **kwargs)

    @property
    def config(self) -> AwsConfig:
        return self.client.config

    def node(self, clazz: Optional[Type[AwsResourceType]] = None, **node: Any) -> Optional[AwsResourceType]:
        if isinstance(nd := node.get("node"), AwsResource):
            return nd  # type: ignore
        for n in self.graph:
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                return n  # type: ignore
        return None

    def add_node(self, node: AwsResourceType, source: Optional[Json] = None) -> AwsResourceType:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.account
        node._region = self.region
        self.graph.add_node(node, source=source or {})
        return node

    def add_edge(self, from_node: BaseResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [{edge_type}]")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            self.graph.add_edge(start, end, edge_type=EdgeType.default)
            if delete_reverse:
                start, end = end, start
            log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
            self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[AwsResourceType]) -> List[AwsResourceType]:
        return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    @lru_cache(maxsize=None)
    def instance_type(self, instance_type: str) -> Optional[Any]:
        if (global_type := self.global_instance_types.get(instance_type)) is None:
            return None  # instance type not found
        price = AwsPricingPrice.instance_type_price(self.client, instance_type, self.region.name)
        return evolve(global_type, region=self.region, ondemand_cost=price.on_demand_price_usd if price else None)

    @lru_cache(maxsize=None)
    def volume_type(self, volume_type: str) -> Optional[Any]:
        price = AwsPricingPrice.volume_type_price(self.client, volume_type, self.region.name)
        return AwsEc2VolumeType(
            id=volume_type,
            name=volume_type,
            volume_type=volume_type,
            ondemand_cost=price.on_demand_price_usd if price else 0,
        )

    def for_region(self, region: AwsRegion) -> GraphBuilder:
        return GraphBuilder(
            self.graph,
            self.cloud,
            self.account,
            region,
            self.client.for_region(region.name),
            self.executor,
            self.global_instance_types,
        )
