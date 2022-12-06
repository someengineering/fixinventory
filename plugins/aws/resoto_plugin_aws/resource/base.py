from __future__ import annotations

import concurrent
import logging
from abc import ABC
from concurrent.futures import Executor, Future
from datetime import datetime, timezone
from functools import lru_cache
from threading import Lock
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar, Callable

from attr import evolve, field
from attrs import define
from boto3.exceptions import Boto3Error

from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.pricing import AwsPricingPrice
from resoto_plugin_aws.utils import arn_partition
from resotolib.baseresources import (
    BaseResource,
    EdgeType,
    Cloud,
    BaseAccount,
    BaseRegion,
    BaseVolumeType,
    ModelReference,
)
from resotolib.config import Config, current_config
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.json import to_json as to_js, from_json as from_js
from resotolib.json_bender import Bender, bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")


def get_client(config: Config, resource: BaseResource) -> AwsClient:
    account = resource.account()
    assert isinstance(account, AwsAccount)
    return AwsClient(config.aws, account.id, role=account.role, profile=account.profile, region=resource.region().id)


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
    # The mapping to transform the incoming API json into the internal representation.
    mapping: ClassVar[Dict[str, Bender]] = {}
    # Which API to call and what to expect in the result.
    api_spec: ClassVar[Optional[AwsApiSpec]] = None

    # The AWS specific identifier of the resource. Not available for all resources.
    arn: Optional[str] = None

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        raise NotImplementedError

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        raise NotImplementedError

    def delete_resource(self, client: AwsClient) -> bool:
        return False

    # legacy interface
    def update_tag(self, key: str, value: str) -> bool:
        return self.update_resource_tag(get_client(current_config(), self), key, value)

    # legacy interface
    def delete_tag(self, key: str) -> bool:
        return self.delete_resource_tag(get_client(current_config(), self), key)

    # legacy interface
    def delete(self, graph: Graph) -> bool:
        return self.delete_resource(get_client(current_config(), self))

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
                items = builder.client.list(
                    aws_service=spec.service,
                    action=spec.api_action,
                    result_name=spec.result_property,
                    expected_errors=spec.expected_errors,
                    **kwargs,
                )
                cls.collect(items, builder)
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
            instance = cls.from_api(js)
            builder.add_node(instance, js)

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
    reference_kinds: ClassVar[ModelReference] = {"successors": {"default": ["aws_region"]}}

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


@define(eq=False, slots=False)
class AwsEc2VolumeType(AwsResource, BaseVolumeType):
    kind: ClassVar[str] = "aws_ec2_volume_type"


T = TypeVar("T")


class CancelOnFirstError(Exception):
    pass


@define
class ExecutorQueue:
    executor: Executor
    name: str
    fail_on_first_exception: bool = False
    futures: List[Future[Any]] = field(factory=list)
    _lock: Lock = Lock()
    _exception: Optional[Exception] = None

    def submit_work(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        def do_work() -> T:
            # in case of exception let's fail fast and do not execute the function
            if self._exception is None:
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    # only store the first exception if we should fail on first future
                    if self._exception is None:
                        self._exception = e
                    raise e
            else:
                raise CancelOnFirstError(
                    "Exception happened in another thread. Do not start work."
                ) from self._exception

        future = (
            self.executor.submit(do_work) if self.fail_on_first_exception else self.executor.submit(fn, *args, **kwargs)
        )

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
            except CancelOnFirstError:
                pass
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
        core_feedback: CoreFeedback,
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
        self.core_feedback = core_feedback

    def submit_work(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> Future[Any]:
        """
        Use this method for work that can be done in parallel.
        Example: fetching tags of a resource.
        """
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

    def add_edge(
        self, from_node: BaseResource, edge_type: EdgeType = EdgeType.default, reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [{edge_type}]")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_same_as_default: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end} [default]")
            self.graph.add_edge(start, end, edge_type=EdgeType.default)
            if delete_same_as_default:
                start, end = end, start
            log.debug(f"{self.name}: add edge: {end} -> {start} [delete]")
            self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[AwsResourceType]) -> List[AwsResourceType]:
        return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    @lru_cache(maxsize=None)
    def instance_type(self, instance_type: str) -> Optional[Any]:
        if (global_type := self.global_instance_types.get(instance_type)) is None:
            return None  # instance type not found
        price = AwsPricingPrice.instance_type_price(self.client, instance_type, self.region.safe_name)
        return evolve(global_type, region=self.region, ondemand_cost=price.on_demand_price_usd if price else None)

    @lru_cache(maxsize=None)
    def volume_type(self, volume_type: str) -> Optional[Any]:
        price = AwsPricingPrice.volume_type_price(self.client, volume_type, self.region.safe_name)
        vt = AwsEc2VolumeType(
            id=volume_type,
            name=volume_type,
            volume_type=volume_type,
            ondemand_cost=price.on_demand_price_usd if price else 0,
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
        )
