from __future__ import annotations

import concurrent
import logging
from abc import ABC
from collections import defaultdict, deque
from concurrent.futures import Executor, Future
from datetime import datetime, timezone
from functools import lru_cache, reduce
from threading import Lock, Event
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar, Callable, Iterator, Deque, Tuple

from attr import evolve, field
from attrs import define
from boto3.exceptions import Boto3Error

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.configuration import AwsConfig
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
from resotolib.graph import Graph, EdgeKey, ByNodeId, BySearchCriteria, NodeSelector
from resotolib.json_bender import Bender, bend
from resotolib.lock import RWLock
from resotolib.proc import set_thread_name
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


class GatherFutures:
    def __init__(self, futures: List[Future[Any]]) -> None:
        self._futures = futures
        self._lock = Lock()
        self._to_wait = len(futures)
        self._when_done: Future[None] = Future()
        for future in futures:
            future.add_done_callback(self._on_future_done)

    def _on_future_done(self, _: Future[Any]) -> None:
        with self._lock:
            self._to_wait -= 1
            if self._to_wait == 0:
                self._when_done.set_result(None)

    @staticmethod
    def all(futures: List[Future[Any]]) -> Future[None]:
        return GatherFutures(futures)._when_done


@define
class ExecutorQueueTask:
    key: Any
    fn: Callable[..., T]
    args: Tuple[Any, ...]
    kwargs: Dict[str, Any]
    future: Future[Any]

    def __call__(self) -> T:  # type: ignore
        try:
            result: T = self.fn(*self.args, **self.kwargs)
            self.future.set_result(result)
            return result
        except Exception as e:
            self.future.set_exception(e)
            raise


@define
class ExecutorQueue:
    """
    Use an underlying executor to perform work in parallel, but limit the number of tasks per key.
    If fail_on_first_exception_in_group is True, then the first exception in a group
    will not execute any more tasks in the same group.
    """

    executor: Executor
    tasks_per_key: Callable[[str], int]
    name: str
    fail_on_first_exception_in_group: bool = False
    _tasks_lock: Lock = Lock()
    _tasks: Dict[str, Deque[ExecutorQueueTask]] = field(factory=lambda: defaultdict(deque))
    _in_progress: Dict[str, int] = field(factory=lambda: defaultdict(int))
    _futures: List[Future[Any]] = field(factory=list)
    _exceptions: Dict[Any, Exception] = field(factory=dict)
    _task_finished: Event = Event()

    def submit_work(self, key: Any, fn: Callable[..., T], *args: Any, **kwargs: Any) -> Future[T]:
        future = Future[T]()
        task = ExecutorQueueTask(key=key, fn=fn, args=args, kwargs=kwargs, future=future)
        self.__append_work(task)
        return future

    def __append_work(self, task: ExecutorQueueTask) -> None:
        with self._tasks_lock:
            self._tasks[task.key].appendleft(task)
            self.__check_queue(task.key)

    def __check_queue(self, key: Any) -> None:
        # note: this method is not thread safe, it should only be called from within a lock
        in_progress = self._in_progress[key]
        tasks = self._tasks[key]

        if self.fail_on_first_exception_in_group and self._exceptions.get(key) is not None:
            # Fail all tasks in this group
            ex = CancelOnFirstError("Exception happened in another thread. Do not start work.")
            for task in tasks:
                task.future.set_exception(ex)
            # Clear the queue, so we don't execute them
            # Clear the queue, so we don't execute them
            tasks.clear()

        if in_progress < self.tasks_per_key(key) and tasks:
            task = tasks.pop()
            self._in_progress[key] += 1
            self.__perform_task(task)

    def __perform_task(self, task: ExecutorQueueTask) -> Future[T]:
        def only_start_when_no_error() -> T:
            # in case of exception let's fail fast and do not execute the function
            if self._exceptions.get(task.key) is None:
                try:
                    return task()
                except Exception as e:
                    # only store the first exception if we should fail on first future
                    if self._exceptions.get(task.key) is None:
                        self._exceptions[task.key] = e
                    raise e
            else:
                raise CancelOnFirstError(
                    "Exception happened in another thread. Do not start work."
                ) from self._exceptions[task.key]

        def execute() -> T:
            try:
                return only_start_when_no_error() if self.fail_on_first_exception_in_group else task()
            finally:
                with self._tasks_lock:
                    self._in_progress[task.key] -= 1
                    self._task_finished.set()
                    self.__check_queue(task.key)

        future = self.executor.submit(execute)

        self._futures.append(future)
        return future

    def wait_for_submitted_work(self) -> None:
        # wait until all futures are complete
        to_wait = []

        # step 1: wait until all tasks are committed to the executor
        while True:
            with self._tasks_lock:
                ip = reduce(lambda x, y: x + y, self._in_progress.values(), 0)
                if ip == 0:
                    to_wait = self._futures
                    self._futures = []
                    break
                else:
                    # safe inside the lock. clear this event and check when next task is done
                    self._task_finished.clear()
            self._task_finished.wait()

        # step 2: wait for all tasks to complete
        for future in concurrent.futures.as_completed(to_wait):
            try:
                future.result()
            except CancelOnFirstError:
                pass
            except Exception as ex:
                log.exception(f"Unhandled exception in {self.name}: {ex}")
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
        graph_nodes_access: Optional[RWLock] = None,
        graph_edges_access: Optional[RWLock] = None,
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

        price = AwsPricingPrice.instance_type_price(self.client.for_region(region.id), instance_type, region.safe_name)
        result = evolve(it, region=region, ondemand_cost=price.on_demand_price_usd if price else None)
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
            self.graph_nodes_access,
            self.graph_edges_access,
        )
