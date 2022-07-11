from __future__ import annotations

import json
import logging
from functools import cached_property, lru_cache

from attr import evolve
from attrs import define
from datetime import datetime, timezone
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar

from botocore.loaders import Loader

from resoto_plugin_aws.aws_client import AwsClient
from resotolib.baseresources import BaseResource, EdgeType, Cloud, BaseAccount, BaseRegion
from resotolib.graph import Graph
from resotolib.json import to_json as to_js, from_json as from_js
from resotolib.json_bender import Bender, bend, S, F
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
                "successor_kinds",
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
    def from_json(cls: Type[AWSResourceType], json: Json) -> AWSResourceType:
        return from_js(json, cls)

    @classmethod
    def from_api(cls: Type[AWSResourceType], json: Json) -> AWSResourceType:
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

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


AWSResourceType = TypeVar("AWSResourceType", bound=AwsResource)


# derived from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
@define(eq=False)
class AwsAccount(BaseAccount, AwsResource):
    kind: ClassVar[str] = "aws_account"
    account_alias: Optional[str] = ""
    role: Optional[str] = None
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
    ctime: Optional[datetime] = default_ctime


class GraphBuilder:
    def __init__(
        self,
        graph: Graph,
        cloud: Cloud,
        account: AwsAccount,
        region: AwsRegion,
        client: AwsClient,
        global_instance_types: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.region = region
        self.client = client
        self.name = f"AWS:{account.name}:{region.name}"
        self.boto_loader = Loader()
        self.global_instance_types: Dict[str, Any] = global_instance_types or {}

    @cached_property
    def price_region(self) -> str:
        endpoints = self.boto_loader.load_data("endpoints")
        price_name: str = bend(S("partitions")[0] >> S("regions", self.region.name, "description"), endpoints)
        return price_name.replace("Europe", "EU")  # note: Europe is named differently in the price list

    def node(self, clazz: Optional[Type[AWSResourceType]] = None, **node: Any) -> Optional[AWSResourceType]:
        if isinstance(nd := node.get("node"), AwsResource):
            return nd  # type: ignore
        for n in self.graph:
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                return n  # type: ignore
        return None

    def add_node(self, node: AwsResource, source: Json) -> None:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.account
        node._region = self.region
        self.graph.add_node(node, source=source)

    def add_edge(self, from_node: BaseResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end}")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def dependant_node(
        self, from_node: BaseResource, reverse: bool = False, delete_reverse: bool = False, **to_node: Any
    ) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AwsResource) and isinstance(to_n, AwsResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add dependant edge: {start} -> {end}")
            self.graph.add_edge(start, end, edge_type=EdgeType.default)
            if delete_reverse:
                start, end = end, start
            self.graph.add_edge(end, start, edge_type=EdgeType.delete)

    def resources_of(self, resource_type: Type[AWSResourceType]) -> List[AWSResourceType]:
        return [n for n in self.graph.nodes if isinstance(n, resource_type)]

    @lru_cache(maxsize=None)
    def instance_type(self, instance_type: str) -> Optional[Any]:
        if (global_type := self.global_instance_types.get(instance_type)) is None:
            return None  # instance type not found
        # get price information
        search_filter = [
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "operation", "Value": "RunInstances"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": self.price_region},
        ]
        # Prices are only available in us-east-1
        prices = self.client.for_region("us-east-1").list(
            "pricing", "get-products", "PriceList", ServiceCode="AmazonEC2", Filters=search_filter, MaxResults=1
        )
        if prices:
            first = F(lambda x: x.get(next(iter(x)), {}))
            pi = S("terms", "OnDemand") >> first >> S("priceDimensions") >> first >> S("pricePerUnit", "USD")
            usd = bend(pi, json.loads(prices[0]))
            result = evolve(global_type, region=self.region, ondemand_cost=usd)
        else:
            result = evolve(global_type, region=self.region)

        return result

    def for_region(self, region: AwsRegion) -> GraphBuilder:
        return GraphBuilder(
            self.graph,
            self.cloud,
            self.account,
            region,
            self.client.for_region(region.name),
            self.global_instance_types,
        )
