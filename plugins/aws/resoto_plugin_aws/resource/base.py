import logging
from attrs import define
from datetime import datetime, timezone
from typing import ClassVar, Dict, Optional, List, Type, Any, TypeVar

from resoto_plugin_aws.aws_client import AwsClient
from resotolib.baseresources import BaseResource, EdgeType, Cloud, BaseAccount, BaseRegion, BaseInstanceType
from resotolib.graph import Graph
from resotolib.json import to_json as to_js, from_json as from_js
from resotolib.json_bender import Bender, bend
from resotolib.types import Json

log = logging.getLogger("resoto.plugins.aws")

default_ctime = datetime(2006, 3, 19, tzinfo=timezone.utc)  # AWS public launch date


@define(eq=False, slots=False)
class AWSResource(BaseResource):
    mapping: ClassVar[Dict[str, Bender]] = {}
    kind: ClassVar[str] = "aws_resource"
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
            ),
        )

    @classmethod
    def from_json(cls: Type["AWSResourceType"], json: Json) -> "AWSResourceType":
        return from_js(json, cls)

    @classmethod
    def from_api(cls: Type["AWSResourceType"], json: Json) -> "AWSResourceType":
        mapped = bend(cls.mapping, json)
        return cls.from_json(mapped)

    @classmethod
    def collect(cls: Type["AWSResource"], json: List[Json], builder: "GraphBuilder") -> None:
        # Default behavior: iterate over json snippets and for each:
        # - bend the json
        # - transform the result into a resource
        # - add the resource to the graph
        # In case additional work needs to be done, override this method.
        for js in json:
            instance = cls.from_api(js)
            builder.add_node(instance, js)

    def connect_in_graph(self, builder: "GraphBuilder", source: Json) -> None:
        # Default behavior: add resource to the namespace
        pass

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


AWSResourceType = TypeVar("AWSResourceType", bound=AWSResource)


# derived from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
@define(eq=False)
class AWSAccount(BaseAccount, AWSResource):
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


@define(eq=False)
class AWSRegion(BaseRegion, AWSResource):
    kind: ClassVar[str] = "aws_region"
    ctime: Optional[datetime] = default_ctime


@define(eq=False)
class AWSEC2InstanceType(AWSResource, BaseInstanceType):
    kind: ClassVar[str] = "aws_ec2_instance_type"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["aws_ec2_instance"],
        "delete": [],
    }


class GraphBuilder:
    def __init__(self, graph: Graph, cloud: Cloud, account: AWSAccount, region: AWSRegion, client: AwsClient) -> None:
        self.graph = graph
        self.cloud = cloud
        self.account = account
        self.region = region
        self.client = client
        self.name = f"AWS:{account.name}:{region.name}"

    def node(self, clazz: Optional[Type[AWSResource]] = None, **node: Any) -> Optional[AWSResource]:
        if isinstance(nd := node.get("node"), AWSResource):
            return nd
        for n in self.graph:
            is_clazz = isinstance(n, clazz) if clazz else True
            if is_clazz and all(getattr(n, k, None) == v for k, v in node.items()):
                return n  # type: ignore
        return None

    def add_node(self, node: AWSResource, source: Json) -> None:
        log.debug(f"{self.name}: add node {node}")
        node._cloud = self.cloud
        node._account = self.account
        node._region = self.region
        self.graph.add_node(node, source=source)

    def add_edge(self, from_node: BaseResource, edge_type: EdgeType, reverse: bool = False, **to_node: Any) -> None:
        to_n = self.node(**to_node)
        if isinstance(from_node, AWSResource) and isinstance(to_n, AWSResource):
            start, end = (to_n, from_node) if reverse else (from_node, to_n)
            log.debug(f"{self.name}: add edge: {start} -> {end}")
            self.graph.add_edge(start, end, edge_type=edge_type)

    def instance_type(self, instance_type: Optional[str]) -> Optional[AWSEC2InstanceType]:
        # TODO: implement me
        return None
