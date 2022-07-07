from __future__ import annotations

from attrs import define
from typing import Optional, List

from resotocore.types import Json
from resotocore.util import value_in_path_get


class NodePath:
    node_id = ["id"]
    kinds = ["kinds"]
    type = ["type"]
    revision = ["revision"]
    reported = ["reported"]
    reported_kind = ["reported", "kind"]
    reported_ctime = ["reported", "ctime"]
    reported_id = ["reported", "id"]
    reported_name = ["reported", "name"]
    descendant_summary = ["metadata", "descendant_summary"]
    descendant_count = ["metadata", "descendant_count"]
    python_type = ["metadata", "python_type"]
    is_phantom = ["metadata", "phantom"]
    from_node = ["from"]
    to_node = ["to"]
    edge_type = ["edge_type"]
    ancestor_account_name = ["ancestors", "account", "reported", "name"]


@define(frozen=True)
class ResolveProp:
    # Path to the property that needs to be extracted
    extract_path: List[str]

    # Path to write this property to
    to_path: List[str]

    # If this resolver should apply, if the related node is the node itself.
    # e.g.: the node is an account node and the ancestor of type account is requested.
    apply_on_self: bool = False

    @property
    def to(self) -> str:
        return ".".join(self.to_path)


@define(frozen=True)
class ResolveAncestor:
    # kind of ancestor. Stop at first occurrence.
    kind: str
    # List of all properties to be resolved.
    resolve: List[ResolveProp]

    def resolves_id(self) -> Optional[ResolveProp]:
        for prop in self.resolve:
            if prop.extract_path == NodePath.node_id:
                return prop
        return None


class GraphResolver:
    """
    Resolve common properties from the structure of the graph and make them available
    as properties on the node. This way the data does not have to be looked up in the hierarchy
    but can be queried directly.
    """

    to_resolve = [
        ResolveAncestor(
            "cloud",
            [
                ResolveProp(NodePath.reported_name, ["ancestors", "cloud", "reported", "name"]),
                ResolveProp(NodePath.reported_id, ["ancestors", "cloud", "reported", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "cloud_id"], apply_on_self=True),
            ],
        ),
        ResolveAncestor(
            "account",
            [
                ResolveProp(NodePath.reported_name, ["ancestors", "account", "reported", "name"]),
                ResolveProp(NodePath.reported_id, ["ancestors", "account", "reported", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "account_id"], apply_on_self=True),
            ],
        ),
        ResolveAncestor(
            "region",
            [
                ResolveProp(NodePath.reported_name, ["ancestors", "region", "reported", "name"]),
                ResolveProp(NodePath.reported_id, ["ancestors", "region", "reported", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "region_id"], apply_on_self=True),
            ],
        ),
        ResolveAncestor(
            "zone",
            [
                ResolveProp(NodePath.reported_name, ["ancestors", "zone", "reported", "name"]),
                ResolveProp(NodePath.reported_id, ["ancestors", "zone", "reported", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "zone_id"], apply_on_self=True),
            ],
        ),
    ]

    # dict: kind->property name to get the id in order to resolve this kind
    resolved_ancestors = {kind: prop.to for kind, prop in {a.kind: a.resolves_id() for a in to_resolve}.items() if prop}

    # set of all resolved property names
    resolved_property_names = {prop.to for elem in to_resolve for prop in elem.resolve}

    count_successors = {
        # note: order is important. zone is computed first and can be reused for region -> account -> cloud etc.
        "zone": ResolveProp(NodePath.reported_kind, NodePath.descendant_summary),
        "region": ResolveProp(NodePath.reported_kind, NodePath.descendant_summary),
        "account": ResolveProp(NodePath.reported_kind, NodePath.descendant_summary),
        "cloud": ResolveProp(NodePath.reported_kind, NodePath.descendant_summary),
    }

    @staticmethod
    def resolved_kind(node: Json) -> Optional[str]:
        kinds: List[str] = value_in_path_get(node, NodePath.kinds, [])
        for kind in kinds:
            if kind in GraphResolver.resolved_ancestors:
                return kind
        return None
