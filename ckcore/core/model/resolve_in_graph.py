from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List


class NodePath:
    node_id = ["id"]
    kinds = ["kinds"]
    reported_kind = ["reported", "kind"]
    reported_ctime = ["reported", "ctime"]
    reported_id = ["reported", "id"]
    reported_name = ["reported", "name"]


@dataclass(frozen=True)
class ResolveProp:
    # Path to the property that needs to be extracted
    extract_path: List[str]

    # Path to write this property to
    to_path: List[str]


@dataclass(frozen=True)
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
                ResolveProp(NodePath.reported_name, ["metadata", "ancestors", "cloud", "name"]),
                ResolveProp(NodePath.reported_id, ["metadata", "ancestors", "cloud", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "cloud_id"]),
            ],
        ),
        ResolveAncestor(
            "account",
            [
                ResolveProp(NodePath.reported_name, ["metadata", "ancestors", "account", "name"]),
                ResolveProp(NodePath.reported_id, ["metadata", "ancestors", "account", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "account_id"]),
            ],
        ),
        ResolveAncestor(
            "region",
            [
                ResolveProp(NodePath.reported_name, ["metadata", "ancestors", "region", "name"]),
                ResolveProp(NodePath.reported_id, ["metadata", "ancestors", "region", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "region_id"]),
            ],
        ),
        ResolveAncestor(
            "zone",
            [
                ResolveProp(NodePath.reported_name, ["metadata", "ancestors", "zone", "name"]),
                ResolveProp(NodePath.reported_id, ["metadata", "ancestors", "zone", "id"]),
                ResolveProp(NodePath.node_id, ["refs", "zone_id"]),
            ],
        ),
    ]

    resolved_ancestors = {
        kind: ".".join(prop.to_path) for kind, prop in {a.kind: a.resolves_id() for a in to_resolve}.items() if prop
    }
