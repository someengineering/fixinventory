from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class NodePath:
    node_id = ["id"]
    kinds = ["kinds"]
    reported_kind = ["reported", "kind"]
    reported_id = ["reported", "id"]
    reported_name = ["reported", "name"]


@dataclass(frozen=True)
class ResolveProp:
    # Path to the property that needs to be extracted
    extract_path: list[str]
    # section to write the result (e.g. metadata, refs etc)
    section: str
    # name of property in section
    name: str


@dataclass(frozen=True)
class ResolveAncestor:
    # kind of ancestor. Stop at first occurrence.
    kind: str
    # List of all properties to be resolved.
    resolve: list[ResolveProp]

    def resolves_id(self) -> Optional[ResolveProp]:
        for prop in self.resolve:
            if prop.extract_path == NodePath.node_id:
                return prop
        return None


class GraphResolver:
    to_resolve = [
        ResolveAncestor(
            "cloud",
            [
                ResolveProp(NodePath.reported_name, "metadata", "cloud"),
                ResolveProp(NodePath.node_id, "refs", "cloud_id"),
            ],
        ),
        ResolveAncestor(
            "account",
            [
                ResolveProp(NodePath.reported_name, "metadata", "account"),
                ResolveProp(NodePath.node_id, "refs", "account_id"),
            ],
        ),
        ResolveAncestor(
            "region",
            [
                ResolveProp(NodePath.reported_name, "metadata", "region"),
                ResolveProp(NodePath.node_id, "refs", "region_id"),
            ],
        ),
        ResolveAncestor(
            "zone",
            [
                ResolveProp(NodePath.reported_name, "metadata", "zone"),
                ResolveProp(NodePath.node_id, "refs", "zone_id"),
            ],
        ),
    ]

    resolved_ancestors = {
        kind: f"{prop.section}.{prop.name}"
        for kind, prop in {a.kind: a.resolves_id() for a in to_resolve}.items()
        if prop
    }
