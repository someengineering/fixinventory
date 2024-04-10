from __future__ import annotations

from abc import ABC
from typing import Dict, Any, Optional, Tuple

from attr import define

from fixcore.model.graph_access import Section
from fixcore.model.model import Model, ResolvedPropertyPath
from fixcore.model.resolve_in_graph import GraphResolver
from fixcore.query.model import Query
from fixcore.util import first

ancestor_merges = {
    f"ancestors.{p.to_path[1]}" for r in GraphResolver.to_resolve for p in r.resolve if p.to_path[0] == "ancestors"
}


@define
class QueryModel:
    query: Query
    model: Model
    env: Dict[str, Any] = {}

    def is_set(self, name: str) -> bool:
        if value := self.env.get(name):
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ["1", "true", "yes", "y"]
        return False

    def prop_kind(self, path: str) -> Tuple[ResolvedPropertyPath, Optional[str]]:  # prop, merge_name
        merge_name = first(lambda name: path.startswith(name + "."), self.query.merge_names) or first(
            lambda name: path.startswith(name + "."), ancestor_merges
        )
        # remove merge_name and section part (if existent) from the local_path
        lookup = Section.without_section(path[len(merge_name) + 1 :] if merge_name else path)  # noqa: E203
        resolved = self.model.property_by_path(lookup)
        return resolved, merge_name


@define(repr=True, eq=True)
class GraphUpdate(ABC):
    nodes_created: int = 0
    nodes_updated: int = 0
    nodes_deleted: int = 0
    edges_created: int = 0
    edges_updated: int = 0
    edges_deleted: int = 0

    def all_changes(self) -> int:
        return (
            self.nodes_created
            + self.nodes_updated
            + self.nodes_deleted
            + self.edges_created
            + self.edges_updated
            + self.edges_deleted
        )

    def __add__(self, other: GraphUpdate) -> GraphUpdate:
        return GraphUpdate(
            self.nodes_created + other.nodes_created,
            self.nodes_updated + other.nodes_updated,
            self.nodes_deleted + other.nodes_deleted,
            self.edges_created + other.edges_created,
            self.edges_updated + other.edges_updated,
            self.edges_deleted + other.edges_deleted,
        )
