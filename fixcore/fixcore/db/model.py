from __future__ import annotations

from abc import ABC
from typing import Dict, Any

from attr import define

from fixcore.model.model import Model
from fixcore.query.model import Query


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
