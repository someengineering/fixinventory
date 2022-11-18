from __future__ import annotations
from abc import ABC
from typing import Any

from resotocore.model.model import Model
from resotocore.query.model import Query


class QueryModel(ABC):
    def __init__(self, query: Query, model: Model):
        self.query = query
        self.model = model


class GraphUpdate(ABC):
    def __init__(
        self,
        nodes_created: int = 0,
        nodes_updates: int = 0,
        nodes_deleted: int = 0,
        edges_created: int = 0,
        edges_updated: int = 0,
        edges_deleted: int = 0,
    ):
        self.nodes_created = nodes_created
        self.nodes_updated = nodes_updates
        self.nodes_deleted = nodes_deleted
        self.edges_created = edges_created
        self.edges_updated = edges_updated
        self.edges_deleted = edges_deleted

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

    def __repr__(self) -> str:
        return (
            f"[[{self.nodes_created},{self.nodes_updated},"
            f"{self.nodes_deleted}],[{self.edges_created},"
            f"{self.edges_updated},{self.edges_deleted}]]"
        )

    def __str__(self) -> str:
        return (
            f"GraphUpdate(nodes_created={self.nodes_created}, nodes_updated={self.nodes_updated}, "
            f"nodes_deleted={self.nodes_deleted}, edges_created={self.edges_created}, "
            f"edges_updated={self.edges_updated}, edges_deleted={self.edges_deleted})"
        )

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, GraphUpdate) else False
