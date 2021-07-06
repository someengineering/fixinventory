from abc import ABC
from typing import Optional, List, Union

from core.model.model import Model
from core.query.model import Query


class QueryModel(ABC):
    def __init__(self, query: Query, model: Model, query_section: str,
                 return_section: Optional[Union[str, List[str]]] = None):
        self.query = query
        self.model = model
        self.query_section = query_section
        self.return_section = return_section if return_section is not None else query_section


class GraphUpdate(ABC):
    def __init__(self, nodes_created=0, nodes_updates=0, nodes_deleted=0,
                 edges_created=0, edges_updated=0, edges_deleted=0):
        self.nodes_created = nodes_created
        self.nodes_updated = nodes_updates
        self.nodes_deleted = nodes_deleted
        self.edges_created = edges_created
        self.edges_updated = edges_updated
        self.edges_deleted = edges_deleted

    def all_changes(self) -> int:
        return self.nodes_created + self.nodes_updated + self.nodes_deleted + \
               self.edges_created + self.edges_updated + self.edges_deleted

    def __repr__(self):
        return f"[[{self.nodes_created},{self.nodes_updated}," \
               f"{self.nodes_deleted}],[{self.edges_created}," \
               f"{self.edges_updated},{self.edges_deleted}]]"

    def __eq__(self, other):
        if isinstance(other, GraphUpdate):
            return self.__dict__ == other.__dict__
