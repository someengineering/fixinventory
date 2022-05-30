from dataclasses import dataclass
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.model.graph_access import DeferredEdge
from resotocore.ids import TaskId
from typing import List


@dataclass
class PendingDeferredEdges:
    task_id: TaskId
    graph: str
    edges: List[DeferredEdge]


OuterEdgeDb = EntityDb[TaskId, PendingDeferredEdges]


def outer_edge_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[TaskId, PendingDeferredEdges]:
    return ArangoEntityDb(db, collection, PendingDeferredEdges, lambda k: k.task_id)
