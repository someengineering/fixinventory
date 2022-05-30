from dataclasses import dataclass
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.model.graph_access import EdgeKey
from resotocore.ids import TaskId
from typing import List


@dataclass
class PendingOuterEdges:
    task_id: TaskId
    graph: str
    edge_keys: List[EdgeKey]


OuterEdgeDb = EntityDb[TaskId, PendingOuterEdges]


def outer_edge_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[TaskId, PendingOuterEdges]:
    return ArangoEntityDb(db, collection, PendingOuterEdges, lambda k: k.task_id)
