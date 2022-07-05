from attrs import define
from datetime import datetime
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import ArangoEntityDb
from resotocore.model.graph_access import DeferredEdge
from resotocore.ids import TaskId
from typing import List
import logging


@define
class PendingDeferredEdges:
    task_id: TaskId
    created_at: datetime  # update the corresponding TTL index when changing this name
    graph: str
    edges: List[DeferredEdge]


TWO_HOURS = 7200


log = logging.getLogger(__name__)


class PendingDeferredEdgeDb(ArangoEntityDb[TaskId, PendingDeferredEdges]):
    async def create_update_schema(self) -> None:
        await super().create_update_schema()
        ttl_index_name = "deferred_edges_expiration_index"
        collection = self.db.collection(self.collection_name)
        if ttl_index_name not in {idx["name"] for idx in collection.indexes()}:
            log.info(f"Add index {ttl_index_name} on {collection.name}")
            collection.add_ttl_index(["created_at"], TWO_HOURS, "deferred_edges_expiration_index")


def pending_deferred_edge_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[TaskId, PendingDeferredEdges]:
    return PendingDeferredEdgeDb(db, collection, PendingDeferredEdges, lambda k: k.task_id)
