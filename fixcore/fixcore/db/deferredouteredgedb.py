from attrs import define
from datetime import datetime
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import ArangoEntityDb
from fixcore.model.graph_access import DeferredEdge
from fixcore.ids import TaskId
from typing import List, cast
import logging

from fixcore.model.typed_model import from_js
from fixcore.types import Json
from fixcore.ids import GraphName


@define
class DeferredOuterEdges:
    id: str
    change_id: str
    task_id: TaskId
    created_at: datetime  # update the corresponding TTL index when changing this name
    graph: GraphName
    edges: List[DeferredEdge]


TWO_HOURS = 7200


log = logging.getLogger(__name__)


class DeferredOuterEdgeDb(ArangoEntityDb[str, DeferredOuterEdges]):
    async def all_for_task(self, task_id: TaskId) -> List[DeferredOuterEdges]:
        result = []
        async with await self.db.aql_cursor(
            f"FOR e IN `{self.collection_name}` FILTER e.task_id == @task_id RETURN e", bind_vars={"task_id": task_id}
        ) as cursor:
            async for doc in cursor:
                edges = from_js(doc, DeferredOuterEdges)
                result.append(edges)
        return result

    async def delete_for_task(self, task_id: TaskId) -> None:
        async with await self.db.aql_cursor(
            f"FOR e IN `{self.collection_name}` FILTER e.task_id == @task_id REMOVE e IN `{self.collection_name}`",
            bind_vars={"task_id": task_id},
        ) as cursor:
            async for _ in cursor:
                pass

    async def create_update_schema(self) -> None:
        await super().create_update_schema()
        ttl_index_name = "deferred_edges_expiration_index"
        collection = self.db.collection(self.collection_name)
        if ttl_index_name not in {idx["name"] for idx in cast(List[Json], collection.indexes())}:
            log.info(f"Add index {ttl_index_name} on {collection.name}")
            collection.add_ttl_index(["created_at"], TWO_HOURS, "deferred_edges_expiration_index")


def deferred_outer_edge_db(db: AsyncArangoDB, collection: str) -> DeferredOuterEdgeDb:
    return DeferredOuterEdgeDb(db, collection, DeferredOuterEdges, lambda k: k.id)
