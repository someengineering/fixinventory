from typing import List, Optional, AsyncIterator
from asyncio import Lock

from resotocore.db.db_access import DbAccess
from resotocore.util import utc_str
from resotocore.ids import GraphName
from resotocore.web.service import Service
import re


class GraphManager(Service):
    def __init__(self, db_access: DbAccess) -> None:
        self.db_access = db_access
        self.lock: Optional[Lock] = None

    async def start(self) -> None:
        self.lock = Lock()

    async def list(self, pattern: Optional[str]) -> List[GraphName]:
        return [key for key in await self.db_access.list_graphs() if pattern is None or re.match(pattern, key)]

    async def copy(self, source: GraphName, destination: GraphName, ignore_existing: bool) -> GraphName:
        if not self.lock:
            raise RuntimeError("GraphManager has not been started")

        async with self.lock:
            if not await self.db_access.db.has_graph(source):
                raise ValueError(f"Source graph {source} does not exist")

            if await self.db_access.db.has_graph(destination):
                if ignore_existing:
                    await self.delete(destination)
                else:
                    raise ValueError(f"Destination graph {destination} already exists")

            source_graph = self.db_access.get_graph_db(name=source)

            await source_graph.copy_graph(destination)

            source_model_db = await self.db_access.get_graph_model_db(source)
            destination_model_db = await self.db_access.get_graph_model_db(destination)

            model_kinds = [kind async for kind in source_model_db.all()]
            await destination_model_db.update_many(model_kinds)
            return destination

    async def snapshot(self, source: GraphName, label: str) -> GraphName:
        time = utc_str().replace(":", "-")
        snapshot_name = GraphName(f"snapshot-{source}-{label}-{time}")
        return await self.copy(source, snapshot_name, ignore_existing=False)

    async def delete(self, source: GraphName) -> None:
        await self.db_access.delete_graph(source)
        await self.db_access.delete_graph_model(source)

    async def dump(self, source: GraphName) -> AsyncIterator[bytes]:
        raise NotImplementedError()

    def load(self, stream: AsyncIterator[bytes]) -> None:
        raise NotImplementedError()
