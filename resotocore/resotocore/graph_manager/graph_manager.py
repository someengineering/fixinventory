from typing import List, Optional, AsyncIterator, cast
from asyncio import Lock

from resotocore.db.db_access import DbAccess
from resotocore.db.graphdb import EventGraphDB
from resotocore.util import utc_str
from resotocore.ids import GraphName
from resotocore.web.service import Service
from resotocore.util import check_graph_name
from resotocore.types import Json
from resotocore.model.model import Kind
from resotocore.model.typed_model import from_js, to_js_str
from resotocore.model.graph_access import EdgeTypes
from resotocore.db.async_arangodb import AsyncCursor
from json import loads, dumps
from datetime import datetime
from attrs import frozen
import re


class GraphManager(Service):
    def __init__(self, db_access: DbAccess) -> None:
        self.db_access = db_access
        self.lock: Optional[Lock] = None

    async def start(self) -> None:
        self.lock = Lock()

    async def list(self, pattern: Optional[str]) -> List[GraphName]:
        return [key for key in await self.db_access.list_graphs() if pattern is None or re.match(pattern, key)]

    async def copy(
        self, source: GraphName, destination: GraphName, replace_existing: bool, validate_name: bool = True
    ) -> GraphName:
        if not self.lock:
            raise RuntimeError("GraphManager has not been started")

        async with self.lock:
            if not await self.db_access.db.has_graph(source):
                raise ValueError(f"Source graph {source} does not exist")

            if await self.db_access.db.has_graph(destination):
                if replace_existing:
                    await self.delete(destination)
                else:
                    raise ValueError(f"Destination graph {destination} already exists")
            return await self._copy_graph(source, destination, validate_name)

    async def _copy_graph(self, source: GraphName, destination: GraphName, validate_name: bool = True) -> GraphName:
        if validate_name:
            check_graph_name(destination)

        if not await self.db_access.db.has_graph(source):
            raise ValueError(f"Source graph {source} does not exist")

        source_db = self.db_access.get_graph_db(source, no_check=True)

        await source_db.copy_graph(destination)

        source_model_db = await self.db_access.get_graph_model_db(source)
        destination_model_db = await self.db_access.get_graph_model_db(destination)

        model_kinds = [kind async for kind in source_model_db.all()]
        await destination_model_db.update_many(model_kinds)

        return destination

    async def snapshot(self, source: GraphName, label: str) -> GraphName:
        time = utc_str().replace(":", "_")
        check_graph_name(label)
        snapshot_name = GraphName(f"snapshot-{source}-{label}-{time}")
        return await self.copy(source, snapshot_name, replace_existing=False, validate_name=False)

    async def delete(self, graph_name: GraphName) -> None:
        await self.db_access.delete_graph(graph_name)
        await self.db_access.delete_graph_model(graph_name)

    async def export_graph(self, graph_name: GraphName) -> AsyncIterator[str]:
        if not await self.db_access.db.has_graph(graph_name):
            raise ValueError(f"Graph {graph_name} does not exist")

        graph = cast(EventGraphDB, self.db_access.get_graph_db(graph_name)).real
        vertex_collection = graph_name
        default_edge_collection = graph.edge_collection(EdgeTypes.default)
        delete_edge_collection = graph.edge_collection(EdgeTypes.delete)
        model_collection = self.db_access.graph_model_name(graph_name)

        if not await self.db_access.db.has_collection(vertex_collection):
            model_collection = "model"

        async with self.db_access.db.begin_transaction(
            read=[vertex_collection, default_edge_collection, delete_edge_collection, model_collection]
        ) as tx:
            # Snapshot isolation ensures that the counts are consistent with the cursor data
            metadata = ExportMetadata(
                serializer_version="0.1.0",
                created_at=datetime.now().isoformat(),
                model_collection_size=await tx.count(model_collection),
                vertex_collection_size=await tx.count(vertex_collection),
                default_edge_collection_size=await tx.count(default_edge_collection),
                delete_edge_collection_size=await tx.count(delete_edge_collection),
            )

            # sturcture of the export file:
            # 1. metadata
            yield to_js_str(metadata)

            # 2. model collection
            cursor = AsyncCursor(await tx.all(model_collection), None)
            async for doc in cursor:
                yield dumps(doc)

            # 3. vertex collection
            cursor = AsyncCursor(await tx.all(vertex_collection), None)
            async for doc in cursor:
                yield dumps(doc)

            # 4. default edge collection
            cursor = AsyncCursor(await tx.all(default_edge_collection), None)
            async for doc in cursor:
                yield dumps(doc)

            # 5. delete edge collection
            cursor = AsyncCursor(await tx.all(delete_edge_collection), None)
            async for doc in cursor:
                yield dumps(doc)

    async def import_graph(self, graph_name: GraphName, stream: AsyncIterator[str], replace_existing: bool) -> None:
        if not self.lock:
            raise RuntimeError("GraphManager has not been started")

        async with self.lock:
            if await self.db_access.db.has_graph(graph_name):
                if replace_existing:
                    await self.delete(graph_name)
                else:
                    raise ValueError(f"Graph {graph_name} already exists")

            if await self.db_access.db.has_graph(graph_name):
                raise ValueError(f"Graph {graph_name} already exists")

            # temp graph to load the dump
            temp_graph = cast(
                EventGraphDB, await self.db_access.create_graph(GraphName(graph_name + "-temp"), validate_name=False)
            ).real

            metadata = from_js(loads(await stream.__anext__()), ExportMetadata)
            # check the serializer version, in the future we might need to support multiple versions
            if metadata.serializer_version != "0.1.0":
                raise ValueError(f"Unsupported dump version {metadata.serializer_version}")

            # import the model directly to the target graph model collection
            async def import_graph_model(data: AsyncIterator[str]) -> None:
                if metadata.model_collection_size == 0:
                    return

                position = 0
                kinds: List[Json] = []
                async for doc in data:
                    kinds.append(loads(doc))

                    # stop if we have reached the end of model
                    if position == metadata.model_collection_size - 1:
                        break
                    position += 1

                graph_model_db = await self.db_access.get_graph_model_db(graph_name)
                await graph_model_db.update_many(from_js(kinds, List[Kind]))

            # import the data into the temp graph
            async def import_buffered(data: AsyncIterator[str], doc_num: int, collection: str) -> None:
                if doc_num == 0:
                    return
                position = 0
                buffer = []
                async for doc in data:
                    # collect a batch
                    buffer.append(loads(doc))
                    # insert the batch
                    if len(buffer) == 1000:
                        await self.db_access.db.insert_many(collection, buffer)
                        buffer = []

                    if position == doc_num - 1:
                        break
                    position += 1

                if len(buffer) > 0:
                    await self.db_access.db.insert_many(collection, buffer)

            # step 1: import the graph model and the graph data into temporary collections
            await import_graph_model(stream)
            await import_buffered(stream, metadata.vertex_collection_size, temp_graph.vertex_name)
            await import_buffered(
                stream, metadata.default_edge_collection_size, temp_graph.edge_collection(EdgeTypes.default)
            )
            await import_buffered(
                stream, metadata.delete_edge_collection_size, temp_graph.edge_collection(EdgeTypes.delete)
            )

            # step 2: move the temporary graph collection to the final collection
            # we're using the copy to do an atomic rename and rewrite the edge references
            await self._copy_graph(temp_graph.vertex_name, graph_name, validate_name=False)

            # step 3: delete the temporary graph
            await self.db_access.delete_graph(temp_graph.name)


@frozen
class ExportMetadata:
    serializer_version: str
    created_at: str
    model_collection_size: int
    vertex_collection_size: int
    default_edge_collection_size: int
    delete_edge_collection_size: int
