from typing import List, Optional, AsyncIterator, cast, Tuple
from asyncio import Lock

import logging

from resotocore.db.db_access import DbAccess
from resotocore.db.graphdb import EventGraphDB
from resotocore.util import utc_str, UTC_Date_Format_short, utc
from resotocore.ids import GraphName, TaskDescriptorId
from resotocore.service import Service
from resotocore.util import check_graph_name, Periodic
from resotocore.types import Json
from resotocore.model.model import Kind
from resotocore.model.typed_model import from_js, to_js_str
from resotocore.model.graph_access import EdgeTypes
from resotocore.db.async_arangodb import AsyncCursor
from resotocore.config.core_config_handler import CoreConfigHandler
from resotocore.core_config import SnapshotsScheduleConfig, ResotoCoreSnapshotsConfigId
from resotocore.task import TaskHandler
from resotocore.task.task_description import Job, ExecuteCommand, TimeTrigger
from json import loads, dumps
from datetime import datetime, timedelta
from dateutil.parser import parse
from attrs import frozen
import re


log = logging.getLogger(__name__)


class GraphManager(Service):
    def __init__(
        self,
        db_access: DbAccess,
        default_snapshots_config: SnapshotsScheduleConfig,
        config_handler: CoreConfigHandler,
        task_handler: TaskHandler,
    ) -> None:
        self.db_access = db_access
        self.lock: Optional[Lock] = None
        self.task_handler = task_handler
        self.default_snapshots_config = default_snapshots_config
        self.config_handler = config_handler
        self.snapshot_cleanup_worker: Optional[Periodic] = None

    async def __setup_cleanup_old_snapshots_worker(self, snapshots_config: SnapshotsScheduleConfig) -> None:
        if self.snapshot_cleanup_worker:
            await self.snapshot_cleanup_worker.stop()

        self.snapshot_cleanup_worker = Periodic(
            "snapshot_cleanup_worker", lambda: self._clean_outdated_snapshots(snapshots_config), timedelta(seconds=60)
        )
        await self.snapshot_cleanup_worker.start()

    async def _clean_outdated_snapshots(self, snapshots_config: SnapshotsScheduleConfig) -> None:
        # get all existing snapshots
        existing_snapshots = await self.list("snapshot-.*")

        snapshots_to_keep: List[Tuple[str, int]] = []
        for label, schedule in snapshots_config.snapshots.items():
            regex = rf"snapshot-\w+-{label}-.*"
            snapshots_to_keep.append((regex, schedule.retain))

        # delete all snapshots that are outdated
        for regex, retain in snapshots_to_keep:
            snapshots = [snapshot for snapshot in existing_snapshots if re.match(regex, snapshot)]
            snapshots.sort(reverse=True)
            for snapshot in snapshots[retain:]:
                await self.delete(snapshot)

    async def _on_config_updated(self, config_id: str) -> None:
        if config_id == ResotoCoreSnapshotsConfigId:
            job_prefix = "resoto:snapshots:"
            # get the new config or use the default
            snapshots_config = SnapshotsScheduleConfig()
            try:
                new_config = await self.config_handler.config_handler.get_config(ResotoCoreSnapshotsConfigId)
                if new_config:
                    snapshots_config = from_js(new_config.config, SnapshotsScheduleConfig)
            except Exception as e:
                log.error(f"Can not parse snapshot schedule. Fall back to defaults. Reason: {e}", exc_info=e)

            # recreate the cleanup worker according to the new schedule
            await self.__setup_cleanup_old_snapshots_worker(snapshots_config)

            # cancel all existing snapshot jobs
            existing_jobs = [job for job in await self.task_handler.list_jobs() if job.id.startswith(job_prefix)]
            for job in existing_jobs:
                await self.task_handler.delete_job(job.id, force=True)

            # schedule new snapshot jobs for the current graph
            for label, schedule in snapshots_config.snapshots.items():
                job = Job(
                    uid=TaskDescriptorId(f"{job_prefix}{label}"),
                    command=ExecuteCommand(f"graph snapshot {label}"),
                    timeout=timedelta(minutes=5),
                    trigger=TimeTrigger(schedule.schedule),
                )

                await self.task_handler.add_job(job, force=True)

    async def start(self) -> None:
        self.lock = Lock()
        # initialize the snapshot schedule
        await self._on_config_updated(ResotoCoreSnapshotsConfigId)
        # subscribe to config updates to update the snapshot schedule
        self.config_handler.add_callback(self._on_config_updated)
        await self.__setup_cleanup_old_snapshots_worker(self.default_snapshots_config)

    async def stop(self) -> None:
        if self.snapshot_cleanup_worker:
            await self.snapshot_cleanup_worker.stop()
            self.snapshot_cleanup_worker = None

    async def list(self, pattern: Optional[str]) -> List[GraphName]:
        return [key for key in await self.db_access.list_graphs() if pattern is None or re.match(pattern, key)]

    async def snapshot_at(self, *, time: datetime, graph_name: GraphName) -> Optional[GraphName]:
        regex = rf"snapshot-{graph_name}-.*-(.+)"
        graphs = await self.list(regex)
        graphs_with_time = []
        for graph in graphs:
            match = re.match(regex, graph)
            if match:
                graphs_with_time.append((parse(match.group(1)), graph))

        graphs_with_time.sort(reverse=True, key=lambda x: x[0])
        # take the first graph that is older than the given time
        for graph_time, graph in graphs_with_time:
            if graph_time <= time:
                return graph

        # nothing found
        return None

    async def copy(
        self,
        source: GraphName,
        destination: GraphName,
        replace_existing: bool,
        validate_name: bool = True,
        to_snapshot: bool = False,
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
            return await self._copy_graph(source, destination, validate_name, to_snapshot)

    async def _copy_graph(
        self, source: GraphName, destination: GraphName, validate_name: bool = True, to_snapshot: bool = False
    ) -> GraphName:
        destination = GraphName(_compress_timestamps(destination))

        if validate_name:
            check_graph_name(destination)

        if not await self.db_access.db.has_graph(source):
            raise ValueError(f"Source graph {source} does not exist")

        source_db = self.db_access.get_graph_db(source, no_check=True)

        await source_db.copy_graph(destination, to_snapshot)

        source_model_db = await self.db_access.get_graph_model_db(source)
        destination_model_db = await self.db_access.get_graph_model_db(destination)

        model_kinds = [kind async for kind in source_model_db.all()]
        await destination_model_db.update_many(model_kinds)

        return destination

    async def snapshot(self, source: GraphName, label: str, timestamp: Optional[datetime] = None) -> GraphName:
        if not timestamp:
            timestamp = utc()

        if source.startswith("snapshot-"):
            raise ValueError("Can not snapshot a snapshot")

        time = utc_str(timestamp, date_format=UTC_Date_Format_short)
        check_graph_name(label)
        snapshot_name = GraphName(f"snapshot-{source}-{label}-{time}")
        return await self.copy(source, snapshot_name, replace_existing=False, validate_name=False, to_snapshot=True)

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

            metadata = from_js(
                loads(await stream.__anext__()), ExportMetadata  # pylint: disable=unnecessary-dunder-call
            )
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


def _compress_timestamps(value: str) -> str:
    # support for negative years was removed in order to not parse the dashes in front
    iso8601 = re.compile(
        r"([\+]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?"  # noqa: E501
    )

    # result string to be built
    result = ""
    # position in the source string
    source_pos = 0

    # find all timestamps in the source string
    for match in iso8601.finditer(value):
        # if there is a gap between the previous match and this one, copy the source string
        if match.start() > source_pos:
            result += value[source_pos : match.start()]

        # compact the timestamp
        timestamp = match.group(0)
        dt = parse(timestamp)
        compact_ts = utc_str(dt, UTC_Date_Format_short)
        result += compact_ts

        # update the pointer
        source_pos = match.end()

    # copy the rest of the source string
    if source_pos < len(value):
        result += value[source_pos:]

    return result
