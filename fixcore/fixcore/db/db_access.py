import json
import logging
import re
from argparse import Namespace
from asyncio import Lock
from datetime import datetime, timezone, timedelta
from time import sleep
from typing import Dict, List, Tuple, Union, cast, Optional, AsyncIterator, Awaitable, Callable

from arango import ArangoServerError
from arango.client import ArangoClient
from arango.database import StandardDatabase
from attr import frozen
from dateutil.parser import parse
from requests.exceptions import RequestException

from fixcore.analytics import AnalyticsEventSender
from fixcore.async_extensions import run_async
from fixcore.core_config import CoreConfig, current_git_hash
from fixcore.db import SystemData
from fixcore.db.arangodb_extensions import ArangoHTTPClient
from fixcore.db.async_arangodb import AsyncArangoDB, AsyncCursor
from fixcore.db.configdb import config_entity_db, config_validation_entity_db
from fixcore.db.deferredouteredgedb import deferred_outer_edge_db
from fixcore.db.entitydb import EventEntityDb
from fixcore.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from fixcore.db.jobdb import job_db
from fixcore.db.modeldb import ModelDb, model_db
from fixcore.db.packagedb import app_package_entity_db
from fixcore.db.reportdb import report_check_db, benchmark_db
from fixcore.db.runningtaskdb import running_task_db
from fixcore.db.system_data_db import SystemDataDb
from fixcore.db.templatedb import template_entity_db
from fixcore.db.timeseriesdb import TimeSeriesDB
from fixcore.error import NoSuchGraph, RequiredDependencyMissingError
from fixcore.ids import GraphName
from fixcore.model.adjust_node import AdjustNode
from fixcore.model.graph_access import EdgeTypes
from fixcore.model.model import Kind
from fixcore.model.typed_model import from_js, to_js, to_js_str
from fixcore.service import Service
from fixcore.types import Json
from fixcore.util import (
    Periodic,
    utc,
    shutdown_process,
    uuid_str,
    check_graph_name,
    utc_str,
    UTC_Date_Format_short,
    set_value_in_path,
    async_noop,
)

log = logging.getLogger(__name__)

CurrentDatabaseVersion = 2


class DbAccess(Service):
    def __init__(
        self,
        arango_database: StandardDatabase,
        event_sender: AnalyticsEventSender,
        adjust_node: AdjustNode,
        config: CoreConfig,
        running_task_name: str = "running_tasks",
        job_name: str = "jobs",
        deferred_outer_edge_name: str = "deferred_outer_edges",
        config_entity: str = "configs",
        config_validation_entity: str = "config_validation",
        configs_model: str = "configs_model",
        template_entity: str = "templates",
        infra_app_packages: str = "infra_app_packages",
        time_series: str = "ts",
        report_checks: str = "report_checks",
        benchmarks: str = "report_benchmarks",
    ):
        super().__init__()
        self.event_sender = event_sender
        self.database = arango_database
        self.db = AsyncArangoDB(arango_database)
        self.adjust_node = adjust_node
        self.graph_model_dbs: Dict[GraphName, ModelDb] = {}
        self.system_data_db = SystemDataDb(self.db)
        self.running_task_db = running_task_db(self.db, running_task_name)
        self.deferred_outer_edge_db = deferred_outer_edge_db(self.db, deferred_outer_edge_name)
        self.job_db = job_db(self.db, job_name)
        self.config_entity_db = config_entity_db(self.db, config_entity)
        self.config_validation_entity_db = config_validation_entity_db(self.db, config_validation_entity)
        self.configs_model_db = model_db(self.db, configs_model)
        self.template_entity_db = template_entity_db(self.db, template_entity)
        self.package_entity_db = app_package_entity_db(self.db, infra_app_packages)
        self.report_check_db = report_check_db(self.db, report_checks)
        self.benchmark_db = benchmark_db(self.db, benchmarks)
        self.time_series_db = TimeSeriesDB(self.db, time_series, config)
        self.graph_dbs: Dict[str, GraphDB] = {}
        self.config = config
        self.cleaner = Periodic("outdated_updates_cleaner", self.check_outdated_updates, timedelta(seconds=60))

    async def start(self) -> None:
        await self.__migrate()
        await self.cleaner.start()

    async def stop(self) -> None:
        await self.cleaner.stop()

    async def __migrate(self) -> None:
        try:
            system_data = await self.system_data_db.system_data()
        except Exception:
            system_data = None
            if not await self.db.has_collection("system_data"):  # make sure the system data collection exists
                await self.db.create_collection("system_data")
        if system_data is None:  # in case no version is available, create a genesis version
            system_data = SystemData(uuid_str(), utc(), CurrentDatabaseVersion)
        git_hash = current_git_hash()
        if (
            system_data.db_version != CurrentDatabaseVersion
            or system_data.version is None
            or git_hash is None
            or git_hash != system_data.version
        ):
            # check if we need to run a migration
            if system_data.db_version < CurrentDatabaseVersion:
                log.info(f"Database migration required: db={system_data.db_version} -> latest={CurrentDatabaseVersion}")
                migrations: List[Callable[[], Awaitable[None]]] = [async_noop, self.__migrate_v1_to_v2]
                log.info(f"Migrate to database version {CurrentDatabaseVersion}")
                for version in range(system_data.db_version, CurrentDatabaseVersion):
                    log.info(f"Running migration {version} -> {version + 1}")
                    await migrations[version]()
                system_data.db_version = CurrentDatabaseVersion
                await self.system_data_db.update_system_data(system_data)

            # will be executed on every git change
            log.info(f"Git hash change detected. Update schema. {system_data.version} -> {git_hash}")
            await self.running_task_db.create_update_schema()
            await self.job_db.create_update_schema()
            await self.config_entity_db.create_update_schema()
            await self.config_validation_entity_db.create_update_schema()
            await self.configs_model_db.create_update_schema()
            await self.template_entity_db.create_update_schema()
            await self.deferred_outer_edge_db.create_update_schema()
            await self.package_entity_db.create_update_schema()
            await self.time_series_db.create_update_schema()
            await self.report_check_db.create_update_schema()
            await self.benchmark_db.create_update_schema()
            for graph in cast(List[Json], self.database.graphs()):
                graph_name = GraphName(graph["name"])
                # snapshot graphs do not need any schema migrations
                if graph_name.startswith("snapshot"):
                    continue
                log.info(f"Found graph: {graph_name}")
                db = self.get_graph_db(graph_name)
                await db.create_update_schema()
                em = await self.get_graph_model_db(graph_name)
                await em.create_update_schema()

            # update the system data version to the current git hash
            system_data.version = git_hash

            # update the system data version to not migrate the next time
            await self.system_data_db.update_system_data(system_data)

    async def __migrate_v1_to_v2(self) -> None:
        def migrate_config(old_id: str, old_root: str, config: Json) -> Json:
            cid = old_id.replace("resoto", "fix")
            new_root = old_root.replace("resoto", "fix")
            updated = config.copy()
            updated[new_root] = updated.pop(old_root)
            if cid == "fix.core":
                set_value_in_path("fix", [new_root, "cli", "default_graph"], updated)
            elif cid in ("fix.worker", "fix.metrics"):
                set_value_in_path("fix", [new_root, "graph"], updated)
            return dict(_key=cid, id=cid, config=updated)

        graph_names = {GraphName(graph["name"]) for graph in cast(List[Json], self.database.graphs())}
        resoto = GraphName("resoto")
        if resoto in graph_names:
            # Rename resoto to fix
            async with GraphOperations(self) as gm:
                log.info("Copy graph resoto -> fix")
                await gm.copy(resoto, GraphName("fix"), replace_existing=True)
                log.info("Delete graph resoto")
                await gm.delete(resoto)
            # get resoto configs
            configs = {
                et["id"]: et["config"]
                for et in await self.db.all(self.config_entity_db.collection_name)
                if et["id"].startswith("resoto")
            }
            # migrate the known configs
            updated = [
                migrate_config(cid, cfg_root, config_value)
                for cid, cfg_root in {
                    "resoto.core": "resotocore",
                    "resoto.worker": "resotoworker",
                    "resoto.metrics": "resotometrics",
                    "resoto.users": "resoto_users",
                    "resoto.core.commands": "custom_commands",
                    "resoto.core.snapshots": "snapshots",
                }.items()
                if (config_value := configs.get(cid))
            ]
            if updated:
                log.info(f"Insert the updated configs: {[et['id'] for et in updated]}")
                await self.db.insert_many(self.config_entity_db.collection_name, updated, overwrite=True)
            # delete all resoto configs
            log.info(f"Delete the following configs: {', '.join(configs.keys())}")
            await self.db.delete_many(self.config_entity_db.collection_name, [{"_key": et} for et in configs])

    def graph_model_name(self, graph_name: GraphName) -> str:
        return f"{graph_name}_model"

    async def create_graph(self, name: GraphName, validate_name: bool = True) -> GraphDB:
        if validate_name:
            check_graph_name(name)

        # create the graph in the database
        db = self.get_graph_db(name, no_check=True)
        await db.create_update_schema()
        # also create the related model database
        model = await self.get_graph_model_db(name)
        await model.create_update_schema()
        return db

    async def delete_graph(self, name: GraphName) -> None:
        def delete() -> None:
            db = self.database
            if db.has_graph(name):
                log.info(f"Delete graph: {name}")
                db.delete_view(f"search_{name}", ignore_missing=True)
                # delete arrangodb graph
                db.delete_graph(name, drop_collections=True, ignore_missing=True)
                # delete vertex collections just in case
                db.delete_collection(name, ignore_missing=True)
                # delete edge collections
                for edge_type in EdgeTypes.all:
                    db.delete_collection(f"{name}_{edge_type}", ignore_missing=True)
                # delete the rest
                db.delete_collection(f"{name}_in_progress", ignore_missing=True)
                db.delete_collection(f"{name}_node_history", ignore_missing=True)
                db.delete_collection(f"{name}_usage", ignore_missing=True)
                db.delete_collection(f"{name}_usage_metrics", ignore_missing=True)
                # remove all temp collection names
                for coll in cast(List[Json], db.collections()):
                    if coll["name"].startswith(f"{name}-temp_"):
                        db.delete_collection(coll["name"], ignore_missing=True)
                self.graph_dbs.pop(name, None)
                self.graph_model_dbs.pop(name, None)

        return await run_async(delete)

    async def delete_graph_model(self, graph_name: GraphName) -> None:
        await self.db.delete_collection(self.graph_model_name(graph_name), ignore_missing=True)
        self.graph_model_dbs.pop(graph_name, None)

    async def list_graphs(self) -> List[GraphName]:
        return [a["name"] for a in cast(List[Json], self.database.graphs()) if not a["name"].endswith("_hs")]

    def get_graph_db(self, name: GraphName, no_check: bool = False) -> GraphDB:
        if name in self.graph_dbs:
            return self.graph_dbs[name]
        else:
            if not no_check and not self.database.has_graph(name):
                raise NoSuchGraph(name)
            graph_db = ArangoGraphDB(self.db, name, self.adjust_node, self.config.graph_update)
            event_db = EventGraphDB(graph_db, self.event_sender)
            self.graph_dbs[name] = event_db
            return event_db

    async def get_graph_model_db(self, graph_name: GraphName) -> ModelDb:
        if db := self.graph_model_dbs.get(graph_name):
            return db
        else:
            model_name = self.graph_model_name(graph_name)
            db = EventEntityDb(model_db(self.db, model_name), self.event_sender, model_name)
            self.graph_model_dbs[graph_name] = db
            return db

    async def check_outdated_updates(self) -> None:
        now = datetime.now(timezone.utc)
        for db in self.graph_dbs.values():
            for update in await db.list_in_progress_updates():
                created = datetime.fromtimestamp(parse(update["created"]).timestamp(), timezone.utc)
                if (now - created) > self.config.graph_update.abort_after():
                    batch_id = update["id"]
                    log.warning(f"Given update is too old: {batch_id}. Will abort the update.")
                    await db.abort_update(batch_id)

    @classmethod
    def create_database(
        cls,
        *,
        server: str,
        username: str,
        password: str,
        database: str,
        root_password: str,
        request_timeout: int,
        secure_root: bool,
    ) -> None:
        log.info(f"Create new database {database} for user {username} on server {server}.")
        try:
            # try to access the system database with given credentials.
            http_client = ArangoHTTPClient(request_timeout, False)
            root_db = ArangoClient(hosts=server, http_client=http_client).db(password=root_password)
            root_db.echo()  # this call will fail if we are not allowed to access the system db
            user = username
            change = False
            if not root_db.has_user(user):
                log.info("Configured graph db user does not exist. Create it.")
                root_db.create_user(user, password, active=True)
                change = True
            if not root_db.has_database(database):
                log.info("Configured graph db database does not exist. Create it.")
                root_db.create_database(
                    database,
                    [{"username": user, "password": password, "active": True, "extra": {"generated": "fix"}}],
                )
                change = True
            if change and secure_root and root_password == "" and password != "" and password not in {"test"}:
                root_db.replace_user("root", password, True)
                log.info(
                    "Database is using an empty password. "
                    "Secure the root account with the provided user password. "
                    "Login to the Fix Inventory database via provided username and password. "
                    "Login to the System database via `root` and provided password!"
                )
            if not change:
                log.info("Not allowed to access database, while user and database exist. Wrong password?")
        except Exception as ex:
            log.error(
                "Database or user does not exist or does not have enough permissions. "
                f"Attempt to create user/database via default system account is not possible. Reason: {ex}. "
                "You can provide the password of the root user via --graphdb-root-password to setup "
                "a Fix Inventory user and database automatically."
            )

    # Only used during startup.
    # Note: this call uses sleep and will block the current executing thread!
    @classmethod
    def connect(
        cls, args: Namespace, timeout: timedelta, sleep_time: float = 5, verify: Union[str, bool, None] = None
    ) -> Tuple[bool, SystemData, StandardDatabase]:
        deadline = utc() + timeout

        def try_db(name: Optional[str] = None) -> StandardDatabase:
            db = cls.client(args, verify, name=name)
            db.echo()
            try:
                db_version = int(cast(str, db.required_db_version()))
            except Exception as ex:
                log.warning(f"Not able to retrieve version of arangodb. Reason: {ex}. Continue.")
            else:
                if db_version < 30802:
                    raise RequiredDependencyMissingError("Need arangodb in version 3.8.2 or later")
            return db

        def connect_db() -> StandardDatabase:
            try:
                return try_db()
            except ArangoServerError as ex:
                # Backward compatibility: if we cannot connect to the fix database, but the resoto database works.
                if args.graphdb_database == "fix" and ex.error_code in (11, 1228, 1703):
                    result = try_db("resoto")
                    args.graphdb_database = "resoto"
                    args.graphdb_username = "resoto"
                    return result
                else:
                    raise

        def system_data(db: StandardDatabase) -> Tuple[bool, SystemData]:
            def insert_system_data() -> SystemData:
                system = SystemData(uuid_str(), utc(), CurrentDatabaseVersion)
                log.info(f"Create new system data entry: {system}")
                db.insert_document("system_data", {"_key": "system", **to_js(system)}, overwrite=True)
                return system

            if not db.has_collection("system_data"):
                db.create_collection("system_data")

            sys_js: Optional[Json] = db.collection("system_data").get("system")  # type: ignore
            return (True, insert_system_data()) if not sys_js else (False, from_js(sys_js, SystemData))

        while True:
            try:
                db = connect_db()
                created, sys_data = system_data(db)
                return created, sys_data, db
            except ArangoServerError as ex:
                if utc() > deadline:
                    log.error("Can not connect to database. Giving up.")
                    shutdown_process(1)
                elif ex.error_code in (11, 1228, 1703):
                    # https://www.arangodb.com/docs/stable/appendix-error-codes.html
                    # This means we can reach the database, but are either not allowed to access it
                    # or the related user and or database could not be found.
                    # We assume the database does not exist and try to create it.
                    cls.create_database(
                        server=args.graphdb_server,
                        username=args.graphdb_username,
                        password=args.graphdb_password,
                        database=args.graphdb_database,
                        root_password=args.graphdb_root_password,
                        request_timeout=args.graphdb_request_timeout,
                        secure_root=not args.graphdb_bootstrap_do_not_secure,
                    )
                else:
                    log.warning(f"Problem accessing the graph database: {ex}. Trying again in 5 seconds.")
                # Retry directly after the first attempt
                sleep(sleep_time)
            except (RequestException, ConnectionError) as ex:
                log.warning(f"Can not access database. Trying again in 5 seconds: {ex}")
                sleep(sleep_time)

    @staticmethod
    def client(
        args: Namespace, verify: Union[bool, str, None] = None, *, name: Optional[str] = None
    ) -> StandardDatabase:
        if args.graphdb_type not in "arangodb":
            log.fatal(f"Unknown Graph DB type {args.graphdb_type}")
            shutdown_process(1)

        http_client = ArangoHTTPClient(args.graphdb_request_timeout, verify=verify)
        client = ArangoClient(hosts=args.graphdb_server, http_client=http_client)
        return client.db(
            name or args.graphdb_database, username=name or args.graphdb_username, password=args.graphdb_password
        )


class GraphOperations(Service):
    def __init__(
        self,
        db_access: DbAccess,
    ) -> None:
        super().__init__()
        self.db_access = db_access
        self.lock: Optional[Lock] = None

    async def start(self) -> None:
        self.lock = Lock()

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
        await destination_model_db.create_update_schema()

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

            # structure of the export file:
            # 1. metadata
            yield to_js_str(metadata)

            # 2. model collection
            cursor = AsyncCursor(await tx.all(model_collection), query=model_collection)
            async for doc in cursor:
                yield json.dumps(doc)

            # 3. vertex collection
            cursor = AsyncCursor(await tx.all(vertex_collection), query=vertex_collection)
            async for doc in cursor:
                yield json.dumps(doc)

            # 4. default edge collection
            cursor = AsyncCursor(await tx.all(default_edge_collection), query=default_edge_collection)
            async for doc in cursor:
                yield json.dumps(doc)

            # 5. delete edge collection
            cursor = AsyncCursor(await tx.all(delete_edge_collection), query=delete_edge_collection)
            async for doc in cursor:
                yield json.dumps(doc)

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
                json.loads(await stream.__anext__()), ExportMetadata  # pylint: disable=unnecessary-dunder-call
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
                    kinds.append(json.loads(doc))

                    # stop if we have reached the end of model
                    if position == metadata.model_collection_size - 1:
                        break
                    position += 1

                graph_model_db = await self.db_access.get_graph_model_db(graph_name)
                await graph_model_db.create_update_schema()
                await graph_model_db.update_many(from_js(kinds, List[Kind]))

            # import the data into the temp graph
            async def import_buffered(data: AsyncIterator[str], doc_num: int, collection: str) -> None:
                if doc_num == 0:
                    return
                position = 0
                buffer = []
                async for doc in data:
                    # collect a batch
                    buffer.append(json.loads(doc))
                    # insert the batch
                    if len(buffer) == 10000:
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
