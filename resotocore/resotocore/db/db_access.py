import logging
from abc import ABC
from argparse import Namespace
from datetime import datetime, timezone, timedelta
from time import sleep
from typing import Dict, List, Tuple, Union, cast, Optional, AsyncIterator
from jsons import dumps, loads
from attrs import frozen

from arango import ArangoServerError
from arango.client import ArangoClient
from arango.database import StandardDatabase
from dateutil.parser import parse
from requests.exceptions import RequestException


from resotocore.analytics import AnalyticsEventSender
from resotocore.async_extensions import run_async
from resotocore.core_config import CoreConfig
from resotocore.db import SystemData
from resotocore.db.arangodb_extensions import ArangoHTTPClient
from resotocore.db.async_arangodb import AsyncArangoDB, AsyncCursor
from resotocore.db.configdb import config_entity_db, config_validation_entity_db
from resotocore.db.entitydb import EventEntityDb
from resotocore.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from resotocore.db.jobdb import job_db
from resotocore.db.modeldb import ModelDb, model_db
from resotocore.db.deferred_edge_db import pending_deferred_edge_db
from resotocore.db.runningtaskdb import running_task_db
from resotocore.db.subscriberdb import subscriber_db
from resotocore.db.templatedb import template_entity_db
from resotocore.db.packagedb import app_package_entity_db
from resotocore.error import NoSuchGraph, RequiredDependencyMissingError
from resotocore.model.adjust_node import AdjustNode
from resotocore.model.typed_model import from_js, to_js
from resotocore.model.graph_access import EdgeTypes
from resotocore.model.model import Kind
from resotocore.types import Json
from resotocore.ids import GraphName
from resotocore.util import Periodic, utc, shutdown_process, uuid_str, check_graph_name

log = logging.getLogger(__name__)


class DbAccess(ABC):
    def __init__(
        self,
        arango_database: StandardDatabase,
        event_sender: AnalyticsEventSender,
        adjust_node: AdjustNode,
        config: CoreConfig,
        model_name: str = "model",
        subscriber_name: str = "subscribers",
        running_task_name: str = "running_tasks",
        job_name: str = "jobs",
        deferred_edge_name: str = "deferred_outer_edges",
        config_entity: str = "configs",
        config_validation_entity: str = "config_validation",
        configs_model: str = "configs_model",
        template_entity: str = "templates",
        infra_app_packages: str = "infra_app_packages",
    ):
        self.event_sender = event_sender
        self.database = arango_database
        self.db = AsyncArangoDB(arango_database)
        self.adjust_node = adjust_node
        self.model_db = EventEntityDb(model_db(self.db, model_name), event_sender, model_name)
        self.graph_model_dbs: Dict[GraphName, ModelDb] = {}
        self.subscribers_db = EventEntityDb(subscriber_db(self.db, subscriber_name), event_sender, subscriber_name)
        self.running_task_db = running_task_db(self.db, running_task_name)
        self.pending_deferred_edge_db = pending_deferred_edge_db(self.db, deferred_edge_name)
        self.job_db = job_db(self.db, job_name)
        self.config_entity_db = config_entity_db(self.db, config_entity)
        self.config_validation_entity_db = config_validation_entity_db(self.db, config_validation_entity)
        self.configs_model_db = model_db(self.db, configs_model)
        self.template_entity_db = template_entity_db(self.db, template_entity)
        self.package_entity_db = app_package_entity_db(self.db, infra_app_packages)
        self.graph_dbs: Dict[str, GraphDB] = {}
        self.config = config
        self.cleaner = Periodic("outdated_updates_cleaner", self.check_outdated_updates, timedelta(seconds=60))

    async def start(self) -> None:
        await self.model_db.create_update_schema()
        await self.subscribers_db.create_update_schema()
        await self.running_task_db.create_update_schema()
        await self.job_db.create_update_schema()
        await self.config_entity_db.create_update_schema()
        await self.config_validation_entity_db.create_update_schema()
        await self.configs_model_db.create_update_schema()
        await self.template_entity_db.create_update_schema()
        await self.pending_deferred_edge_db.create_update_schema()
        await self.package_entity_db.create_update_schema()
        for graph in cast(List[Json], self.database.graphs()):
            graph_name = GraphName(graph["name"])
            log.info(f"Found graph: {graph_name}")
            db = self.get_graph_db(graph_name)
            await db.create_update_schema()
            await self.get_graph_model_db(graph_name)
        await self.cleaner.start()

    async def stop(self) -> None:
        await self.cleaner.stop()

    def graph_model_name(self, graph_name: GraphName) -> str:
        return f"{graph_name}_model"

    async def create_graph(self, name: GraphName, validate_name: bool = True) -> GraphDB:
        if validate_name:
            check_graph_name(name)

        db = self.get_graph_db(name, no_check=True)
        await db.create_update_schema()
        return db

    async def copy_graph(self, source: GraphName, destination: GraphName, validate_name: bool) -> GraphName:
        """NOT THREAD SAFE! Be sure to use locks when calling this method."""
        if validate_name:
            check_graph_name(destination)

        if not await self.db.has_graph(source):
            raise ValueError(f"Source graph {source} does not exist")

        source_db = self.get_graph_db(source, no_check=True)

        await source_db.copy_graph(destination)

        source_model_db = await self.get_graph_model_db(source)
        destination_model_db = await self.get_graph_model_db(destination)

        model_kinds = [kind async for kind in source_model_db.all()]
        await destination_model_db.update_many(model_kinds)

        return destination

    async def delete_graph(self, name: GraphName) -> None:
        def delete(name: GraphName) -> None:
            db = self.database
            if db.has_graph(name):
                # delete arrangodb graph
                db.delete_graph(name, drop_collections=True, ignore_missing=True)
                # delete vertex collections just in case
                db.delete_collection(name, ignore_missing=True)
                # delete edge collections
                for edge_type in EdgeTypes.all:
                    db.delete_collection(f"{name}_{edge_type}", ignore_missing=True)
                # delete the rest
                db.delete_collection(f"{name}_in_progress", ignore_missing=True)
                db.delete_view(f"search_{name}", ignore_missing=True)
                # remove all temp collection names
                for coll in cast(List[Json], db.collections()):
                    if coll["name"].startswith(f"{name}_temp_"):
                        db.delete_collection(coll["name"], ignore_missing=True)
                self.graph_dbs.pop(name, None)

        return await run_async(delete, name)

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

    async def export_graph(self, graph_name: GraphName) -> AsyncIterator[str]:
        """
        Export the graph as a newline-separated json object stream.
        """
        if not await self.db.has_graph(graph_name):
            raise NoSuchGraph(graph_name)

        graph = cast(EventGraphDB, self.get_graph_db(graph_name)).real
        vertex_collection = graph_name
        default_edge_collection = graph.edge_collection(EdgeTypes.default)
        delete_edge_collection = graph.edge_collection(EdgeTypes.delete)
        model_collection = self.graph_model_name(graph_name)

        if not await self.db.has_collection(vertex_collection):
            model_collection = "model"

        async with self.db.begin_transaction(
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
            yield dumps(metadata)

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

    async def import_graph(self, graph_name: GraphName, data: AsyncIterator[str]) -> None:
        if await self.db.has_graph(graph_name):
            raise ValueError(f"Graph {graph_name} already exists")

        # temp graph to load the dump
        temp_graph = cast(EventGraphDB, await self.create_graph(GraphName(graph_name + "_temp"))).real

        metadata = from_js(loads(await data.__anext__()), ExportMetadata)
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

            graph_model_db = await self.get_graph_model_db(graph_name)
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
                    await self.db.insert_many(collection, buffer)
                    buffer = []

                if position == doc_num - 1:
                    break
                position += 1

            if len(buffer) > 0:
                await self.db.insert_many(collection, buffer)

        # step 1: import the graph model and the graph data into temporary collections
        await import_graph_model(data)
        await import_buffered(data, metadata.vertex_collection_size, temp_graph.vertex_name)
        await import_buffered(
            data, metadata.default_edge_collection_size, temp_graph.edge_collection(EdgeTypes.default)
        )
        await import_buffered(data, metadata.delete_edge_collection_size, temp_graph.edge_collection(EdgeTypes.delete))

        # step 2: move the temporary graph collection to the final collection
        # we're using the copy to do an atomic rename and rewrite the edge references
        await self.copy_graph(temp_graph.vertex_name, graph_name, validate_name=False)

        # step 3: delete the temporary graph
        await self.delete_graph(temp_graph.name)

    def get_model_db(self) -> ModelDb:
        return self.model_db

    async def get_graph_model_db(self, graph_name: GraphName) -> ModelDb:
        if db := self.graph_model_dbs.get(graph_name):
            return db
        else:
            model_name = self.graph_model_name(graph_name)
            db = EventEntityDb(model_db(self.db, model_name), self.event_sender, model_name)
            await db.create_update_schema()
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

    # Only used during startup.
    # Note: this call uses sleep and will block the current executing thread!
    @classmethod
    def connect(
        cls, args: Namespace, timeout: timedelta, sleep_time: float = 5, verify: Union[str, bool, None] = None
    ) -> Tuple[bool, SystemData, StandardDatabase]:
        deadline = utc() + timeout
        db = cls.client(args, verify)

        def create_database() -> None:
            try:
                # try to access the system database with default credentials.
                # this only works if arango has been started with default settings.
                http_client = ArangoHTTPClient(args.graphdb_request_timeout, not args.graphdb_no_ssl_verify)
                root_pw = args.graphdb_root_password
                secure_root = not args.graphdb_bootstrap_do_not_secure
                root_db = ArangoClient(hosts=args.graphdb_server, http_client=http_client).db(password=root_pw)
                root_db.echo()  # this call will fail, if we are not allowed to access the system db
                user = args.graphdb_username
                passwd = args.graphdb_password
                database = args.graphdb_database
                change = False
                if not root_db.has_user(user):
                    log.info("Configured graph db user does not exist. Create it.")
                    root_db.create_user(user, passwd, active=True)
                    change = True
                if not root_db.has_database(database):
                    log.info("Configured graph db database does not exist. Create it.")
                    root_db.create_database(
                        database,
                        [{"username": user, "password": passwd, "active": True, "extra": {"generated": "resoto"}}],
                    )
                    change = True
                if change and secure_root and root_pw == "" and passwd != "" and passwd not in {"test"}:
                    root_db.replace_user("root", passwd, True)
                    log.info(
                        "Database is using an empty password. "
                        "Secure the root account with the provided user password. "
                        "Login to the Resoto database via provided username and password. "
                        "Login to the System database via `root` and provided password!"
                    )
                if not change:
                    log.info("Not allowed to access database, while user and database exist. Wrong password?")
            except Exception as ex:
                log.error(
                    "Database or user does not exist or does not have enough permissions. "
                    f"Attempt to create user/database via default system account is not possible. Reason: {ex}. "
                    "You can provide the password of the root user via --graphdb-root-password to setup "
                    "a Resoto user and database automatically."
                )

        def system_data() -> Tuple[bool, SystemData]:
            def insert_system_data() -> SystemData:
                system = SystemData(uuid_str(), utc(), 1)
                log.info(f"Create new system data entry: {system}")
                db.insert_document("system_data", {"_key": "system", **to_js(system)}, overwrite=True)
                return system

            if not db.has_collection("system_data"):
                db.create_collection("system_data")

            sys_js: Optional[Json] = db.collection("system_data").get("system")  # type: ignore
            return (True, insert_system_data()) if not sys_js else (False, from_js(sys_js, SystemData))

        while True:
            try:
                db.echo()
                try:
                    db_version = int(cast(str, db.required_db_version()))
                except Exception as ex:
                    log.warning(f"Not able to retrieve version of arangodb. Reason: {ex}. Continue.")
                else:
                    if db_version < 30802:
                        raise RequiredDependencyMissingError("Need arangodb in version 3.8.2 or later")

                created, sys_data = system_data()
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
                    create_database()
                else:
                    log.warning(f"Problem accessing the graph database: {ex}. Trying again in 5 seconds.")
                # Retry directly after the first attempt
                sleep(sleep_time)
            except (RequestException, ConnectionError) as ex:
                log.warning(f"Can not access database. Trying again in 5 seconds: {ex}")
                sleep(sleep_time)

    @staticmethod
    def client(args: Namespace, verify: Union[bool, str, None] = None) -> StandardDatabase:
        if args.graphdb_type not in "arangodb":
            log.fatal(f"Unknown Graph DB type {args.graphdb_type}")
            shutdown_process(1)

        http_client = ArangoHTTPClient(args.graphdb_request_timeout, verify=verify)
        client = ArangoClient(hosts=args.graphdb_server, http_client=http_client)
        return client.db(args.graphdb_database, username=args.graphdb_username, password=args.graphdb_password)


@frozen
class ExportMetadata:
    serializer_version: str
    created_at: str
    model_collection_size: int
    vertex_collection_size: int
    default_edge_collection_size: int
    delete_edge_collection_size: int
