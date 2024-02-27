import logging
from argparse import Namespace
from datetime import datetime, timezone, timedelta
from time import sleep
from typing import Dict, List, Tuple, Union, cast, Optional

from arango import ArangoServerError
from arango.client import ArangoClient
from arango.database import StandardDatabase
from dateutil.parser import parse
from requests.exceptions import RequestException

from fixcore.analytics import AnalyticsEventSender
from fixcore.async_extensions import run_async
from fixcore.core_config import CoreConfig, current_git_hash
from fixcore.db import SystemData
from fixcore.db.arangodb_extensions import ArangoHTTPClient
from fixcore.db.async_arangodb import AsyncArangoDB
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
from fixcore.model.typed_model import from_js, to_js
from fixcore.service import Service
from fixcore.types import Json
from fixcore.util import Periodic, utc, shutdown_process, uuid_str, check_graph_name

log = logging.getLogger(__name__)


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
            system_data = SystemData(uuid_str(), utc(), 1)
        git_hash = current_git_hash()
        if system_data.version is None or git_hash is None or git_hash != system_data.version:
            log.info(f"Version change detected. Running migrations. {system_data.version} -> {git_hash}")
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

                # snapshot graphs do not need any schema migrations,
                # we can skip them
                if str(graph_name).startswith("snapshot"):
                    continue

                log.info(f"Found graph: {graph_name}")
                db = self.get_graph_db(graph_name)
                await db.create_update_schema()
                em = await self.get_graph_model_db(graph_name)
                await em.create_update_schema()
            if git_hash is not None:
                # update the system data version to not migrate the next time
                system_data.version = git_hash
                await self.system_data_db.update_system_data(system_data)
            else:
                log.warning("No git_hash found - will always update the database schema on startup.")

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
        db = cls.client(args, verify)

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
    def client(args: Namespace, verify: Union[bool, str, None] = None) -> StandardDatabase:
        if args.graphdb_type not in "arangodb":
            log.fatal(f"Unknown Graph DB type {args.graphdb_type}")
            shutdown_process(1)

        http_client = ArangoHTTPClient(args.graphdb_request_timeout, verify=verify)
        client = ArangoClient(hosts=args.graphdb_server, http_client=http_client)
        return client.db(args.graphdb_database, username=args.graphdb_username, password=args.graphdb_password)
