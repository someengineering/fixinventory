import logging
from abc import ABC
from datetime import datetime, timezone, timedelta
from typing import Dict, List

from arango.database import StandardDatabase
from dateutil.parser import parse

from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EventEntityDb
from core.db.jobdb import job_db
from core.db.modeldb import ModelDb, model_db
from core.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from core.db.subscriberdb import subscriber_db
from core.db.runningtaskdb import running_task_db
from core.error import NoSuchGraph
from core.event_bus import EventBus
from core.model.adjust_node import AdjustNode
from core.util import Periodic

log = logging.getLogger(__name__)


class DbAccess(ABC):
    def __init__(
        self,
        arango_database: StandardDatabase,
        event_bus: EventBus,
        adjust_node: AdjustNode,
        model_name: str = "model",
        subscriber_name: str = "subscribers",
        running_task_name: str = "running_tasks",
        job_name: str = "jobs",
        batch_outdated: timedelta = timedelta(minutes=30),
    ):
        self.event_bus = event_bus
        self.database = arango_database
        self.db = AsyncArangoDB(arango_database)
        self.adjust_node = adjust_node
        self.model_db = EventEntityDb(model_db(self.db, model_name), event_bus, model_name)
        self.subscribers_db = EventEntityDb(subscriber_db(self.db, subscriber_name), event_bus, subscriber_name)
        self.running_task_db = running_task_db(self.db, running_task_name)
        self.job_db = job_db(self.db, job_name)
        self.graph_dbs: Dict[str, GraphDB] = {}
        self.batch_outdated = batch_outdated
        self.cleaner = Periodic("batch_cleaner", self.check_outdated_batches, timedelta(seconds=60))

    async def start(self) -> None:
        await self.model_db.create_update_schema()
        await self.subscribers_db.create_update_schema()
        await self.running_task_db.create_update_schema()
        await self.job_db.create_update_schema()
        await self.cleaner.start()

    async def create_graph(self, name: str) -> GraphDB:
        db = self.get_graph_db(name, no_check=True)
        await db.create_update_schema()
        return db

    async def delete_graph(self, name: str) -> None:
        db = self.database
        if db.has_graph(name):
            db.delete_graph(name, drop_collections=True, ignore_missing=True)
            db.delete_collection(f"{name}_in_progress", ignore_missing=True)
            db.delete_view(f"search_{name}", ignore_missing=True)
            self.graph_dbs.pop(name, None)

    async def list_graphs(self) -> List[str]:
        return [a["name"] for a in self.database.graphs() if not a["name"].endswith("_hs")]

    def get_graph_db(self, name: str, no_check: bool = False) -> GraphDB:
        if name in self.graph_dbs:
            return self.graph_dbs[name]
        else:
            if not no_check and not self.database.has_graph(name):
                raise NoSuchGraph(name)
            graph_db = ArangoGraphDB(self.db, name, self.adjust_node)
            event_db = EventGraphDB(graph_db, self.event_bus)
            self.graph_dbs[name] = event_db
            return event_db

    def get_model_db(self) -> ModelDb:
        return self.model_db

    async def check_outdated_batches(self) -> None:
        now = datetime.now(timezone.utc)
        for db in self.graph_dbs.values():
            for batch in await db.list_in_progress_batch_updates():
                created = datetime.fromtimestamp(parse(batch["created"]).timestamp(), timezone.utc)
                if (now - created) > self.batch_outdated:
                    batch_id = batch["id"]
                    log.warning(f"Given batch is too old: {batch_id}. Will abort the batch.")
                    await db.abort_batch_update(batch_id)
