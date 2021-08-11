import logging
from abc import ABC
from datetime import datetime, timezone, timedelta
from typing import Dict, List

from arango.database import StandardDatabase
from dateutil.parser import parse

from core.db.async_arangodb import AsyncArangoDB
from core.db.graphdb import ArangoGraphDB, GraphDB, EventGraphDB
from core.db.modeldb import ArangoModelDB, ModelDB, EventModelDB
from core.event_bus import EventBus
from core.util import Periodic

log = logging.getLogger(__name__)


class DbAccess(ABC):
    def __init__(
        self,
        arango_database: StandardDatabase,
        event_bus: EventBus,
        model_name: str = "model",
        batch_outdated: timedelta = timedelta(minutes=30),
    ):
        self.event_bus = event_bus
        self.database = arango_database
        self.db = AsyncArangoDB(arango_database)
        self.model_name = model_name
        self.model_db = ArangoModelDB(self.db, model_name)
        self.model_event_db = EventModelDB(self.model_db, event_bus)
        self.graph_dbs: Dict[str, GraphDB] = {}
        self.batch_outdated = batch_outdated
        self.cleaner = Periodic("batch_cleaner", self.check_outdated_batches, timedelta(seconds=60))

    async def start(self) -> None:
        await self.model_db.create_update_schema()
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

    async def list_graphs(self) -> List[str]:
        return [a["name"] for a in self.database.graphs() if not a["name"].endswith("_hs")]

    def get_graph_db(self, name: str, no_check: bool = False) -> GraphDB:
        if name in self.graph_dbs:
            return self.graph_dbs[name]
        else:
            if not no_check and not self.database.has_graph(name):
                raise AttributeError(f"No graph with this name: {name}")
            graph_db = ArangoGraphDB(self.db, name)
            event_db = EventGraphDB(graph_db, self.event_bus)
            self.graph_dbs[name] = event_db
            return event_db

    def get_model_db(self) -> ModelDB:
        return self.model_event_db

    async def check_outdated_batches(self) -> None:
        now = datetime.now(timezone.utc)
        for db in self.graph_dbs.values():
            for batch in await db.list_in_progress_batch_updates():
                created = datetime.fromtimestamp(parse(batch["created"]).timestamp(), timezone.utc)
                if (now - created) > self.batch_outdated:
                    batch_id = batch["id"]
                    log.warning(f"Given batch is too old: {batch_id}. Will abort the batch.")
                    await db.abort_batch_update(batch_id)
