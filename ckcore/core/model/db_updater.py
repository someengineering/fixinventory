import asyncio
import json
from abc import ABC
from dataclasses import dataclass
from multiprocessing import Process, Queue
from typing import Optional, Any

from core.dependencies import db_access
from core.event_bus import EventBus
from core.model.graph_access import GraphBuilder
from core.model.model import Model


class Action(ABC):
    pass


@dataclass
class ReadLine(Action):
    line: bytes


@dataclass
class MergeGraph(Action):
    graph: str
    maybe_batch: Optional[str]


@dataclass
class Result:
    value: Any

    def get_value(self) -> Any:
        if isinstance(self.value, Exception):
            raise self.value
        else:
            return self.value


class DbUpdater(Process):
    def __init__(self, read_queue: Queue, write_queue: Queue) -> None:
        super().__init__(name="db_update")
        self.read_queue = read_queue
        self.write_queue = write_queue

    def next_action(self) -> Action:
        return self.read_queue.get(True, 30)

    async def main(self) -> None:
        db = db_access(EventBus())
        model = Model.from_kinds([kind async for kind in db.model_db.all()])
        builder = GraphBuilder(model)
        nxt = self.next_action()
        while isinstance(nxt, ReadLine):
            builder.add_from_json(json.loads(nxt.line))
            nxt = self.next_action()
        builder.check_complete()
        if isinstance(nxt, MergeGraph):
            graphdb = db.get_graph_db(nxt.graph)
            result = await graphdb.merge_graph(builder.graph, model, nxt.maybe_batch)
            self.write_queue.put(Result(result))

    def run(self) -> None:
        try:
            asyncio.run(self.main())
            exit(0)
        except Exception as ex:
            self.write_queue.put(Result(ex))
            exit(1)
