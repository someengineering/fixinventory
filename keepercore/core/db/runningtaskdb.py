from __future__ import annotations

import logging
from typing import Sequence, Optional
from dataclasses import dataclass, field
from datetime import datetime

from abc import abstractmethod

from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, ArangoEntityDb
from core.event_bus import Message
from core.model.typed_model import to_js
from core.types import Json
from core.util import utc
from core.task.task_description import RunningTask

log = logging.getLogger(__name__)


@dataclass(order=True, unsafe_hash=True, frozen=True)
class RunningTaskData:
    # id of the related task
    id: str
    # id of the related task descriptor
    task_descriptor_id: str
    # name of the related task descriptor
    task_descriptor_name: str
    # all messages that have been received by this task
    received_messages: Sequence[Message] = field(default_factory=list)
    # the name of the current state inside the finite state machine
    current_state_name: str = field(default="start")
    # the state of the current state exported as json
    current_state_snapshot: Json = field(default_factory=dict)
    # the timestamp when the step has been started
    step_started_at: datetime = field(default_factory=utc)

    @staticmethod
    def data(wi: RunningTask) -> RunningTaskData:
        return RunningTaskData(
            wi.id,
            wi.descriptor.id,
            wi.descriptor.name,
            wi.received_messages,
            wi.current_state.name,
            wi.current_state.export_state(),
            wi.step_started_at,
        )


class RunningTaskDb(EntityDb[RunningTaskData]):
    @abstractmethod
    async def update_state(self, wi: RunningTask, message: Optional[Message]) -> None:
        pass

    @abstractmethod
    async def insert(self, task: RunningTask) -> RunningTaskData:
        pass


class ArangoRunningTaskDb(ArangoEntityDb[RunningTaskData], RunningTaskDb):
    def __init__(self, db: AsyncArangoDB, collection: str):
        super().__init__(db, collection, RunningTaskData, lambda k: k.id)

    async def update_state(self, wi: RunningTask, message: Optional[Message]) -> None:
        bind = {
            "id": f"{self.collection_name}/{wi.id}",
            "current_state_name": wi.current_state.name,
            "current_state_snapshot": wi.current_state.export_state(),
        }
        if message:
            bind["message"] = to_js(message)
            aql = self.__update_state_with_message()
        else:
            aql = self.__update_state()

        await self.db.aql(aql, bind_vars=bind)

    async def insert(self, task: RunningTask) -> RunningTaskData:
        return await self.update(RunningTaskData.data(task))

    def __update_state(self) -> str:
        return f"""
        LET doc = Document(@id)
        UPDATE doc WITH {{
            current_state_name: @current_state_name,
            current_state_snapshot: @current_state_snapshot
        }} IN {self.collection_name}
        """

    def __update_state_with_message(self) -> str:
        return f"""
        LET doc = Document(@id)
        UPDATE doc WITH {{
            current_state_name: @current_state_name,
            current_state_snapshot: @current_state_snapshot,
            received_messages: APPEND(doc.received_messages, @message)
        }} IN {self.collection_name}
        """


def running_task_db(db: AsyncArangoDB, collection: str) -> RunningTaskDb:
    return ArangoRunningTaskDb(db, collection)
