from __future__ import annotations

import logging
from typing import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from abc import abstractmethod

from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, ArangoEntityDb
from core.event_bus import Message
from core.model.typed_model import to_js
from core.types import Json
from core.util import utc
from core.workflow.workflows import WorkflowInstance

log = logging.getLogger(__name__)


@dataclass(order=True, unsafe_hash=True, frozen=True)
class WorkflowInstanceData:
    # id of the related workflow instance
    id: str
    # id of the related workflow
    workflow_id: str
    # name of the related workflow
    workflow_name: str
    # all messages that have been received by this workflow instance
    received_messages: Sequence[Message] = field(default_factory=list)
    # the name of the current state inside the finite state machine
    current_state_name: str = field(default="start")
    # the state of the current state exported as json
    current_state_snapshot: Json = field(default_factory=dict)
    # the timestamp when the step has been started
    step_started_at: datetime = field(default_factory=utc)

    @staticmethod
    def data(wi: WorkflowInstance) -> WorkflowInstanceData:
        return WorkflowInstanceData(
            wi.id,
            wi.workflow.id,
            wi.workflow.name,
            wi.received_messages,
            wi.current_state.name,
            wi.current_state.export_state(),
            wi.step_started_at,
        )


class WorkflowInstanceDb(EntityDb[WorkflowInstanceData]):
    @abstractmethod
    async def append_message(self, wi_id: str, message: Message) -> None:
        pass

    @abstractmethod
    async def insert(self, workflow_instance: WorkflowInstance) -> WorkflowInstanceData:
        pass


class ArangoWorkflowInstanceDb(ArangoEntityDb[WorkflowInstanceData], WorkflowInstanceDb):
    def __init__(self, db: AsyncArangoDB, collection: str):
        super().__init__(db, collection, WorkflowInstanceData, lambda k: k.id)

    async def append_message(self, wi_id: str, message: Message) -> None:
        bind = {"id": f"{self.collection_name}/{wi_id}", "message": to_js(message)}
        await self.db.aql(self.__add_message(), bind_vars=bind)

    async def insert(self, workflow_instance: WorkflowInstance) -> WorkflowInstanceData:
        return await self.update(WorkflowInstanceData.data(workflow_instance))

    @staticmethod
    def __add_message() -> str:
        return """
        LET doc = Document(@id)
        UPDATE doc WITH {received_messages: APPEND(doc.received_messages, @message)} IN workflow_instance
        """


def workflow_instance_db(db: AsyncArangoDB, collection: str) -> WorkflowInstanceDb:
    return ArangoWorkflowInstanceDb(db, collection)
