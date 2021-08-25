from __future__ import annotations

from typing import Sequence
from dataclasses import dataclass
from datetime import datetime

from toolz import valmap

from core.db.async_arangodb import AsyncArangoDB
from core.db.entitydb import EntityDb, EventEntityDb, ArangoEntityDb
from core.event_bus import Message
from core.workflow.workflows import WorkflowInstance


@dataclass(order=True, unsafe_hash=True, frozen=True)
class WorkflowInstanceData:
    id: str
    workflow_id: str
    workflow_name: str
    received_messages: Sequence[Message]
    subscriber_by_event: dict[str, list[str]]
    step_started_at: datetime

    @staticmethod
    def data(wi: WorkflowInstance) -> WorkflowInstanceData:
        return WorkflowInstanceData(
            wi.id,
            wi.workflow.id,
            wi.workflow.name,
            wi.received_messages,
            valmap(lambda subs: [s.id for s in subs], wi.subscribers_by_event),
            wi.step_started_at,
        )


WorkflowInstanceDb = EntityDb[WorkflowInstanceData]
EventWorkflowInstanceDb = EventEntityDb[WorkflowInstanceData]


def workflow_instance_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[WorkflowInstanceData]:
    return ArangoEntityDb(db, collection, WorkflowInstanceData, lambda k: k.id)
