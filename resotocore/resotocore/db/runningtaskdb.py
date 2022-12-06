from __future__ import annotations

import logging
from abc import abstractmethod
from datetime import datetime, timedelta
from functools import partial
from typing import Sequence, Optional, List, AsyncGenerator, Dict, Union

from attrs import define, field
from jsons import JsonsError

from resotocore.db.async_arangodb import AsyncArangoDB, AsyncCursorContext
from resotocore.db.entitydb import EntityDb, ArangoEntityDb
from resotocore.ids import TaskId, TaskDescriptorId
from resotocore.message_bus import Message, ActionInfo, ActionError
from resotocore.model.typed_model import to_js, from_js
from resotocore.task.task_description import RunningTask
from resotocore.types import Json, JsonElement
from resotocore.util import utc, utc_str
from resotolib.durations import duration_str

log = logging.getLogger(__name__)


@define(order=True, hash=True, frozen=True)
class RunningTaskStepInfo:
    step_name: str
    timed_out: bool = False
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @staticmethod
    def from_task(task: RunningTask) -> List[RunningTaskStepInfo]:
        return [
            RunningTaskStepInfo(name, s.timed_out, s.started_at, s.finished_at)
            for name, s in task.states.items()
            if name not in ("task_start", "task_end")
        ]


@define(order=True, hash=True, frozen=True)
class RunningTaskData:
    # id of the related task
    id: TaskId
    # id of the related task descriptor
    task_descriptor_id: TaskDescriptorId
    # kind of the descriptor
    task_descriptor_kind: str
    # name of the related task descriptor
    task_descriptor_name: str
    # all messages that have been received by this task
    received_messages: Sequence[Message] = field(factory=list)
    # the name of the current state inside the finite state machine
    current_state_name: str = field(default="start")
    # the state of the current state exported as json
    current_state_snapshot: Json = field(factory=dict)
    # base state of every step
    step_states: List[RunningTaskStepInfo] = field(factory=list)
    # the timestamp when the step has been started
    task_started_at: datetime = field(factory=utc)
    # duration of the task
    task_duration: Optional[timedelta] = None
    # indicates if this task is still active
    done: bool = False
    # indicates if this task had warnings
    has_info: bool = False
    # indicates if this task had errors
    has_error: bool = False

    def info_messages(self) -> List[Union[ActionInfo, ActionError]]:
        return [m for m in iter(self.received_messages) if isinstance(m, (ActionInfo, ActionError))]

    @staticmethod
    def data(wi: RunningTask) -> RunningTaskData:
        return RunningTaskData(
            wi.id,
            wi.descriptor.id,
            type(wi.descriptor).__name__,
            wi.descriptor.name,
            wi.received_messages,
            wi.current_state.name,
            wi.current_state.export_state(),
            RunningTaskStepInfo.from_task(wi),
            wi.task_started_at,
            wi.task_duration,
            not wi.is_active,
            any(True for msg in wi.info_messages if isinstance(msg, ActionInfo) and msg.level == "info"),
            any(
                True
                for msg in wi.info_messages
                if (isinstance(msg, ActionInfo) and msg.level == "error") or isinstance(msg, ActionError)
            ),
        )


class RunningTaskDb(EntityDb[str, RunningTaskData]):
    @abstractmethod
    def all_running(self) -> AsyncGenerator[RunningTaskData, None]:
        pass

    @abstractmethod
    async def update_state(self, wi: RunningTask, message: Optional[Message] = None) -> None:
        pass

    @abstractmethod
    async def insert(self, task: RunningTask) -> RunningTaskData:
        pass

    @abstractmethod
    async def aggregated_history(self) -> Dict[str, Json]:
        pass

    @abstractmethod
    async def filtered(
        self,
        *,
        task_id: Optional[TaskId] = None,
        descriptor_id: Optional[str] = None,
        started_after: Optional[datetime] = None,
        started_before: Optional[datetime] = None,
        with_info: Optional[bool] = None,
        with_error: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> AsyncCursorContext:
        pass


class ArangoRunningTaskDb(ArangoEntityDb[str, RunningTaskData], RunningTaskDb):
    def __init__(self, db: AsyncArangoDB, collection: str):
        super().__init__(db, collection, RunningTaskData, lambda k: k.id)

    async def create_update_schema(self) -> None:
        await super().create_update_schema()
        collection = self.db.collection(self.collection_name)
        indexes = {idx["name"]: idx for idx in collection.indexes()}
        # descriptor_id, descriptor_name, done, created_at
        id_idx = f"{self.collection_name}_id_done"
        if id_idx not in indexes:
            collection.add_persistent_index(
                ["task_descriptor_id", "task_descriptor_name", "task_started_at", "has_info", "has_error", "done"],
                sparse=False,
                name=id_idx,
            )
        # ttl index to get rid of old entries
        ttl_idx = f"{self.collection_name}_ttl"
        if ttl_idx not in indexes:
            collection.add_ttl_index(
                ["task_started_at"],
                expiry_time=int(timedelta(days=60).total_seconds()),
                in_background=True,
                name=ttl_idx,
            )

    async def all_running(self) -> AsyncGenerator[RunningTaskData, None]:
        aql = f"""FOR doc IN {self.collection_name} FILTER doc.done == false RETURN doc"""
        async with await self.db.aql_cursor(aql) as cursor:
            async for element in cursor:
                try:
                    yield from_js(element, RunningTaskData)
                except JsonsError:
                    log.warning(f"Not able to parse {element} into RunningTaskData. Ignore.")

    async def update_state(self, wi: RunningTask, message: Optional[Message] = None) -> None:
        bind = {
            "id": f"{self.collection_name}/{wi.id}",
            "current_state_name": wi.current_state.name,
            "current_state_snapshot": wi.current_state.export_state(),
            "step_states": to_js(RunningTaskStepInfo.from_task(wi)),
            "task_duration": to_js(wi.task_duration),
            "has_info": any(True for msg in wi.info_messages if isinstance(msg, ActionInfo) and msg.level == "info"),
            "has_error": any(True for msg in wi.info_messages if isinstance(msg, ActionInfo) and msg.level == "error"),
            "done": not wi.is_active,
        }
        if message:
            bind["message"] = to_js(message)
            aql = self.__update_state_with_message()
        else:
            aql = self.__update_state()

        await self.db.aql(aql, bind_vars=bind)

    async def aggregated_history(self) -> Dict[str, Json]:
        aql = f"""
        FOR rt in {self.collection_name}
        COLLECT name=rt.task_descriptor_id
        AGGREGATE c=sum(1), l=max(rt.task_started_at), e=sum(abs(rt.has_error)), d=avg(rt.task_duration)
        RETURN {{"name": name, "count": c, "last_run": l, "runs_with_errors": e, "average_duration": ceil(d)}}
        """
        result = {}
        with await self.db.aql(aql) as crsr:
            for elem in crsr:
                name = elem.pop("name")
                elem["average_duration"] = duration_str(timedelta(seconds=elem["average_duration"]), precision=2)
                result[name] = elem
        return result

    async def filtered(
        self,
        *,
        task_id: Optional[TaskId] = None,
        descriptor_id: Optional[str] = None,
        started_after: Optional[datetime] = None,
        started_before: Optional[datetime] = None,
        with_info: Optional[bool] = None,
        with_error: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> AsyncCursorContext:
        filters: List[str] = []
        bind: Dict[str, JsonElement] = {}
        if task_id:
            filters.append("doc.id == @task_id")
            bind["task_id"] = task_id
        if descriptor_id:
            filters.append("doc.task_descriptor_id == @descriptor_id")
            bind["descriptor_id"] = descriptor_id
        if started_after:
            filters.append("doc.task_started_at >= @started_after")
            bind["started_after"] = utc_str(started_after)
        if started_before:
            filters.append("doc.task_started_at <= @started_before")
            bind["started_before"] = utc_str(started_before)
        if with_info is not None:
            filters.append("doc.has_info == @with_info")
            bind["with_info"] = with_info
        if with_error is not None:
            filters.append("doc.has_error == @with_error")
            bind["with_error"] = with_error
        filter_stmt = " FILTER " + (" AND ".join(filters)) if filters else ""
        limit_stmt = f" LIMIT {limit}" if limit else ""
        res = f"FOR doc IN {self.collection_name}{filter_stmt} SORT doc.task_started_at DESC {limit_stmt} RETURN doc"
        aql = f"LET r = ({res}) FOR res in REVERSE(r) RETURN res"
        return await self.db.aql_cursor(query=aql, bind_vars=bind, trafo=partial(from_js, clazz=RunningTaskData))

    async def insert(self, task: RunningTask) -> RunningTaskData:
        return await self.update(RunningTaskData.data(task))

    def __update_state(self) -> str:
        return f"""
        LET doc = Document(@id)
        UPDATE doc WITH {{
            current_state_name: @current_state_name,
            current_state_snapshot: @current_state_snapshot,
            step_states: @step_states,
            task_duration: @task_duration,
            has_info: @has_info,
            has_error: @has_error,
            done: @done
        }} IN {self.collection_name}
        """

    def __update_state_with_message(self) -> str:
        return f"""
        LET doc = Document(@id)
        UPDATE doc WITH {{
            current_state_name: @current_state_name,
            current_state_snapshot: @current_state_snapshot,
            step_states: @step_states,
            task_duration: @task_duration,
            has_info: @has_info,
            has_error: @has_error,
            done: @done,
            received_messages: APPEND(doc.received_messages, @message)
        }} IN {self.collection_name}
        """


def running_task_db(db: AsyncArangoDB, collection: str) -> RunningTaskDb:
    return ArangoRunningTaskDb(db, collection)
