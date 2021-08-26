from __future__ import annotations

import asyncio
import logging
from asyncio import Task, CancelledError
from datetime import timedelta
from typing import List, Dict, Tuple, Optional, Any, Callable, Union, Sequence

from core.db.runningtaskdb import RunningTaskData, RunningTaskDb
from core.event_bus import EventBus, Event, Action, ActionDone, Message, ActionError
from core.task.model import Subscriber
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_description import (
    Workflow,
    RunningTask,
    EventTrigger,
    TimeTrigger,
    TaskSurpassBehaviour,
    PerformAction,
    Step,
    TaskDescription,
    Job,
    ExecuteCommand,
    TaskCommand,
    SendMessage,
    ExecuteOnCLI,
)
from core.util import first, Periodic, group_by

log = logging.getLogger(__name__)


class TaskHandler:
    def __init__(
        self,
        running_task_db: RunningTaskDb,
        event_bus: EventBus,
        subscription_handler: SubscriptionHandler,
        scheduler: Scheduler,
    ):
        self.running_task_db = running_task_db
        self.event_bus = event_bus
        self.subscription_handler = subscription_handler
        self.scheduler = scheduler
        self.task_descriptions: Sequence[TaskDescription] = []
        self.tasks: Dict[str, RunningTask] = {}
        self.event_bus_watcher: Optional[Task[Any]] = None
        self.timeout_watcher = Periodic("task_timeout_watcher", self.check_overdue_tasks, timedelta(seconds=10))
        self.registered_event_trigger: List[Tuple[EventTrigger, TaskDescription]] = []
        self.registered_event_trigger_by_message_type: Dict[str, List[Tuple[EventTrigger, TaskDescription]]] = {}

    async def update_trigger(self, desc: TaskDescription, register: bool = True) -> None:
        # safeguard: unregister all event trigger of this task
        for existing in (tup for tup in self.registered_event_trigger if desc.id == tup[1].id):
            self.registered_event_trigger.remove(existing)
        # safeguard: unregister all schedule trigger of this task
        for job in self.scheduler.list_jobs():
            if str(job.id).startswith(desc.id):
                job.remove()
        # add all triggers
        if register:
            for trigger in desc.triggers:
                if isinstance(trigger, EventTrigger):
                    self.registered_event_trigger.append((trigger, desc))
                if isinstance(trigger, TimeTrigger):
                    uid = f"{desc.id}_{trigger.cron_expression}"
                    name = f"Trigger for task {desc.id} on cron expression {trigger.cron_expression}"
                    self.scheduler.cron(uid, name, trigger.cron_expression, self.time_triggered, desc, trigger)
        # recompute the lookup table
        self.registered_event_trigger_by_message_type = group_by(
            lambda t: t[0].message_type, self.registered_event_trigger
        )

    async def start_interrupted_tasks(self) -> list[RunningTask]:
        descriptions = {w.id: w for w in self.task_descriptions}

        def reset_state(wi: RunningTask, data: RunningTaskData) -> RunningTask:
            # reset the received messages
            wi.received_messages = data.received_messages  # type: ignore
            # move the fsm into the last known state
            wi.machine.set_state(data.current_state_name)
            # import state of the current step
            wi.current_state.import_state(data.current_state_snapshot)
            # ignore all messages that would be emitted
            wi.move_to_next_state()
            return wi

        instances: list[RunningTask] = []
        async for data in self.running_task_db.all():
            descriptor = descriptions.get(data.task_descriptor_id)
            if descriptor:
                instance = RunningTask(data.id, descriptor, self.subscription_handler.subscribers_by_event)
                instances.append(reset_state(instance, data))
            else:
                log.warning(f"No task description with this id found: {data.task_descriptor_id}. Remove instance data.")
                await self.running_task_db.delete(data.id)
        return instances

    async def start(self) -> None:
        # Step1: define all workflows and jobs in code: later it will be persisted and read from database
        td: list[TaskDescription] = []
        td.extend(self.known_workflows())
        td.extend(self.known_jobs())
        self.task_descriptions = td

        # load and restore all tasks
        self.tasks = {wi.id: wi for wi in await self.start_interrupted_tasks()}

        await self.timeout_watcher.start()

        for descriptor in self.task_descriptions:
            await self.update_trigger(descriptor)

        async def listen_to_event_bus() -> None:
            with self.event_bus.subscribe("task_handler") as messages:
                while True:
                    try:
                        message = await messages.get()
                        if isinstance(message, Event):
                            await self.handle_event(message)
                        elif isinstance(message, Action):
                            await self.handle_action(message)
                        elif isinstance(message, (ActionDone, ActionError)):
                            log.info(f"Ignore message via event bus: {message}")
                    except Exception as ex:
                        log.error(f"Could not handle event {message} - give up.", ex)

        self.event_bus_watcher = asyncio.create_task(listen_to_event_bus())

    async def stop(self) -> None:
        for descriptor in self.task_descriptions:
            await self.update_trigger(descriptor, register=False)
        await self.timeout_watcher.stop()
        if self.event_bus_watcher:
            self.event_bus_watcher.cancel()
            try:
                await self.event_bus_watcher
            except CancelledError:
                log.info("task has been cancelled")

    async def time_triggered(self, descriptor: TaskDescription, trigger: TimeTrigger) -> None:
        log.info(f"Task {descriptor.name} triggered by time: {trigger.cron_expression}")
        return await self.start_task(descriptor)

    async def start_task(self, descriptor: TaskDescription) -> None:
        existing = first(lambda x: x.descriptor.id == descriptor.id, self.tasks.values())
        if existing:
            if descriptor.on_surpass == TaskSurpassBehaviour.Skip:
                log.info(
                    f"Task {descriptor.name} has been triggered. Since the last job is not finished, "
                    f"the execution will be skipped, as defined by the task"
                )
                return None
            elif descriptor.on_surpass == TaskSurpassBehaviour.Replace:
                log.info(f"New task {descriptor.name} should replace existing run: {existing.id}.")
                existing.end()
                await self.after_handled(existing, [])
            elif descriptor.on_surpass == TaskSurpassBehaviour.Parallel:
                log.info(f"New task {descriptor.name} will race with existing run {existing.id}.")
            else:
                raise AttributeError(f"Surpass behaviour not handled: {descriptor.on_surpass}")

        wi, commands = RunningTask.empty(descriptor, self.subscription_handler.subscribers_by_event)
        if wi.is_active:
            log.info(f"Start new task: {descriptor.name} with id {wi.id}")
            # store initial state in database
            await self.running_task_db.insert(wi)
            self.tasks[wi.id] = wi
        else:
            log.info(f"Task {descriptor.name} was triggered and ran directly to the end. Ignore.")

        await self.execute_task_commands(wi, commands)

    async def handle_event(self, event: Event) -> None:
        # check if any running task want's to handle this event
        for wi in self.tasks.values():
            handled, messages_to_emit = wi.handle_event(event)
            if handled:
                await self.after_handled(wi, messages_to_emit, event)

        # check if this event triggers any new task
        for trigger, descriptor in self.registered_event_trigger_by_message_type.get(event.message_type, []):
            if event.message_type == trigger.message_type:
                comp = trigger.filter_data
                if {key: event.data.get(key) for key in comp} == comp if comp else True:
                    log.info(f"Event {event.message_type} triggers task: {descriptor.name}")
                    await self.start_task(descriptor)

    # noinspection PyMethodMayBeStatic
    async def handle_action(self, action: Action) -> None:
        log.info(f"Received action: {action.step_name}:{action.message_type} of {action.task_id}")

    async def handle_action_result(
        self,
        done: Union[ActionDone, ActionError],
        fn: Callable[[RunningTask], Sequence[TaskCommand]],
    ) -> None:
        wi = self.tasks.get(done.task_id)
        if wi:
            commands = fn(wi)
            return await self.after_handled(wi, commands, done)
        else:
            log.warning(
                f"Received an ack for an unknown task={done.task_id} "
                f"event={done.message_type} from={done.subscriber_id}. Ignore."
            )

    async def handle_action_done(self, done: ActionDone) -> None:
        return await self.handle_action_result(done, lambda wi: wi.handle_done(done))

    async def handle_action_error(self, err: ActionError) -> None:
        log.info(f"Received error: {err.error} {err.step_name}:{err.message_type} of {err.task_id}")
        return await self.handle_action_result(err, lambda wi: wi.handle_error(err))

    async def execute_task_commands(self, wi: RunningTask, commands: Sequence[TaskCommand]) -> None:
        for command in commands:
            if isinstance(command, SendMessage):
                await self.event_bus.emit(command.message)
            elif isinstance(command, ExecuteOnCLI):
                # TODO interface with cli
                pass
            else:
                raise AttributeError(f"Does not understand this command: {wi.descriptor.name}:  {command}")

    async def after_handled(
        self, wi: RunningTask, commands: Sequence[TaskCommand], origin_message: Optional[Message] = None
    ) -> None:
        await self.execute_task_commands(wi, commands)
        if wi.is_active:
            await self.running_task_db.update_state(wi, origin_message)
        else:
            log.info(f"Task instance {wi.id} is done and will be removed.")
            await self.running_task_db.delete(wi.id)
            del self.tasks[wi.id]

    async def list_all_pending_actions_for(self, subscriber: Subscriber) -> List[Action]:
        pending = map(lambda x: x.pending_action_for(subscriber), self.tasks.values())
        return [x for x in pending if x]

    async def check_overdue_tasks(self) -> None:
        """
        Called periodically by the system.
        In case there is an overdue task, an action error is injected into the task.
        """
        for task in list(self.tasks.values()):
            if task.is_active:  # task is still active
                if task.current_state.check_timeout():
                    messages = task.move_to_next_state()
                    await self.after_handled(task, messages)

    @staticmethod
    def known_workflows() -> Sequence[Workflow]:
        return [
            Workflow(
                "collect",
                "collect",
                [
                    Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
                    Step("act", PerformAction("collect"), timedelta(seconds=10)),
                    Step("done", PerformAction("collect_done"), timedelta(seconds=10)),
                ],
                [EventTrigger("start_collect_workflow"), TimeTrigger("5 * * * *")],
            ),
            Workflow(
                "cleanup",
                "cleanup",
                [
                    Step("pre_plan", PerformAction("pre_cleanup_plan"), timedelta(seconds=10)),
                    Step("plan", PerformAction("cleanup_plan"), timedelta(seconds=10)),
                    Step("post_plan", PerformAction("post_cleanup_plan"), timedelta(seconds=10)),
                    Step("pre_clean", PerformAction("pre_cleanup"), timedelta(seconds=10)),
                    Step("clean", PerformAction("cleanup"), timedelta(seconds=10)),
                    Step("post_clean", PerformAction("post_cleanup"), timedelta(seconds=10)),
                ],
                [EventTrigger("start_cleanup_workflow"), TimeTrigger("5 * * * *")],
            ),
        ]

    @staticmethod
    def known_jobs() -> Sequence[Job]:
        return [Job("example-job", "example-job", ExecuteCommand("echo hello"), EventTrigger("run_job"))]
