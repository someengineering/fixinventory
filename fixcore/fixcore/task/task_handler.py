from __future__ import annotations

import asyncio
import logging
import re
from asyncio import Task, CancelledError
from contextlib import suppress
from copy import copy
from datetime import timedelta
from typing import Optional, Any, Callable, Union, Sequence, Dict, List, Tuple
from aiostream import stream
from attrs import evolve

from fixcore.analytics import AnalyticsEventSender, CoreEvent
from fixcore.cli.model import CLIContext, CLI
from fixcore.core_config import CoreConfig
from fixcore.db.jobdb import JobDb
from fixcore.db.runningtaskdb import RunningTaskData, RunningTaskDb
from fixcore.ids import SubscriberId, TaskDescriptorId, TaskId
from fixcore.message_bus import (
    MessageBus,
    Event,
    Action,
    ActionDone,
    Message,
    ActionError,
    ActionInfo,
    ActionProgress,
    CoreMessage,
)
from fixcore.model.db_updater import GraphMerger
from fixcore.service import Service
from fixcore.task import TaskHandler, RunningTaskInfo
from fixcore.task.model import Subscriber
from fixcore.task.scheduler import Scheduler
from fixcore.task.start_workflow_on_first_subscriber import wait_and_start
from fixcore.task.subscribers import SubscriptionHandler
from fixcore.task.task_dependencies import TaskDependencies
from fixcore.task.task_description import (
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
    StepErrorBehaviour,
    RestartAgainStepAction,
    Trigger,
    WaitForCollectDone,
)
from fixcore.util import first, Periodic, group_by, utc_str, utc, partition_by
from fixcore.types import Json

log = logging.getLogger(__name__)


class TaskHandlerService(TaskHandler, Service):
    # region init

    def __init__(
        self,
        running_task_db: RunningTaskDb,
        job_db: JobDb,
        message_bus: MessageBus,
        event_sender: AnalyticsEventSender,
        subscription_handler: SubscriptionHandler,
        graph_merger: GraphMerger,
        scheduler: Scheduler,
        cli: CLI,
        config: CoreConfig,
    ):
        super().__init__()
        self.running_task_db = running_task_db
        self.job_db = job_db
        self.message_bus = message_bus
        self.event_sender = event_sender
        self.subscription_handler = subscription_handler
        self.scheduler = scheduler
        self.cli = cli
        self.cli_context = CLIContext(source="task_handler")
        self.config = config
        # note: the waiting queue is kept in memory and lost when the service is restarted.
        self.start_when_done: Dict[str, TaskDescription] = {}

        # Step1: define all workflows and jobs in code: later it will be persisted and read from database
        self.task_descriptions: Sequence[TaskDescription] = [*self.known_workflows(config), *self.known_jobs()]
        self.tasks: Dict[TaskId, RunningTask] = {}
        self.message_bus_watcher: Optional[Task[None]] = None
        self.initial_start_workflow_task: Optional[Task[None]] = None
        self.timeout_watcher = Periodic("task_watcher", self.check_running_tasks, timedelta(seconds=10))
        self.registered_event_trigger: List[Tuple[EventTrigger, TaskDescription]] = []
        self.registered_event_trigger_by_message_type: Dict[str, List[Tuple[EventTrigger, TaskDescription]]] = {}
        self.task_dependencies = TaskDependencies(graph_merger, subscription_handler.subscribers_by_event)

    # endregion

    # region startup and teardown

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

    # task descriptors can hold placeholders (e.g. @NOW@)
    # which should be replaced, when the task is started (or restarted).
    def evaluate_task_definition(self, descriptor: TaskDescription, **env: str) -> TaskDescription:
        def evaluate(step: Step) -> Step:
            if isinstance(step.action, ExecuteCommand):
                update = copy(step)
                update.action = ExecuteCommand(self.cli.replace_placeholder(step.action.command, **env))
                return update
            else:
                return step

        updated = copy(descriptor)
        updated.steps = [evaluate(step) for step in descriptor.steps]
        return updated

    async def fetch_task_metadata(self, descriptor_id: TaskDescriptorId) -> Json:
        timing: Dict[str, Dict[str, int]] = {}
        if last_workflow_run := await self.running_task_db.last(descriptor_id=descriptor_id):
            timing = {
                s.step_name: {
                    "started_at": int(s.started_at.timestamp()),
                    "finished_at": int(s.finished_at.timestamp()),
                }
                for s in last_workflow_run.step_states
                if s.finished_at and s.started_at
            }
        return {
            "timing": timing,
        }

    async def start_task_directly(self, desc: TaskDescription, reason: str) -> RunningTask:
        updated = self.evaluate_task_definition(desc)

        metadata = await self.fetch_task_metadata(desc.id)
        task, commands = RunningTask.empty(updated, self.task_dependencies, metadata=metadata)

        log.info(f"Start new task: {updated.name} with id {task.id}")
        # store initial state in database
        await self.running_task_db.insert(task)
        self.tasks[task.id] = task
        await self.execute_task_commands(task, commands)
        await self.event_sender.core_event(
            CoreEvent.TaskStarted,
            {
                "reason": reason,
                "task_descriptor_id": updated.id,
                "task_descriptor_name": updated.name,
                "kind": type(updated).__name__,
            },
        )
        return task

    async def start_task(self, desc: TaskDescription, reason: str) -> Optional[RunningTaskInfo]:
        existing = first(lambda x: x.descriptor.id == desc.id and x.is_active, self.tasks.values())
        if existing:
            if desc.on_surpass == TaskSurpassBehaviour.Skip:
                log.info(
                    f"Task {desc.name} has been triggered. Since the last job is not finished, "
                    f"the execution will be skipped, as defined by the task"
                )
                return None
            elif desc.on_surpass == TaskSurpassBehaviour.Replace:
                log.info(f"New task {desc.name} should replace existing run: {existing.id}.")
                existing.end()
                await self.store_running_task_state(existing)
                return RunningTaskInfo(await self.start_task_directly(desc, reason))
            elif desc.on_surpass == TaskSurpassBehaviour.Parallel:
                log.info(f"New task {desc.name} will race with existing run {existing.id}.")
                return RunningTaskInfo(await self.start_task_directly(desc, reason))
            elif desc.on_surpass == TaskSurpassBehaviour.Wait:
                log.info(f"New task {desc.name} with reason {reason} will run when existing run {existing.id} is done.")
                self.start_when_done[desc.id] = desc
                return RunningTaskInfo(existing, True)
            else:
                raise AttributeError(f"Surpass behaviour not handled: {desc.on_surpass}")
        else:
            return RunningTaskInfo(await self.start_task_directly(desc, reason))

    async def start_interrupted_tasks(self) -> List[RunningTask]:
        descriptions = {w.id: w for w in self.task_descriptions}

        def reset_state(wi: RunningTask, task_data: RunningTaskData) -> RunningTask:
            infos, messages = partition_by(lambda x: isinstance(x, ActionInfo), task_data.received_messages)
            # reset the received messages
            wi.received_messages = messages
            wi.info_messages = infos  # type: ignore
            # move the fsm into the last known state
            wi.machine.set_state(task_data.current_state_name)
            # import state of the current step
            wi.current_state.import_state(task_data.current_state_snapshot)
            for si in task_data.step_states:
                if step_state := wi.states.get(si.step_name):
                    step_state.started_at = si.started_at
                    step_state.finished_at = si.finished_at
                    step_state.timed_out = si.timed_out
            # reset times
            wi.task_started_at = task_data.task_started_at
            # ignore all messages that would be emitted
            wi.move_to_next_state()
            return wi

        started_instances: Dict[TaskDescriptorId, RunningTask] = {}
        async for data in self.running_task_db.all_running():
            descriptor = descriptions.get(data.task_descriptor_id)
            if descriptor is None:
                log.warning(f"No task description with this id found: {data.task_descriptor_id}. Remove instance data.")
                await self.running_task_db.delete(data.id)
                continue

            if descriptor.id in started_instances and descriptor.on_surpass != TaskSurpassBehaviour.Parallel:
                log.warning(f"Already started task for: {data.task_descriptor_id}: {data.id}. Remove instance data.")
                await self.running_task_db.delete(data.id)
                continue

            # we have captured the timestamp when the task has been started
            updated = self.evaluate_task_definition(descriptor, now=utc_str(data.task_started_at))
            rt = RunningTask(data.id, updated, self.task_dependencies)
            instance = reset_state(rt, data)
            if isinstance(instance.current_step.action, RestartAgainStepAction):
                log.info(f"Restart interrupted action: {instance.current_step.action}")
                await self.execute_task_commands(instance, instance.current_state.commands_to_execute())
            started_instances[descriptor.id] = instance
        return list(started_instances.values())

    async def start(self) -> TaskHandlerService:
        log.debug("TaskHandlerService is starting up!")

        # load job descriptions from database
        if not self.config.multi_tenant_setup:
            db_jobs = [job async for job in self.job_db.all()]
            self.task_descriptions = [*self.task_descriptions, *db_jobs]

        # load and restore all tasks
        if not self.config.args.ignore_interrupted_tasks and not self.config.multi_tenant_setup:
            self.tasks = {wi.id: wi for wi in await self.start_interrupted_tasks()}

        await self.timeout_watcher.start()

        for descriptor in self.task_descriptions:
            await self.update_trigger(descriptor)

        if self.config.runtime.start_collect_on_subscriber_connect:
            filtered = [wf for wf in self.known_workflows(self.config) if wf.id == "collect_and_cleanup"]
            self.initial_start_workflow_task = wait_and_start(filtered, self, self.message_bus)

        async def listen_to_message_bus() -> None:
            async with self.message_bus.subscribe(SubscriberId("fixcore.task_handler")) as messages:
                while True:
                    message = None
                    try:
                        message = await messages.get()
                        if isinstance(message, Event):
                            await self.handle_event(message)
                        elif isinstance(message, Action):
                            await self.handle_action(message)
                        elif isinstance(message, (ActionDone, ActionError)):
                            log.info(f"Ignore message via event bus: {message}")
                    except Exception as ex:
                        log.error(f"Could not handle event {message} - give up.", exc_info=ex)

        self.message_bus_watcher = asyncio.create_task(listen_to_message_bus())
        return self

    async def stop(self) -> None:
        log.info("Tear down task handler")
        # deregister from all triggers
        for descriptor in self.task_descriptions:
            await self.update_trigger(descriptor, register=False)

        # stop timeout watcher
        await self.timeout_watcher.stop()

        # stop event listener
        if self.message_bus_watcher and not self.message_bus_watcher.done():
            self.message_bus_watcher.cancel()
            try:
                await self.message_bus_watcher
            except CancelledError:
                log.info("task has been cancelled")
            except Exception:
                log.error("Error while waiting for message bus watcher to stop.", exc_info=True)

        # wait for all running commands to complete
        for task in list(self.tasks.values()):
            if task.update_task:
                with suppress(Exception):
                    await task.update_task
                del self.tasks[task.id]

        # in case the task is not done
        if self.initial_start_workflow_task and not self.initial_start_workflow_task.done():
            self.initial_start_workflow_task.cancel()

    # endregion

    # region job handler

    async def running_tasks(self) -> List[RunningTask]:
        return list(self.tasks.values())

    async def start_task_by_descriptor_id(self, uid: TaskDescriptorId) -> Optional[RunningTaskInfo]:
        td = first(lambda t: t.id == uid, self.task_descriptions)
        if td:
            return await self.start_task(td, "direct")
        else:
            raise NameError(f"No task with such id: {uid}")

    async def list_jobs(self) -> List[Job]:
        return [td for td in self.task_descriptions if isinstance(td, Job)]

    async def list_workflows(self) -> List[Workflow]:
        return [td for td in self.task_descriptions if isinstance(td, Workflow)]

    def __check_system_job(self, name: str) -> None:
        # : is not allowed in job names
        if re.match(r"^[^:]+$", name) is None:
            raise AttributeError(f"System jobs can't be modified: {name}")

    async def add_job(self, job: Job, force: bool = False) -> None:
        if not force:
            self.__check_system_job(job.name)
        descriptions = list(self.task_descriptions)
        existing = first(lambda td: td.id == job.id, descriptions)
        if existing:
            if not existing.mutable:
                raise AttributeError(f"There is an existing job with this {job.id} which can not be deleted!")
            log.info(f"Job with id {job.id} already exists. Update this job.")
            descriptions.remove(existing)
        # store in database
        await self.job_db.update(job)
        descriptions.append(job)
        self.task_descriptions = descriptions
        await self.update_trigger(job)

    async def stop_task(self, uid: TaskId) -> Optional[RunningTask]:
        if task := self.tasks.get(uid):
            commands = task.current_state.abort()  # abort current step
            task.end()  # mark task as done
            await self.execute_task_commands(task, commands)
            return task
        return None

    async def delete_running_task(self, task: RunningTask) -> None:
        # send analytics event
        await self.event_sender.core_event(
            CoreEvent.TaskCompleted,
            {
                "task_descriptor_id": task.descriptor.id,
                "task_descriptor_name": task.descriptor.name,
                "kind": type(task.descriptor).__name__,
                "success": not task.is_error,
            },
            duration=(utc() - task.task_started_at).total_seconds(),
            step_count=len(task.descriptor.steps),
        )
        task.descriptor_alive = False
        # remove tasks from list of running tasks
        self.tasks.pop(task.id, None)
        if task.update_task and not task.update_task.done():
            task.update_task.cancel()

        # mark step as error
        task.end()
        await self.mark_done_in_database(task)

    async def delete_job(self, job_id: str, force: bool = False) -> Optional[Job]:
        if not force:
            self.__check_system_job(job_id)
        job: Job = first(lambda td: td.id == job_id and isinstance(td, Job), self.task_descriptions)  # type: ignore
        if job:
            if not job.mutable:
                raise AttributeError(f"Can not delete job: {job.id} - it is defined in a system file!")
            # delete all running tasks of this job
            for task in list(filter(lambda x: x.descriptor.id == job.id, self.tasks.values())):
                log.info(f"Job: {job_id}: delete running task: {task.id}")
                await self.delete_running_task(task)
            await self.job_db.delete(job_id)
            descriptions = list(self.task_descriptions)
            descriptions.remove(job)
            self.task_descriptions = descriptions
            await self.update_trigger(job, register=False)
        return job

    # endregion

    # region maintain running tasks

    async def time_triggered(self, descriptor: TaskDescription, trigger: TimeTrigger) -> None:
        log.info(f"Task {descriptor.name} triggered by time: {trigger.cron_expression}")
        await self.start_task(descriptor, "time")

    async def check_for_task_to_start_on_message(self, msg: Message) -> None:
        # check if this event triggers any new task
        for trigger, descriptor in self.registered_event_trigger_by_message_type.get(msg.message_type, []):
            if msg.message_type == trigger.message_type:
                comp = trigger.filter_data
                if {key: msg.data.get(key) for key in comp} == comp if comp else True:
                    log.info(f"Event {msg.message_type} triggers task: {descriptor.name}")
                    await self.start_task(descriptor, "event")

    async def handle_event(self, event: Event) -> None:
        # check if any running task want's to handle this event
        for wi in list(self.tasks.values()):
            handled, commands = wi.handle_event(event)
            if handled:
                await self.execute_task_commands(wi, commands, event)

        # check if this event triggers any new task
        await self.check_for_task_to_start_on_message(event)

    # noinspection PyMethodMayBeStatic
    async def handle_action(self, action: Action) -> None:
        await self.check_for_task_to_start_on_message(action)

    async def handle_action_result(
        self, done: Union[ActionDone, ActionError], fn: Callable[[RunningTask], Sequence[TaskCommand]]
    ) -> None:
        wi = self.tasks.get(done.task_id)
        if wi:
            commands = fn(wi)
            await self.execute_task_commands(wi, commands, done)
        else:
            log.warning(
                f"Received an ack for an unknown task={done.task_id} "
                f"event={done.message_type} from={done.subscriber_id}. Ignore."
            )

    async def handle_action_done(self, done: ActionDone) -> None:
        return await self.handle_action_result(done, lambda wi: wi.handle_done(done))

    async def handle_action_error(self, err: ActionError) -> None:
        log.info(f"Received error: {err.error} {err.step_name}:{err.message_type} of {err.task_id}")
        if rt := self.tasks.get(err.task_id):
            await self.handle_action_result(err, lambda wi: wi.handle_error(err))
            rt.info_messages.append(err)
            name = rt.descriptor.name
            await self.event_sender.core_event(CoreEvent.ActionError, {"workflow": name, "message": err.error})
            await self.message_bus.emit_event(
                CoreMessage.ErrorMessage, {"workflow": name, "task": rt.id, "message": err.error}
            )

    async def handle_action_info(self, info: ActionInfo) -> None:
        if rt := self.tasks.get(info.task_id):
            rt.handle_info(info)
            name = rt.descriptor.name
            await self.running_task_db.update_state(rt, info)
            await self.event_sender.core_event(CoreEvent.ActionError, {"workflow": name, "message": info.message})
            if info.level == "error":
                await self.message_bus.emit_event(
                    CoreMessage.ErrorMessage, {"workflow": name, "task": rt.id, "message": info.message}
                )

    async def handle_action_progress(self, info: ActionProgress) -> None:
        if rt := self.tasks.get(info.task_id):  # get the related running task
            if info.step_name == rt.current_step.name:  # make sure this progress belongs to the current step
                log.debug("Received progress: %s", info)
                rt.handle_progress(info)

    async def execute_task_commands(
        self, wi: RunningTask, commands: Sequence[TaskCommand], origin_message: Optional[Message] = None
    ) -> None:
        async def execute_commands() -> None:
            # execute and collect all task commands
            results: Dict[TaskCommand, Any] = {}
            for command in commands:
                try:
                    if isinstance(command, SendMessage):
                        await self.message_bus.emit(command.message)
                        results[command] = None
                    elif isinstance(command, ExecuteOnCLI):
                        ctx = evolve(self.cli_context, env={**command.env, **wi.descriptor.environment})
                        result = await self.cli.execute_cli_command(command.command, stream.list, ctx)  # type: ignore
                        results[command] = result
                    else:
                        raise AttributeError(f"Does not understand this command: {wi.descriptor.name}:  {command}")
                except Exception as ex:
                    log.info(f"Error executing command: {command} {ex}")
                    results[command] = ex

            # The descriptor might be removed in the meantime. If this is the case stop execution.
            if wi.descriptor_alive:
                active_before_result = wi.is_active
                # before we move on, we need to store the current state of the task (or delete if it is done)
                await self.store_running_task_state(wi, origin_message)
                # inform the task about the result, which might trigger new tasks to execute
                new_commands = wi.handle_command_results(results)
                if new_commands:
                    # note: recursion depth is defined by the number of steps in a job description and should be safe.
                    await self.execute_task_commands(wi, new_commands)
                elif active_before_result and not wi.is_active:
                    # if this was the last result the task was waiting for, delete the task
                    await self.store_running_task_state(wi, origin_message)

        async def execute_in_order(task: Task[Any]) -> None:
            # make sure the last execution is finished, before the new execution starts
            await task
            await execute_commands()

        # start execution of commands in own task to not block the task handler
        # note: the task is awaited finally in the timeout handler or context handler shutdown
        wi.update_task = asyncio.create_task(execute_in_order(wi.update_task) if wi.update_task else execute_commands())

    async def store_running_task_state(self, wi: RunningTask, origin_message: Optional[Message] = None) -> None:
        if wi.is_active:
            await self.running_task_db.update_state(wi, origin_message)
        elif wi.id in self.tasks:
            # only here as safeguard: in case of a core restart, the task would be restarted again
            # cleanup happens in the overdue handler
            await self.mark_done_in_database(wi)

    async def list_all_pending_actions_for(self, subscriber: Subscriber) -> List[Action]:
        pending = map(lambda x: x.pending_action_for(subscriber), self.tasks.values())
        return [x for x in pending if x]

    async def mark_done_in_database(self, task: RunningTask) -> None:
        # workflows are kept in database, jobs are deleted
        with suppress(Exception):
            if isinstance(task.descriptor, Job):
                await self.running_task_db.delete(task.id)
            else:
                await self.running_task_db.update_state(task)

    # endregion

    # region periodic task checker

    async def check_running_tasks(self) -> None:
        """
        Called periodically by the system.
        In case there is an overdue task, an action error is injected into the task.
        In case there is progress not emitted, it is send to the message bus.
        """
        for task in list(self.tasks.values()):
            # check if there is any pending progress update to emit
            if pr := task.not_emitted_progress():
                await self.message_bus.emit_event(
                    CoreMessage.ProgressMessage,
                    {"workflow": task.descriptor.name, "task": task.id, "message": pr},
                )
            # check if active tasks are overdue
            if task.is_active:
                if task.current_state.check_timeout():
                    if task.current_step.on_error == StepErrorBehaviour.Continue:
                        current_step = task.current_step.name
                        commands = task.move_to_next_state()
                        log.warning(
                            f"Task {task.id}: {task.descriptor.name} timed out in step "
                            f"{current_step}. Moving on to step: {task.current_step.name}."
                        )
                        await self.execute_task_commands(task, commands)
                    else:
                        log.warning(
                            f"Task {task.id}: {task.descriptor.name} timed out "
                            f"in step {task.current_step.name}. Stop the task."
                        )
                        task.end()
                        await self.store_running_task_state(task)
            # check again for active (might have changed for overdue tasks)
            if not task.is_active:
                if task.update_task and not task.update_task.cancelled():
                    with suppress(Exception, CancelledError):
                        await task.update_task
                await self.delete_running_task(task)
            # if the task is finished, check if there is already the next run to start
            if task.id not in self.tasks and task.descriptor.id in self.start_when_done:
                self.start_when_done.pop(task.descriptor.id, None)
                await self.start_task_directly(task.descriptor, "previous_task_finished")

    # endregion

    # region known task descriptors

    @staticmethod
    def known_jobs() -> List[Job]:
        return []

    @staticmethod
    def known_workflows(config: CoreConfig) -> List[Workflow]:
        def workflow(name: TaskDescriptorId, steps: List[Step]) -> Workflow:
            trigger: List[Trigger] = [EventTrigger(f"start_{name}_workflow")]
            wf_config = config.workflows.get(name)
            if wf_config:
                trigger.append(TimeTrigger(wf_config.schedule))
            return Workflow(uid=name, name=name, steps=steps, triggers=trigger, on_surpass=TaskSurpassBehaviour.Wait)

        collect_steps = [
            Step("pre_collect", PerformAction("pre_collect"), timedelta(seconds=10)),
            Step("collect", PerformAction("collect"), timedelta(seconds=10)),
            Step("wait_for_graph_merged", WaitForCollectDone(), timedelta(minutes=10)),
            Step("merge_outer_edges", PerformAction("merge_outer_edges"), timedelta(seconds=10)),
            Step("post_collect", PerformAction("post_collect"), timedelta(seconds=10)),
        ]
        cleanup_steps = [
            Step("pre_cleanup_plan", PerformAction("pre_cleanup_plan"), timedelta(seconds=10)),
            Step("cleanup_plan", PerformAction("cleanup_plan"), timedelta(seconds=10)),
            Step("post_cleanup_plan", PerformAction("post_cleanup_plan"), timedelta(seconds=10)),
            Step("pre_cleanup", PerformAction("pre_cleanup"), timedelta(seconds=10)),
            Step("cleanup", PerformAction("cleanup"), timedelta(seconds=10)),
            Step("post_cleanup", PerformAction("post_cleanup"), timedelta(seconds=10)),
        ]
        metrics_steps = [
            Step("pre_generate_metrics", PerformAction("pre_generate_metrics"), timedelta(seconds=10)),
            Step("generate_metrics", PerformAction("generate_metrics"), timedelta(seconds=10)),
            Step("post_generate_metrics", PerformAction("post_generate_metrics"), timedelta(seconds=10)),
        ]
        return [
            workflow(TaskDescriptorId("collect"), collect_steps + metrics_steps),
            workflow(TaskDescriptorId("cleanup"), cleanup_steps + metrics_steps),
            workflow(TaskDescriptorId("metrics"), metrics_steps),
            workflow(TaskDescriptorId("collect_and_cleanup"), collect_steps + cleanup_steps + metrics_steps),
        ]

    # endregion
