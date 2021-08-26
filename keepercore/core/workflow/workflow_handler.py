from __future__ import annotations

import asyncio
import logging
from asyncio import Task, CancelledError
from datetime import timedelta
from typing import List, Dict, Tuple, Optional, Any, Callable, Union, Sequence

from core.db.workflowinstancedb import WorkflowInstanceData, WorkflowInstanceDb
from core.event_bus import EventBus, Event, Action, ActionDone, Message, ActionError
from core.util import first, Periodic, group_by
from core.workflow.model import Subscriber
from core.workflow.scheduler import Scheduler
from core.workflow.subscribers import SubscriptionHandler
from core.workflow.workflows import (
    Workflow,
    WorkflowInstance,
    EventTrigger,
    TimeTrigger,
    WorkflowSurpassBehaviour,
    PerformAction,
    Step,
)

log = logging.getLogger(__name__)


class WorkflowHandler:
    def __init__(
        self,
        workflow_instance_db: WorkflowInstanceDb,
        event_bus: EventBus,
        subscription_handler: SubscriptionHandler,
        scheduler: Scheduler,
    ):
        self.workflow_instance_db = workflow_instance_db
        self.event_bus = event_bus
        self.subscription_handler = subscription_handler
        self.scheduler = scheduler
        self.workflows: List[Workflow] = []
        self.workflow_instances: Dict[str, WorkflowInstance] = {}
        self.running_task: Optional[Task[Any]] = None
        self.timeout_watcher = Periodic("workflow_timeout_watcher", self.check_overdue_workflows, timedelta(seconds=10))
        self.registered_event_trigger: List[Tuple[EventTrigger, Workflow]] = []
        self.registered_event_trigger_by_message_type: Dict[str, List[Tuple[EventTrigger, Workflow]]] = {}

    async def update_trigger(self, workflow: Workflow, register: bool = True) -> None:
        # safeguard: unregister all event trigger of this workflow
        for existing in (tup for tup in self.registered_event_trigger if workflow.id == tup[1].id):
            self.registered_event_trigger.remove(existing)
        # safeguard: unregister all schedule trigger of this workflow
        for job in self.scheduler.list_jobs():
            if str(job.id).startswith(workflow.id):
                job.remove()
        # add all triggers
        if register:
            for trigger in workflow.triggers:
                if isinstance(trigger, EventTrigger):
                    self.registered_event_trigger.append((trigger, workflow))
                if isinstance(trigger, TimeTrigger):
                    uid = f"{workflow.id}_{trigger.cron_expression}"
                    name = f"Trigger for workflow {workflow.id} on cron expression {trigger.cron_expression}"
                    self.scheduler.cron(uid, name, trigger.cron_expression, self.time_triggered, workflow, trigger)
        # recompute the lookup table
        self.registered_event_trigger_by_message_type = group_by(
            lambda t: t[0].message_type, self.registered_event_trigger
        )

    async def start_interrupted_workflow_instances(self) -> list[WorkflowInstance]:
        workflows = {w.id: w for w in self.workflows}

        def reset_state(wi: WorkflowInstance, data: WorkflowInstanceData) -> WorkflowInstance:
            # reset the received messages
            wi.received_messages = data.received_messages  # type: ignore
            # move the fsm into the last known state
            wi.machine.set_state(data.current_state_name)
            # import state of the current step
            wi.current_state.import_state(data.current_state_snapshot)
            # ignore all messages that would be emitted
            wi.move_to_next_state()
            return wi

        instances: list[WorkflowInstance] = []
        async for data in self.workflow_instance_db.all():
            workflow = workflows.get(data.workflow_id)
            if workflow:
                instance = WorkflowInstance(data.id, workflow, self.subscription_handler.subscribers_by_event)
                instances.append(reset_state(instance, data))
            else:
                log.warning(f"No workflow with this id found: {data.workflow_id}. Remove instance data.")
                await self.workflow_instance_db.delete(data.id)
        return instances

    async def start(self) -> None:
        # Step1: define all workflows in code: later it will be persisted in database
        self.workflows = self.known_workflows()

        # load and restore all workflow instances
        self.workflow_instances = {wi.id: wi for wi in await self.start_interrupted_workflow_instances()}

        await self.timeout_watcher.start()

        for workflow in self.workflows:
            await self.update_trigger(workflow)

        async def listen_to_event_bus() -> None:
            with self.event_bus.subscribe("workflow_manager") as messages:
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

        self.running_task = asyncio.create_task(listen_to_event_bus())

    async def stop(self) -> None:
        for workflow in self.workflows:
            await self.update_trigger(workflow, register=False)
        await self.timeout_watcher.stop()
        if self.running_task:
            self.running_task.cancel()
            try:
                await self.running_task
            except CancelledError:
                log.info("task has been cancelled")

    async def time_triggered(self, workflow: Workflow, trigger: TimeTrigger) -> None:
        log.info(f"Workflow {workflow.name} triggered by time: {trigger.cron_expression}")
        return await self.start_workflow(workflow)

    async def start_workflow(self, workflow: Workflow) -> None:
        existing = first(lambda x: x.workflow.id == workflow.id, self.workflow_instances.values())
        if existing:
            if workflow.on_surpass == WorkflowSurpassBehaviour.Skip:
                log.info(
                    f"Workflow {workflow.name} has been triggered. Since the last job is not finished, "
                    f"the execution will be skipped, as defined by the workflow"
                )
                return None
            elif workflow.on_surpass == WorkflowSurpassBehaviour.Replace:
                log.info(f"New workflow {workflow.name} should replace existing run: {existing.id}.")
                existing.end()
                await self.after_handled(existing, [])
            elif workflow.on_surpass == WorkflowSurpassBehaviour.Parallel:
                log.info(f"New workflow {workflow.name} will race with existing run {existing.id}.")
            else:
                raise AttributeError(f"Surpass behaviour not handled: {workflow.on_surpass}")

        wi, messages = WorkflowInstance.empty(workflow, self.subscription_handler.subscribers_by_event)
        if wi.is_active:
            log.info(f"Start new workflow: {workflow.name} with id {wi.id}")
            # store initial state in database
            await self.workflow_instance_db.insert(wi)
            self.workflow_instances[wi.id] = wi
        else:
            log.info(f"Workflow {workflow.name} was triggered and ran directly to the end. Ignore.")

        for message in messages:
            await self.event_bus.emit(message)

    async def handle_event(self, event: Event) -> None:
        # check if any running workflow instance want's to handle this event
        for wi in self.workflow_instances.values():
            handled, messages_to_emit = wi.handle_event(event)
            if handled:
                await self.after_handled(wi, messages_to_emit, event)

        # check if this event triggers any new workflow
        for trigger, workflow in self.registered_event_trigger_by_message_type.get(event.message_type, []):
            if event.message_type == trigger.message_type:
                comp = trigger.filter_data
                if {key: event.data.get(key) for key in comp} == comp if comp else True:
                    log.info(f"Event {event.message_type} triggers workflow: {workflow.name}")
                    await self.start_workflow(workflow)

    # noinspection PyMethodMayBeStatic
    async def handle_action(self, action: Action) -> None:
        log.info(f"Received action: {action.step_name}:{action.message_type} of {action.workflow_instance_id}")

    async def handle_action_result(
        self,
        done: Union[ActionDone, ActionError],
        fn: Callable[[WorkflowInstance], Sequence[Message]],
    ) -> None:
        wi = self.workflow_instances.get(done.workflow_instance_id)
        if wi:
            messages = fn(wi)
            return await self.after_handled(wi, messages, done)
        else:
            log.warning(
                f"Received an ack for an unknown workflow={done.workflow_instance_id} "
                f"event={done.message_type} from={done.subscriber_id}. Ignore."
            )

    async def handle_action_done(self, done: ActionDone) -> None:
        return await self.handle_action_result(done, lambda wi: wi.handle_done(done))

    async def handle_action_error(self, err: ActionError) -> None:
        log.info(f"Received error: {err.error} {err.step_name}:{err.message_type} of {err.workflow_instance_id}")
        return await self.handle_action_result(err, lambda wi: wi.handle_error(err))

    async def after_handled(
        self, wi: WorkflowInstance, messages_to_emit: Sequence[Message], origin_message: Optional[Message] = None
    ) -> None:
        for event in messages_to_emit:
            await self.event_bus.emit(event)

        if wi.is_active:
            await self.workflow_instance_db.update_state(wi, origin_message)
        else:
            log.info(f"Workflow instance {wi.id} is done and will be removed.")
            await self.workflow_instance_db.delete(wi.id)
            del self.workflow_instances[wi.id]

    async def list_all_pending_actions_for(self, subscriber: Subscriber) -> List[Action]:
        pending = map(lambda x: x.pending_action_for(subscriber), self.workflow_instances.values())
        return [x for x in pending if x]

    async def check_overdue_workflows(self) -> None:
        """
        Called periodically by the system.
        In case there is an overdue workflow instance, an action error is injected into the workflow.
        """
        for wi in list(self.workflow_instances.values()):
            if wi.is_active:  # workflow instance is still active
                if wi.current_state.check_timeout():
                    messages = wi.move_to_next_state()
                    await self.after_handled(wi, messages)

    @staticmethod
    def known_workflows() -> list[Workflow]:
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
