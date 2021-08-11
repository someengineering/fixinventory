from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC
from asyncio import Task
from datetime import timedelta, datetime, timezone
from enum import Enum
from typing import List, Dict, Tuple, Set, Optional, Any, Callable, Union, Sequence

from transitions import Machine, State, MachineError

from core.event_bus import EventBus, Event, Action, ActionDone, Message, ActionError
from core.types import Json
from core.util import first, Periodic, interleave, empty, exist, group_by
from core.workflow.scheduler import Scheduler
from core.workflow.subscribers import SubscriptionHandler, Subscriber

log = logging.getLogger(__name__)


class StepErrorBehaviour(Enum):
    """
    This enumeration defines the behaviour of steps in case of an error:
    - Continue: the response from the actor is ignored and the whole workflow instance continues.
    - Stop: the workflow instance will be stopped in case of error
    Default is: Continue
    """

    Continue = 1
    Stop = 2


class WorkflowSurpassBehaviour(Enum):
    """
    This enumeration defines the behaviour of a spawned workflow instance where the previous workflow instance
    of the same workflow is still running.
    - Skip: the new workflow instance is not started and dropped.
    - Parallel: the new workflow instance is started and runs side by side with the already running instance.
    - Replace: the already running workflow instance is stopped and gets replaced by the new one.
    """

    Skip = 1
    Parallel = 2
    Replace = 3


class StepAction(ABC):
    """
    Base class for an action that should be performed in one step.
    """

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, StepAction) else False


class PerformAction(StepAction):
    """
    Perform an action by emitting an action message and wait for all subscribers to respond.
    """

    def __init__(self, message_type: str):
        self.message_type = message_type


class EmitEvent(StepAction):
    """
    Emit a specified event.
    """

    def __init__(self, event: Event):
        self.event = event


class WaitForEvent(StepAction):
    """
    Wait for an event to arrive.
    """

    def __init__(self, message_type: str, filter_data: Optional[Json]):
        self.message_type = message_type
        self.filter_data = filter_data


class ExecuteCommand(StepAction):
    """
    Execute a command in the command interpreter. TBD.
    """

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, ExecuteCommand) else False


class Step:
    """
    Immutable description of a step inside a workflow.
    """

    def __init__(
        self,
        name: str,
        action: StepAction,
        timeout: Optional[timedelta] = None,
        on_error: StepErrorBehaviour = StepErrorBehaviour.Continue,
    ):
        self.name = name
        self.action = action
        self.timeout = timeout if timeout else timedelta(minutes=5)
        self.on_error = on_error

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Step) else False


class Trigger(ABC):
    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Trigger) else False


class EventTrigger(Trigger):
    def __init__(self, message_type: str, filter_data: Optional[Json] = None):
        self.message_type = message_type
        self.filter_data = filter_data


class TimeTrigger(Trigger):
    def __init__(self, cron_expression: str):
        self.cron_expression = cron_expression


class Workflow:
    """
    Immutable description of a complete workflow.
    """

    def __init__(
        self,
        uid: str,
        name: str,
        steps: List[Step],
        triggers: List[Trigger],
        on_surpass: WorkflowSurpassBehaviour = WorkflowSurpassBehaviour.Skip,
    ):
        self.id = uid
        self.name = name
        self.steps = steps
        self.triggers = triggers
        self.on_surpass = on_surpass

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Workflow) else False

    def step_by_name(self, name: str) -> Optional[Step]:
        return first(lambda x: x.name == name, self.steps)


class StepState(State):  # type: ignore
    """
    Base class for all states in a workflow instance.
    There is always a related step definition inside a related workflow instance.
    """

    def __init__(self, step: Step, instance: WorkflowInstance):
        super().__init__(step.name, "begin_step")
        self.step = step
        self.instance = instance
        self.timed_out = False

    def current_step_done(self) -> bool:
        """
        Override this method in deriving classes to define, when this state is done.
        :return: True when this state is done otherwise false.
        """
        return not self.timed_out

    def messages_to_emit(self) -> Sequence[Message]:
        """
        Override this method in deriving classes to emit messages when this state is entered.
        :return: all messages to emit when this state is entered.
        """
        return []

    def timeout(self) -> timedelta:
        """
        Define the timeout of this step.
        Defaults to the configured step timeout, but can be overridden in subsequent classes.
        :return: the timeout of this step.
        """
        return self.step.timeout

    def handle_event(self, event: Event) -> bool:
        """
        Return true if the internal state of the fsm has changed by this event.
        Note: all events received by the system are provided to this state.
              The state has to decide if this event is meaningful or not.
        """
        return False

    def check_timeout(self) -> bool:
        """
        Return true if the internal state of the fsm has changed by this event.
        This method is called periodically by the workflow cleaner task.
        """
        if (self.instance.step_started_at + self.timeout()) < datetime.now(timezone.utc):
            self.timed_out = True
            return True
        return False

    @staticmethod
    def from_step(step: Step, instance: WorkflowInstance) -> StepState:
        """
        Create the related state based on the given step and workflow instance.
        """
        if isinstance(step.action, PerformAction):
            return PerformActionState(step.action, step, instance)
        elif isinstance(step.action, EmitEvent):
            return EmitEventState(step.action, step, instance)
        elif isinstance(step.action, WaitForEvent):
            return WaitForEventState(step.action, step, instance)
        elif isinstance(step.action, ExecuteCommand):
            # TODO: add action
            return StepState(step, instance)
        else:
            raise AttributeError(f"No mapping for {type(step.action).__name__}")


class PerformActionState(StepState):
    """
    This state emits an action when started and then waits for all actors to respond with a done message.
    State is done, when all subscribers with expected answer send a done message.
    """

    def __init__(self, perform: PerformAction, step: Step, instance: WorkflowInstance):
        super().__init__(step, instance)
        self.perform = perform

    def current_step_done(self) -> bool:
        """
        This state is done, when we received an ack or an error from every subscriber.
        The step behavior defines how to deal in case of an error.
        """
        msg_type = self.perform.message_type
        in_step: Set[str] = {
            x.subscriber_id
            for x in self.instance.received_messages
            if isinstance(x, (ActionDone, ActionError)) and x.step_name == self.step.name
        }
        subscriber = self.instance.subscribers_by_event.get(msg_type, [])
        missing = {x.id for x in subscriber if x[msg_type].wait_for_completion} - in_step
        return self.timed_out or (not self.instance.is_error and empty(missing))

    def timeout(self) -> timedelta:
        """
        The timeout is extended to the longest timeout of all subscribers falling back to the step timeout.
        """
        msg_type = self.perform.message_type
        max_timeout = self.step.timeout
        for subscriber in self.instance.subscribers_by_event.get(msg_type, []):
            subscription = subscriber.subscriptions[msg_type]
            to = subscription.timeout
            # only extend the timeout, when the subscriber is blocking and has a longer timeout
            max_timeout = max_timeout if not subscription.wait_for_completion or max_timeout > to else to
        return max_timeout

    def messages_to_emit(self) -> Sequence[Message]:
        """
        When the state is entered, emit the action message and inform all actors.
        """
        return [Action(self.perform.message_type, self.instance.id, self.step.name)]


class WaitForEventState(StepState):
    def __init__(self, perform: WaitForEvent, step: Step, instance: WorkflowInstance):
        super().__init__(step, instance)
        self.perform = perform

    def current_step_done(self) -> bool:
        """
        This step is done, when the event it is waiting for has arrived.
        """
        return self.timed_out or exist(
            lambda x: isinstance(x, Event) and x.message_type == self.perform.message_type,
            self.instance.received_messages,
        )

    def handle_event(self, event: Event) -> bool:
        """
        Check if the provided event is the one this step is waiting for.
        The event has to have the same message_type and the provided filter has to apply.
        """

        def filter_applies() -> bool:
            comp = self.perform.filter_data
            if comp:
                return {key: event.data.get(key) for key in comp} == comp
            else:
                return True

        if event.message_type == self.perform.message_type and filter_applies():
            self.instance.received_messages.append(event)
            return True
        return False


class EmitEventState(StepState):
    def __init__(self, emit: EmitEvent, step: Step, instance: WorkflowInstance):
        super().__init__(step, instance)
        self.emit = emit

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.emit.event]


class StartState(StepState):
    def __init__(self, instance: WorkflowInstance):
        self.event = Event("workflow_start")
        super().__init__(Step("workflow_start", EmitEvent(self.event)), instance)

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.event]


class EndState(StepState):
    """
    This state marks the end of the workflow.
    """

    def __init__(self, instance: WorkflowInstance):
        self.event = Event("workflow_end")
        super().__init__(Step("workflow_end", EmitEvent(self.event)), instance)

    def is_error(self) -> bool:
        return self.instance.is_error

    def current_step_done(self) -> bool:
        return False

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.event]


class WorkflowInstance:
    @staticmethod
    def empty(
        workflow: Workflow, subscriber_by_event: Dict[str, List[Subscriber]]
    ) -> Tuple[WorkflowInstance, Sequence[Message]]:
        assert len(workflow.steps) > 0, "Workflow needs at least one step!"
        uid = str(uuid.uuid1())
        wi = WorkflowInstance(uid, workflow, subscriber_by_event)
        messages = [Event("workflow_started", data={"workflow": workflow.name}), *wi.move_to_next_state()]
        return wi, messages

    def __init__(self, uid: str, workflow: Workflow, subscribers_by_event: Dict[str, List[Subscriber]]):
        self.id = uid
        self.is_error = False
        self.workflow = workflow
        self.received_messages: List[Message] = []
        self.subscribers_by_event = subscribers_by_event
        self.step_started_at = datetime.now(timezone.utc)

        steps = [StepState.from_step(step, self) for step in workflow.steps]
        start = StartState(self)
        end = EndState(self)
        states: List[StepState] = [start, *steps, end]
        self.machine = Machine(self, states, start, auto_transitions=False, queued=True)

        for current_state, next_state in interleave(states):
            self.machine.add_transition(
                "_next_state", current_state.name, next_state.name, [current_state.current_step_done]
            )
            self.machine.add_transition("_to_err", current_state.name, end.name, [end.is_error])

    def move_to_next_state(self) -> Sequence[Message]:
        def next_state() -> bool:
            try:
                # this method is defined dynamically by transitions
                last_state = self.current_state
                result: bool = self._next_state()  # type: ignore
                # safe guard: if state transition does not change the state
                if result and self.current_state is last_state:
                    return False
                return result
            except MachineError:
                return False

        resulting_events: List[Message] = []
        while next_state():
            resulting_events.extend(self.current_state.messages_to_emit())
        return resulting_events

    @property
    def current_state(self) -> StepState:
        return self.machine.get_state(self.state)  # type: ignore

    @property
    def current_step(self) -> Step:
        return self.current_state.step

    @property
    def is_active(self) -> bool:
        return not isinstance(self.current_state, EndState)

    def handle_event(self, event: Event) -> Tuple[bool, Sequence[Message]]:
        if self.current_state.handle_event(event):
            return True, self.move_to_next_state()
        else:
            return False, []

    def handle_done(self, done: ActionDone) -> Sequence[Message]:
        self.received_messages.append(done)
        return self.move_to_next_state()

    def handle_error(self, error: ActionError) -> Sequence[Message]:
        """
        An action could not be performed - the subscriber returned an error.
        Such a message only makes sense in a PerformAction step.
        Whether or not this event leads to a state change is decided by the current state.
        Whether or not this leads to the end of this workflow instance is decided by the current step error behaviour.
        """
        if not isinstance(self.current_step.action, PerformAction):
            log.info(
                f"Received action error {error} but the current step is "
                f"{type(self.current_step.action).__name__}. Ignore."
            )
            return []
        elif self.is_active and self.current_step.on_error == StepErrorBehaviour.Continue:
            self.received_messages.append(error)
            return self.move_to_next_state()
        else:
            log.info(
                f"Workflow: {error.workflow_instance_id}: Subscriber {error.subscriber_id} could not handle action: "
                f"{error.message_type} because: {error.error}. Stop this workflow."
            )
            self.end()
            return []

    def end(self) -> None:
        """
        If this method is called, the workflow instance is marked as failed and moves to the end state.
        Use this method to abort a workflow instance.
        """
        self.is_error = True
        self._to_err()  # type: ignore

    def ack_for(self, message_type: str, subscriber: Subscriber) -> Optional[Message]:
        """
        Return the ack received ack for the given message_type of the given subscriber or None.
        """

        def relevant_ack(message: Message) -> bool:
            return (
                isinstance(message, (ActionDone, ActionError))
                and message.message_type == message_type
                and message.subscriber_id == subscriber.id
            )

        return first(relevant_ack, self.received_messages)

    def pending_action_for(
        self, subscriber_by_event: Dict[str, List[Subscriber]], subscriber: Subscriber
    ) -> Optional[Action]:
        """
        In case this workflow is waiting for an action result from the given subscriber,
        the relevant action is returned.
        """
        state = self.current_state
        if isinstance(state, PerformActionState):
            message_type = state.perform.message_type
            subscriptions = subscriber_by_event.get(message_type, [])
            if subscriber in subscriptions and self.ack_for(message_type, subscriber) is None:
                return Action(message_type, self.id, state.step.name)
        return None

    def begin_step(self) -> None:
        log.info(f"Workflow {self.id}: begin step is: {self.current_step.name}")
        # update the step started time, whenever a new state is entered
        self.step_started_at = datetime.now(timezone.utc)


class WorkflowHandler:
    def __init__(self, event_bus: EventBus, subscription_handler: SubscriptionHandler, scheduler: Scheduler):
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

    async def start(self) -> None:
        # Step1: define all workflows in code: later it will be persisted in database
        self.workflows = [
            Workflow(
                "test",
                "test",
                [
                    Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
                    Step("act", PerformAction("collect"), timedelta(seconds=10)),
                    Step("done", PerformAction("collect_done"), timedelta(seconds=10)),
                ],
                [EventTrigger("start_test_workflow"), TimeTrigger("5 * * * *")],
            )
        ]

        await self.timeout_watcher.start()
        # TODO: load and keep all workflow instances

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
                    except BaseException as ex:
                        log.error(f"Could not handle event {message} - give up.", ex)

        self.running_task = asyncio.create_task(listen_to_event_bus())

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
                existing.end()
                await self.after_handled(existing, [])
            elif workflow.on_surpass == WorkflowSurpassBehaviour.Parallel:
                # new workflow instance can be started
                pass
            else:
                raise AttributeError(f"Surpass behaviour not handled: {workflow.on_surpass}")

        wi, messages = WorkflowInstance.empty(workflow, self.subscription_handler.subscribers_by_event)
        if wi.is_active:
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
                await self.after_handled(wi, messages_to_emit)
                # TODO: state of the wi has changed: store event

        # check if this event triggers any new workflow
        for trigger, workflow in self.registered_event_trigger_by_message_type.get(event.message_type, []):
            if event.message_type == trigger.message_type:
                comp = trigger.filter_data
                if {key: event.data.get(key) for key in comp} == comp if comp else True:
                    await self.start_workflow(workflow)

    # noinspection PyMethodMayBeStatic
    async def handle_action(self, action: Action) -> None:
        # TODO: maybe we should store this action in database as well
        log.info(f"Received action: {action.step_name}:{action.message_type} of {action.workflow_instance_id}")

    async def handle_action_result(
        self,
        done: Union[ActionDone, ActionError],
        fn: Callable[[WorkflowInstance], Sequence[Message]],
    ) -> None:
        wi = self.workflow_instances.get(done.workflow_instance_id)
        if wi:
            messages = fn(wi)
            return await self.after_handled(wi, messages)
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

    async def after_handled(self, wi: WorkflowInstance, messages_to_emit: Sequence[Message]) -> None:
        for event in messages_to_emit:
            await self.event_bus.emit(event)
        if not wi.is_active:
            log.info(f"Workflow instance {wi.id} is done and will be removed.")
            # TODO: remove from database
            del self.workflow_instances[wi.id]

    async def list_all_pending_actions_for(self, subscriber: Subscriber) -> List[Action]:
        subscriptions = self.subscription_handler.subscribers_by_event
        pending = map(lambda x: x.pending_action_for(subscriptions, subscriber), self.workflow_instances.values())
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
                    # TODO: store data since state has changed
