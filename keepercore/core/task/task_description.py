from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import timedelta, datetime, timezone
from enum import Enum
from typing import List, Dict, Tuple, Set, Optional, Any, Sequence, MutableSequence, Callable

from transitions import Machine, State, MachineError

from core.event_bus import Event, Action, ActionDone, Message, ActionError
from core.types import Json
from core.util import first, interleave, empty, exist, identity
from core.task.model import Subscriber

log = logging.getLogger(__name__)


class StepErrorBehaviour(Enum):
    """
    This enumeration defines the behaviour of steps in case of an error:
    - Continue: the response from the actor is ignored and the whole task continues.
    - Stop: the task will be stopped in case of error
    Default is: Continue
    """

    Continue = 1
    Stop = 2


class TaskSurpassBehaviour(Enum):
    """
    This enumeration defines the behaviour of a spawned task where the previous task
    of the same task description is still running.
    - Skip: the new task is not started and dropped.
    - Parallel: the new task is started and runs side by side with the already running instance.
    - Replace: the already running task is stopped and gets replaced by the new one.
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
    Immutable description of a step inside a task.
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


class TaskDescription(ABC):
    def __init__(self, uid: str, name: str):
        self.id = uid
        self.name = name

    def step_by_name(self, name: str) -> Optional[Step]:
        return first(lambda x: x.name == name, self.steps)

    @property
    @abstractmethod
    def steps(self) -> Sequence[Step]:
        pass

    @property
    @abstractmethod
    def triggers(self) -> Sequence[Trigger]:
        pass

    @property
    @abstractmethod
    def on_surpass(self) -> TaskSurpassBehaviour:
        pass

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, TaskDescription) else False


class Job(TaskDescription):
    def __init__(self, uid: str, name: str, command: ExecuteCommand, triggers: Sequence[Trigger]):
        super().__init__(uid, name)
        self.command = command
        self._triggers = triggers

    @property
    def steps(self) -> Sequence[Step]:
        return [Step("execute", self.command)]

    @property
    def triggers(self) -> Sequence[Trigger]:
        return self._triggers

    @property
    def on_surpass(self) -> TaskSurpassBehaviour:
        return TaskSurpassBehaviour.Parallel


class Workflow(TaskDescription):
    """
    Immutable description of a complete workflow.
    """

    def __init__(
        self,
        uid: str,
        name: str,
        steps: Sequence[Step],
        triggers: Sequence[Trigger],
        on_surpass: TaskSurpassBehaviour = TaskSurpassBehaviour.Skip,
    ) -> None:
        super().__init__(uid, name)
        self._steps = steps
        self._triggers = triggers
        self._on_surpass = on_surpass

    @property
    def steps(self) -> Sequence[Step]:
        return self._steps

    @property
    def triggers(self) -> Sequence[Trigger]:
        return self._triggers

    @property
    def on_surpass(self) -> TaskSurpassBehaviour:
        return self._on_surpass


class StepState(State):  # type: ignore
    """
    Base class for all states in a task.
    There is always a related step definition inside a related task definition.
    """

    def __init__(self, step: Step, instance: RunningTask):
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
        This method is called periodically by the cleaner task.
        """
        if (self.instance.step_started_at + self.timeout()) < datetime.now(timezone.utc):
            self.timed_out = True
            return True
        return False

    @staticmethod
    def from_step(step: Step, instance: RunningTask) -> StepState:
        """
        Create the related state based on the given step and task description.
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

    def step_started(self) -> None:
        """
        This method is called when the fsm enters this state.
        Override in subsequent classes, if action is required in such a scenario.
        """

    # noinspection PyMethodMayBeStatic
    def export_state(self) -> Json:
        """
        This method is called when the state of the task needs to be persisted.
        Since each state in the FSM can have it's own schema, we export a generic json blob here,
        that has to be interpreted during import_state.
        :return: json representation of this state. empty by default.
        """
        return {}

    def import_state(self, js: Json) -> None:
        """
        This method is called when the execution of this task has been interrupted by a restart.
        The last known state is persisted to some durable storage and imported in the startup phase.

        :param js: the same json that was exported with export_state()
        """


class PerformActionState(StepState):
    """
    This state emits an action when started and then waits for all actors to respond with a done message.
    State is done, when all subscribers with expected answer send a done message.
    """

    def __init__(self, perform: PerformAction, step: Step, instance: RunningTask):
        super().__init__(step, instance)
        self.perform = perform
        self.wait_for = self.instance.subscribers_by_event().get(perform.message_type, [])

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
        subscriber = self.wait_for
        missing = {x.id for x in subscriber if x[msg_type].wait_for_completion} - in_step
        return self.timed_out or (not self.instance.is_error and empty(missing))

    def timeout(self) -> timedelta:
        """
        The timeout is extended to the longest timeout of all subscribers falling back to the step timeout.
        """
        msg_type = self.perform.message_type
        max_timeout = self.step.timeout
        for subscriber in self.instance.subscribers_by_event().get(msg_type, []):
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

    def step_started(self) -> None:
        # refresh the list of subscribers when the step has started
        self.wait_for = self.instance.subscribers_by_event().get(self.perform.message_type, [])

    def export_state(self) -> Json:
        return {"wait_for": [a.id for a in self.wait_for]}

    def import_state(self, js: Json) -> None:
        existing = {s.id: s for s in self.instance.subscribers_by_event().get(self.perform.message_type, [])}
        wait_for = js.get("wait_for", [])
        # filter all existing subscriber from the list of subscribers to wait_for
        self.wait_for = list(filter(identity, (existing.get(sid) for sid in wait_for)))  # type: ignore


class WaitForEventState(StepState):
    def __init__(self, perform: WaitForEvent, step: Step, instance: RunningTask):
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
    def __init__(self, emit: EmitEvent, step: Step, instance: RunningTask):
        super().__init__(step, instance)
        self.emit = emit

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.emit.event]


class StartState(StepState):
    def __init__(self, instance: RunningTask):
        self.event = Event("task_start")
        super().__init__(Step("task_start", EmitEvent(self.event)), instance)

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.event]


class EndState(StepState):
    """
    This state marks the end of the task.
    """

    def __init__(self, instance: RunningTask):
        self.event = Event("task_end")
        super().__init__(Step("task_end", EmitEvent(self.event)), instance)

    def is_error(self) -> bool:
        return self.instance.is_error

    def current_step_done(self) -> bool:
        return False

    def messages_to_emit(self) -> Sequence[Message]:
        return [self.event]


class RunningTask:
    @staticmethod
    def empty(
        task: TaskDescription, subscriber_by_event: Callable[[], Dict[str, List[Subscriber]]]
    ) -> Tuple[RunningTask, Sequence[Message]]:
        assert len(task.steps) > 0, "TaskDescription needs at least one step!"
        uid = str(uuid.uuid1())
        wi = RunningTask(uid, task, subscriber_by_event)
        messages = [Event("task_started", data={"task": task.name}), *wi.move_to_next_state()]
        return wi, messages

    def __init__(
        self, uid: str, task: TaskDescription, subscribers_by_event: Callable[[], Dict[str, List[Subscriber]]]
    ):
        self.id = uid
        self.is_error = False
        self.task = task
        self.received_messages: MutableSequence[Message] = []
        self.subscribers_by_event = subscribers_by_event
        self.step_started_at = datetime.now(timezone.utc)

        steps = [StepState.from_step(step, self) for step in task.steps]
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
                result: bool = self._next_state()  # type: ignore # pylint: disable=no-member
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
        return self.machine.get_state(self.state)  # type: ignore # pylint: disable=no-member

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
        Whether or not this leads to the end of this task is decided by the current step error behaviour.
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
                f"Task: {error.task_id}: Subscriber {error.subscriber_id} could not handle action: "
                f"{error.message_type} because: {error.error}. Stop this task."
            )
            self.end()
            return []

    def end(self) -> None:
        """
        If this method is called, the task is marked as failed and moves to the end state.
        Use this method to abort a task.
        """
        self.is_error = True
        self._to_err()  # type: ignore # pylint: disable=no-member

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

    def pending_action_for(self, subscriber: Subscriber) -> Optional[Action]:
        """
        In case this task is waiting for an action result from the given subscriber,
        the relevant action is returned.
        """
        state = self.current_state
        if isinstance(state, PerformActionState):
            message_type = state.perform.message_type
            subscriptions = state.wait_for
            if subscriber in subscriptions and self.ack_for(message_type, subscriber) is None:
                return Action(message_type, self.id, state.step.name)
        return None

    def begin_step(self) -> None:
        log.info(f"Task {self.id}: begin step is: {self.current_step.name}")
        # update the step started time, whenever a new state is entered
        self.step_started_at = datetime.now(timezone.utc)
        self.current_state.step_started()
