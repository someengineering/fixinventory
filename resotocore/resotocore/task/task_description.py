from __future__ import annotations

import logging
import uuid
from abc import ABC
from contextlib import suppress
from datetime import timedelta, datetime
from enum import Enum
from typing import Optional, Any, Sequence, MutableSequence, Callable, Dict, List, Set, Tuple, Union

from attrs import define

from asyncio import Task

from apscheduler.triggers.cron import CronTrigger
from frozendict import frozendict
from jsons import set_deserializer, set_serializer
from transitions import Machine, State, MachineError

from resotocore.ids import TaskId
from resotocore.task.model import Subscriber
from resotocore.message_bus import Event, Action, ActionDone, Message, ActionError, ActionInfo, ActionProgress
from resotocore.model.typed_model import to_json, from_js, to_js
from resotocore.types import Json
from resotocore.util import first, interleave, empty, exist, identity, utc, utc_str
from resotocore.ids import SubscriberId, TaskDescriptorId
from resotolib.core.progress import ProgressTree, Progress, ProgressDone

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
    - Wait: wait for the current job to finish and then execute.
            Note: the same task description can only be enqueued once, not multiple times.
    """

    Skip = 1
    Parallel = 2
    Replace = 3
    Wait = 4


# region StepAction: what to do in one step


class StepAction(ABC):
    """
    Base class for an action that should be performed in one step.
    """

    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, StepAction) else False

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> StepAction:
        if "wait_for_message_type" in json:
            return from_js(json, WaitForEvent)
        elif "message_type" in json:
            return from_js(json, PerformAction)
        elif "command" in json:
            return from_js(json, ExecuteCommand)
        elif "event" in json:
            return from_js(json, EmitEvent)
        else:
            raise AttributeError(f"Can not deserialize {json} into StepAction!")


# All actions that need to be restarted from start when the action was interrupted
class RestartAgainStepAction(StepAction):
    pass


@define(order=True, hash=True, frozen=True)
class PerformAction(StepAction):
    # Perform an action by emitting an action message and wait for all subscribers to respond.
    message_type: str


@define(order=True, hash=True, frozen=True)
class EmitEvent(StepAction):
    # Emit this event
    event: Event


@define(order=True, hash=True, frozen=True)
class WaitForEvent(StepAction):
    # Wait for this event to arrive
    wait_for_message_type: str
    filter_data: Optional[Json] = None


@define(order=True, hash=True, frozen=True)
class ExecuteCommand(RestartAgainStepAction):
    # Execute this command in the command interpreter.
    command: str


# endregion

# region StepCommand: resulting commands that get executed. Note that one action can create multiple commands.


class TaskCommand(ABC):
    def __eq__(self, other: Any) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, TaskCommand) else False

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> TaskCommand:
        if "message" in json:
            return from_js(json, SendMessage)
        elif "command" in json:
            return from_js(json, ExecuteOnCLI)
        else:
            raise AttributeError(f"Can not deserialize {json} into TaskCommand!")


@define(order=True, hash=True, frozen=True)
class SendMessage(TaskCommand):
    message: Message


@define(order=True, hash=True, frozen=True)
class ExecuteOnCLI(TaskCommand):
    command: str
    # noinspection PyUnresolvedReferences
    env: frozendict


# endregion

# region Trigger: when a task should be triggered
class Trigger(ABC):
    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Trigger) else False

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> Trigger:
        if "cron_expression" in json:
            return from_js(json, TimeTrigger)
        elif "message_type" in json:
            return from_js(json, EventTrigger)
        else:
            raise AttributeError(f"Can not deserialize {json} into StepAction!")


@define(order=True, hash=True, frozen=True)
class EventTrigger(Trigger):
    message_type: str
    filter_data: Optional[Json] = None


@define(order=True, hash=True, frozen=True)
class TimeTrigger(Trigger):
    cron_expression: str

    def __attrs_post_init__(self) -> None:
        # make sure the time trigger is valid
        CronTrigger.from_crontab(self.cron_expression)


# endregion


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


class TaskDescription(ABC):
    def __init__(
        self,
        uid: TaskDescriptorId,
        name: str,
        steps: Sequence[Step],
        triggers: Sequence[Trigger],
        on_surpass: TaskSurpassBehaviour,
        environment: Optional[Dict[str, str]],
        mutable: bool,
    ):
        self.id = uid
        self.name = name
        self.steps = steps
        self.triggers = triggers
        self.on_surpass = on_surpass
        self.environment = environment if environment else {}
        self.mutable = mutable

    def step_by_name(self, name: str) -> Optional[Step]:
        return first(lambda x: x.name == name, self.steps)

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, TaskDescription) else False


class Job(TaskDescription):
    def __init__(
        self,
        uid: TaskDescriptorId,
        command: ExecuteCommand,
        timeout: timedelta,
        trigger: Optional[Trigger] = None,
        wait: Optional[Tuple[EventTrigger, timedelta]] = None,
        environment: Optional[Dict[str, str]] = None,
        mutable: bool = True,
        active: bool = True,
    ):
        steps: List[Step] = []
        if wait:
            wait_trigger, wait_timeout = wait
            action = WaitForEvent(wait_trigger.message_type, wait_trigger.filter_data)
            steps.append(Step("wait", action, wait_timeout, StepErrorBehaviour.Stop))
        steps.append(Step("execute", command, timeout, StepErrorBehaviour.Stop))
        start_trigger = [trigger] if active and trigger else []
        super().__init__(uid, uid, steps, start_trigger, TaskSurpassBehaviour.Wait, environment, mutable)
        self.command = command
        self.timeout = timeout
        self.trigger = trigger
        self.wait = wait
        self.active = active

    @staticmethod
    def to_json(o: Job, **_: object) -> Json:
        wait = {"wait_trigger": to_js(o.wait[0]), "wait_timeout": to_json(o.wait[1])} if o.wait else {}
        env = {"environment": o.environment} if o.environment else {}
        return {
            "id": o.id,
            "name": o.name,
            "command": to_js(o.command),
            "trigger": to_js(o.trigger),
            "timeout": to_json(o.timeout),
            "active": o.active,
            **env,
            **wait,
        }

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> Job:
        maybe_wait = (
            (from_js(json["wait_trigger"], EventTrigger), from_js(json["wait_timeout"], timedelta))
            if "wait_trigger" in json
            else None
        )
        trigger = json.get("trigger")
        return Job(
            json["id"],
            from_js(json["command"], ExecuteCommand),
            from_js(json["timeout"], timedelta),
            from_js(trigger, Trigger) if trigger is not None else None,
            maybe_wait,
            json.get("environment"),
            active=json.get("active", True),  # backward compatibility: in case the prop is missing
        )


class Workflow(TaskDescription):
    """
    Immutable description of a complete workflow.
    """

    def __init__(
        self,
        uid: TaskDescriptorId,
        name: str,
        steps: Sequence[Step],
        triggers: Sequence[Trigger],
        on_surpass: TaskSurpassBehaviour = TaskSurpassBehaviour.Skip,
        environment: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(uid, name, steps, triggers, on_surpass, environment, mutable=False)
        self._triggers = triggers
        self._on_surpass = on_surpass

    @staticmethod
    def to_json(o: Workflow, **_: object) -> Json:
        env = {"environment": o.environment} if o.environment else {}
        return {
            "id": o.id,
            "name": o.name,
            "steps": to_json(o.steps),
            "triggers": to_json(o.triggers),
            "on_surpass": to_js(o.on_surpass),
            **env,
        }

    @staticmethod
    def from_json(json: Json, _: type = object, **__: object) -> Workflow:
        return Workflow(
            json["id"],
            json["name"],
            from_js(json["steps"], List[Step]),
            from_js(json["triggers"], List[Trigger]),
            from_js(json["on_surpass"], TaskSurpassBehaviour),
        )


class StepState(State):
    """
    Base class for all states in a task.
    There is always a related step definition inside a related task definition.
    """

    def __init__(self, step: Step, instance: RunningTask):
        super().__init__(step.name, "begin_step", "end_step")
        self.step = step
        self.instance = instance
        self.timed_out = False
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None

    def current_step_done(self) -> bool:
        """
        Override this method in deriving classes to define, when this state is done.
        :return: True when this state is done otherwise false.
        """
        return not self.timed_out

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        """
        Override this method in deriving classes to define actions when this state is entered.
        :return: all commands to execute when this state is entered.
        """
        return []

    # noinspection PyUnusedLocal
    def handle_command_results(self, results: Dict[TaskCommand, Any]) -> None:
        """
        Override this method in deriving classes to define behaviour based on command results.
        :param results: the results of emitted task commands.
        :return: the list of new task commands.
        """

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
        if self.started_at is not None and ((self.started_at + self.timeout()) < utc()):
            self.timed_out = True
            return True
        return False

    def initial_progress(self, progress: ProgressTree) -> None:
        """
        Override this method in deriving classes to define initial progress.
        :param progress: the progress tree to update.
        """

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
            return ExecuteCommandState(step.action, step, instance)
        else:
            raise AttributeError(f"No mapping for {type(step.action).__name__}")

    def step_started(self) -> None:
        """
        This method is called when the fsm enters this state.
        Override in subsequent classes, if action is required in such a scenario.
        """
        self.started_at = utc()

    def step_finished(self) -> None:
        """
        This method is called when the fsm enters this state.
        Override in subsequent classes, if action is required in such a scenario.
        """
        self.finished_at = utc()

    # noinspection PyMethodMayBeStatic
    def export_state(self) -> Json:
        """
        This method is called when the state of the task needs to be persisted.
        Since each state in the FSM can have its own schema, we export a generic json blob here,
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
        self.wait_for: List[Subscriber] = self.instance.subscribers_by_event().get(perform.message_type, [])

    def current_step_done(self) -> bool:
        """
        This state is done, when we received an ack or an error from every subscriber.
        The step behavior defines how to deal in case of an error.
        """
        msg_type = self.perform.message_type
        in_step: Set[SubscriberId] = {
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

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        """
        When the state is entered, emit the action message and inform all actors.
        """
        return [SendMessage(Action(self.perform.message_type, self.instance.id, self.step.name))]

    def step_started(self) -> None:
        super().step_started()
        # refresh the list of subscribers when the step has started
        self.wait_for = self.instance.subscribers_by_event().get(self.perform.message_type, [])

    def export_state(self) -> Json:
        return {"wait_for": [a.id for a in self.wait_for]}

    def import_state(self, js: Json) -> None:
        existing = {s.id: s for s in self.instance.subscribers_by_event().get(self.perform.message_type, [])}
        wait_for = js.get("wait_for", [])
        # filter all existing subscriber from the list of subscribers to wait_for
        self.wait_for = list(filter(identity, (existing.get(sid) for sid in wait_for)))  # type: ignore

    def initial_progress(self, progress: ProgressTree) -> None:
        super().initial_progress(progress)
        if self.wait_for:
            progress.add_progress(ProgressDone(self.step.name, 0, 1))


class WaitForEventState(StepState):
    def __init__(self, perform: WaitForEvent, step: Step, instance: RunningTask):
        super().__init__(step, instance)
        self.perform = perform

    def current_step_done(self) -> bool:
        """
        This step is done, when the event it is waiting for has arrived.
        """
        return self.timed_out or exist(
            lambda x: isinstance(x, Event) and x.message_type == self.perform.wait_for_message_type,
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

        if event.message_type == self.perform.wait_for_message_type and filter_applies():
            self.instance.received_messages.append(event)
            return True
        return False


class ExecuteCommandState(StepState):
    def __init__(self, execute: ExecuteCommand, step: Step, instance: RunningTask):
        super().__init__(step, instance)
        self.execute = execute
        self.execution_done = False

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        # override now: always use the time when the task has been triggered
        env = frozendict({"now": utc_str(self.instance.task_started_at)})
        return [ExecuteOnCLI(self.execute.command, env)]

    def handle_command_results(self, results: Dict[TaskCommand, Any]) -> None:
        found = first(lambda r: isinstance(r, ExecuteOnCLI) and r.command == self.execute.command, results.keys())
        if found:
            result = results[found]
            if isinstance(result, Exception):
                log.warning(f"Command {self.execute.command} failed with error: {result}")
            else:
                log.info(f"Result of command {self.execute.command} is {result}")
            self.execution_done = True

    def current_step_done(self) -> bool:
        return self.execution_done


class EmitEventState(StepState):
    def __init__(self, emit: EmitEvent, step: Step, instance: RunningTask):
        super().__init__(step, instance)
        self.emit = emit

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        return [SendMessage(self.emit.event)]


class StartState(StepState):
    def __init__(self, instance: RunningTask):
        self.event = Event("task_start")
        super().__init__(Step("task_start", EmitEvent(self.event)), instance)

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        return [SendMessage(self.event)]


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

    def commands_to_execute(self) -> Sequence[TaskCommand]:
        return [SendMessage(self.event)]

    def step_started(self) -> None:
        super().step_started()
        self.instance.task_duration = utc() - self.instance.task_started_at


class RunningTask:
    @staticmethod
    def empty(
        descriptor: TaskDescription, subscriber_by_event: Callable[[], Dict[str, List[Subscriber]]]
    ) -> Tuple[RunningTask, Sequence[TaskCommand]]:
        assert len(descriptor.steps) > 0, "TaskDescription needs at least one step!"
        uid = TaskId(str(uuid.uuid1()))
        task = RunningTask(uid, descriptor, subscriber_by_event)
        messages = [SendMessage(Event("task_started", data={"task": descriptor.name})), *task.move_to_next_state()]
        return task, messages

    def __init__(
        self, uid: TaskId, descriptor: TaskDescription, subscribers_by_event: Callable[[], Dict[str, List[Subscriber]]]
    ):
        self.id = uid
        self.is_error = False
        self.descriptor = descriptor
        self.received_messages: MutableSequence[Message] = []
        self.subscribers_by_event = subscribers_by_event
        self.task_started_at = utc()
        self.task_duration: Optional[timedelta] = None
        self.update_task: Optional[Task[None]] = None
        self.descriptor_alive = True
        self.info_messages: List[Union[ActionInfo, ActionError]] = []
        # ProgressTree: [step_name, path, to progress] -> progress
        self.progresses: ProgressTree = ProgressTree(self.descriptor.name)

        steps = []
        for step in descriptor.steps:
            step_state = StepState.from_step(step, self)
            step_state.initial_progress(self.progresses)
            steps.append(step_state)

        start = StartState(self)
        end = EndState(self)
        states: List[StepState] = [start, *steps, end]
        self.states: Dict[str, StepState] = {state.step.name: state for state in states}
        self.step_name_index = {step.name: i for i, step in enumerate(descriptor.steps)}
        self.machine = Machine(self, states, start, auto_transitions=False, queued=True)

        for current_state, next_state in interleave(states):
            self.machine.add_transition(
                "_next_state", current_state.name, next_state.name, [current_state.current_step_done]
            )
            self.machine.add_transition("_to_err", current_state.name, end.name, [end.is_error])

    def move_to_next_state(self) -> Sequence[TaskCommand]:
        def next_state() -> bool:
            try:
                # this method is defined dynamically by transitions
                last_state = self.current_state
                result: bool = self._next_state()  # type: ignore # pylint: disable=no-member
                # safeguard: if state transition does not change the state
                if result and self.current_state is last_state:
                    return False
                return result
            except MachineError:
                return False

        resulting_commands: List[TaskCommand] = []
        while next_state():
            resulting_commands.extend(self.current_state.commands_to_execute())
        return resulting_commands

    @property
    def current_step_progress(self) -> Progress:
        return self.progresses.sub_progress(self.current_step.name) or ProgressDone(self.current_step.name, 0, 1)

    @property
    def progress(self) -> ProgressTree:
        return self.progresses

    def progress_json(self) -> Json:
        max_idx = len(self.step_name_index)

        def order_progress(p: Progress) -> Tuple[int, int, str]:
            # if the progress is nested, take the first path else the name of the progress
            step_name = p.path[0] if len(p.path) > 0 else p.name
            # lookup the index of the step or fallback to the max index
            idx = self.step_name_index.get(step_name)
            index = idx if idx is not None else max_idx
            progress = p.overall_progress().percentage
            # order by step, progress (done first and in progress later) and name
            return index, -progress, p.name

        return self.progresses.to_json(key=order_progress)

    @property
    def current_state(self) -> StepState:
        return self.machine.get_state(self.state)  # type: ignore # pylint: disable=no-member

    @property
    def current_step(self) -> Step:
        return self.current_state.step

    @property
    def is_active(self) -> bool:
        return not isinstance(self.current_state, EndState)

    def handle_event(self, event: Event) -> Tuple[bool, Sequence[TaskCommand]]:
        if self.current_state.handle_event(event):
            return True, self.move_to_next_state()
        else:
            return False, []

    def handle_done(self, done: ActionDone) -> Sequence[TaskCommand]:
        self.received_messages.append(done)
        return self.move_to_next_state()

    def handle_error(self, error: ActionError) -> Sequence[TaskCommand]:
        """
        An action could not be performed - the subscriber returned an error.
        Such a message only makes sense in a PerformAction step.
        Whether this event leads to a state change is decided by the current state.
        Whether this leads to the end of this task is decided by the current step error behaviour.
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

    def handle_info(self, info: ActionInfo) -> None:
        self.info_messages.append(info)

    def handle_progress(self, msg: ActionProgress) -> None:
        # make sure the step name is part of the progress
        msg.progress.path = [self.current_step.name, *msg.progress.path]
        with suppress(Exception):
            self.progresses.add_progress(msg.progress)

    def handle_command_results(self, results: Dict[TaskCommand, Any]) -> Sequence[TaskCommand]:
        self.current_state.handle_command_results(results)
        return self.move_to_next_state()

    def end(self) -> None:
        """
        If this method is called, the task is marked as failed and moves to the end state.
        Use this method to abort a task.
        """
        if not isinstance(self.current_state, EndState):
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
        self.current_state.step_started()

    def end_step(self) -> None:
        log.debug(f"Task {self.id}: end of step {self.current_step.name}")
        self.current_state.step_finished()
        # mark all progresses as completed
        if self.progresses.has_path(self.current_step.name):
            self.progresses.add_progress(ProgressDone(self.current_step.name, 1, 1))


set_deserializer(StepAction.from_json, StepAction, high_prio=False)
set_deserializer(Trigger.from_json, Trigger, high_prio=False)
set_deserializer(TaskCommand.from_json, TaskCommand, high_prio=False)
set_deserializer(Job.from_json, Job)
set_serializer(Job.to_json, Job)
set_deserializer(Workflow.from_json, Workflow)
set_serializer(Workflow.to_json, Workflow)
