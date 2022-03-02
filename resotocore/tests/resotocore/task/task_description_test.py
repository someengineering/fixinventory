from datetime import timedelta
from typing import Any, List, Dict, Tuple

from deepdiff import DeepDiff
from frozendict import frozendict  # type: ignore
from pytest import fixture

from resotocore.message_bus import MessageBus, Action, ActionDone, ActionError, Event
from resotocore.model.typed_model import from_js, to_js
from resotocore.task.model import Subscriber, Subscription
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.task.task_description import (
    Workflow,
    Step,
    RunningTask,
    StepErrorBehaviour,
    PerformAction,
    WaitForEvent,
    EmitEvent,
    ExecuteCommand,
    EventTrigger,
    Job,
    TimeTrigger,
    SendMessage,
    ExecuteOnCLI,
)
from tests.resotocore.db.entitydb import InMemoryDb

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus


@fixture
async def subscription_handler(message_bus: MessageBus) -> SubscriptionHandler:
    in_mem = InMemoryDb(Subscriber, lambda x: x.id)
    result = SubscriptionHandler(in_mem, message_bus)
    await result.add_subscription("sub_1", "test", True, timedelta(seconds=3))
    return result


@fixture
def test_workflow() -> Workflow:
    return Workflow(
        "test_workflow",
        "Speakable name of workflow",
        [
            Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
            Step("wait", WaitForEvent("godot", {"a": 1}), timedelta(seconds=10)),
            Step("emit_event", EmitEvent(Event("hello", {"a": 1})), timedelta(seconds=10)),
            Step("collect", PerformAction("collect"), timedelta(seconds=10)),
            Step("done", PerformAction("collect_done"), timedelta(seconds=10), StepErrorBehaviour.Stop),
        ],
        [EventTrigger("start me up")],
    )


@fixture
def workflow_instance(
    test_workflow: Workflow,
) -> Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]:
    td = timedelta(seconds=100)
    sub1 = Subscription("start_collect", True, td)
    sub2 = Subscription("collect", True, td)
    sub3 = Subscription("collect_done", True, td)
    s1 = Subscriber.from_list("s1", [sub1, sub2, sub3])
    s2 = Subscriber.from_list("s2", [sub2, sub3])
    subscriptions = {"start_collect": [s1], "collect": [s1, s2], "collect_done": [s1, s2]}
    w, _ = RunningTask.empty(test_workflow, lambda: subscriptions)
    w.received_messages = [
        Action("start_collect", w.id, "start"),
        ActionDone("start_collect", w.id, "start", s1.id),
        ActionDone("start_collect", w.id, "start", s2.id),
        Event("godot", {"a": 1, "b": 2}),
        Action("collect", w.id, "collect"),
        ActionDone("collect", w.id, "collect", s1.id),
    ]
    w.move_to_next_state()
    return w, s1, s2, subscriptions


def test_eq() -> None:
    s1 = Step("a", PerformAction("a"), timedelta())
    s2 = Step("a", WaitForEvent("a", {"foo": "bla"}), timedelta())
    s3 = Step("a", EmitEvent(Event("a", {"a": "b"})), timedelta())
    s4 = Step("a", ExecuteCommand("echo hello"), timedelta())
    assert s1 == Step("a", PerformAction("a"), timedelta())
    assert s2 == Step("a", WaitForEvent("a", {"foo": "bla"}), timedelta())
    assert s3 == Step("a", EmitEvent(Event("a", {"a": "b"})), timedelta())
    assert s4 == Step("a", ExecuteCommand("echo hello"), timedelta())
    trigger = [EventTrigger("start me up")]
    assert Workflow("a", "a", [s1, s2, s3, s4], trigger) == Workflow("a", "a", [s1, s2, s3, s4], trigger)


def test_ack_for(workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]) -> None:
    wi, s1, s2, subscriptions = workflow_instance
    assert wi.ack_for("start_collect", s1) is not None
    assert wi.ack_for("start_collect", s2) is not None
    assert wi.ack_for("collect_done", s1) is None
    assert wi.ack_for("collect_done", s2) is None


def test_pending_action_for(
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]],
) -> None:
    wi, s1, s2, subscriptions = workflow_instance
    # s1 already sent a done message for the current step
    assert wi.pending_action_for(s1) is None
    # s2 is still expected to provide a done message
    assert wi.pending_action_for(s2) == Action("collect", wi.id, "collect")


def test_handle_done(
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]
) -> None:
    wi, s1, s2, subscriptions = workflow_instance
    # we are in state collect. Another ack of start is ignored.
    events = wi.handle_done(ActionDone("start", wi.id, "start", s1.id))  #
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    # This step is unknown to the workflow and should not change its state
    events = wi.handle_done(ActionDone("boom", wi.id, "boom", s1.id))  #
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    # this event has been received already and should not emit any new action
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s1.id))
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    # this event is the last missing event in this step
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s2.id))
    assert wi.current_step.name == "done"
    assert len(events) == 1


def test_handle_error(
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]
) -> None:
    wi, s1, s2, subscriptions = workflow_instance
    # this event is the last missing event in this step. It fails but the workflow should continue at that point
    events = wi.handle_error(ActionError("collect", wi.id, "collect", s2.id, "boom"))
    assert wi.current_step.name == "done"
    assert len(events) == 1
    # this step is configured to fail the whole workflow instance
    events = wi.handle_error(ActionError("collect_done", wi.id, "done", s2.id, "boom"))
    assert wi.is_active is False
    assert wi.is_error is True
    assert len(events) == 0


def test_complete_workflow(
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]
) -> None:
    init, s1, s2, subscriptions = workflow_instance
    # start new workflow instance
    wi, events = RunningTask.empty(init.descriptor, lambda: subscriptions)
    assert wi.current_step.name == "start"
    assert len(events) == 2
    events = wi.handle_done(ActionDone("start", wi.id, "start", s1.id))
    assert wi.current_step.name == "wait"
    assert len(events) == 0
    handled, events = wi.handle_event(Event("godot", {"a": 2}))
    assert wi.current_step.name == "wait"
    assert handled is False
    assert len(events) == 0
    handled, events = wi.handle_event(Event("godot", {"a": 1, "d": "test"}))
    assert wi.current_step.name == "collect"
    assert handled is True
    assert len(events) == 2  # event from EmitEvent and action from PerformAction
    events = wi.handle_done(ActionDone("start", wi.id, "start", s1.id))  #
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s1.id))
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s2.id))
    assert wi.current_step.name == "done"
    assert len(events) == 1
    events = wi.handle_done(ActionDone("done", wi.id, "done", s1.id))
    assert len(events) == 0
    assert wi.current_step.name == "done"
    events = wi.handle_done(ActionDone("done", wi.id, "done", s2.id))
    assert len(events) == 1
    assert wi.is_active is False


def test_marshalling_trigger() -> None:
    roundtrip(EventTrigger("test", {"foo": True}))
    roundtrip(TimeTrigger("* * * * *"))


def test_marshalling_step_action() -> None:
    roundtrip(PerformAction("test"))
    roundtrip(EmitEvent(Event("test", {"foo": "hello"})))
    roundtrip(WaitForEvent("test", {"foo": "hello"}))
    roundtrip(ExecuteCommand("help"))


def test_marshalling_task_command() -> None:
    roundtrip(SendMessage(Event("test", {"foo": "hello"})))
    roundtrip(ExecuteOnCLI("test", frozendict({"fii": "bla"})))


def test_marshalling_step() -> None:
    roundtrip(Step("test", PerformAction("test")))
    roundtrip(Step("test", WaitForEvent("test"), timedelta(seconds=19), StepErrorBehaviour.Stop))


def test_marshalling_job() -> None:
    j = Job("id", ExecuteCommand("echo hello"), timedelta(seconds=10), EventTrigger("run_job"))
    roundtrip(j)
    roundtrip(Job(j.id, j.command, j.timeout, j.trigger, (EventTrigger("test"), timedelta(hours=2))))


def test_marshalling_workflow(test_workflow: Workflow) -> None:
    roundtrip(test_workflow)


def roundtrip(obj: Any) -> None:
    js = to_js(obj)
    again = from_js(js, type(obj))
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"
