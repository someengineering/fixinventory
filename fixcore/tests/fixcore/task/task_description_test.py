from datetime import timedelta
from typing import Any, List, Dict, Tuple, Callable

from attr import evolve
from deepdiff import DeepDiff
from frozendict import frozendict

from fixcore.ids import SubscriberId, TaskDescriptorId
from fixcore.message_bus import Action, ActionDone, ActionError, Event, ActionProgress, ActionInfo, ActionAbort
from fixcore.model.typed_model import from_js, to_js
from fixcore.task.task_dependencies import TaskDependencies
from fixcore.task.model import Subscriber, Subscription
from fixcore.task.task_description import (
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
from fixlib.core.progress import ProgressDone
from fixlib.utils import utc


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
    assert Workflow(TaskDescriptorId("a"), "a", [s1, s2, s3, s4], trigger) == Workflow(
        TaskDescriptorId("a"), "a", [s1, s2, s3, s4], trigger
    )


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
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]],
    task_dependencies: TaskDependencies,
) -> None:
    init, s1, s2, subscriptions = workflow_instance
    # start new workflow instance
    wi, events = RunningTask.empty(
        init.descriptor, evolve(task_dependencies, subscribers_by_event=lambda: subscriptions)
    )
    assert wi.current_step.name == "start"
    assert len(events) == 2
    assert wi.progress.percentage == 0
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
    assert wi.progress.percentage == 0
    wi.handle_progress(ActionProgress("start", wi.id, "start", s1.id, ProgressDone("Test", 0, 100), utc()))
    wi.handle_progress(ActionProgress("start", wi.id, "start", s2.id, ProgressDone("Test", 50, 100), utc()))
    assert wi.progress.percentage == 50
    wi.handle_progress(ActionProgress("start", wi.id, "start", s1.id, ProgressDone("Test", 90, 100), utc()))
    wi.handle_progress(ActionProgress("start", wi.id, "start", s2.id, ProgressDone("Test", 80, 100), utc()))
    assert wi.progress.percentage == 80
    wi.handle_info(ActionInfo("start", wi.id, "start", s1.id, "error", "echt jetzt"))
    assert len(wi.info_messages) == 1
    events = wi.handle_done(ActionDone("start", wi.id, "start", s1.id))
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s1.id))
    assert wi.current_step.name == "collect"
    assert len(events) == 0
    events = wi.handle_done(ActionDone("collect", wi.id, "collect", s2.id))
    assert wi.current_step.name == "done"
    assert len(events) == 1
    assert wi.progress.percentage == 100
    events = wi.handle_done(ActionDone("done", wi.id, "done", s1.id))
    assert len(events) == 0
    assert wi.current_step.name == "done"
    events = wi.handle_done(ActionDone("done", wi.id, "done", s2.id))
    assert len(events) == 2
    assert wi.progress.percentage == 100
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
    j = Job(TaskDescriptorId("id"), ExecuteCommand("echo hello"), timedelta(seconds=10), EventTrigger("run_job"))
    roundtrip(j)
    roundtrip(Job(j.id, j.command, j.timeout, j.trigger, (EventTrigger("test"), timedelta(hours=2))))


def test_marshalling_workflow(test_workflow: Workflow) -> None:
    roundtrip(test_workflow)


def roundtrip(obj: Any) -> None:
    js = to_js(obj)
    again = from_js(js, type(obj))
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"


def test_task_progress(task_dependencies: TaskDependencies) -> None:
    actions = ["collect", "encode"]
    wf = Workflow(TaskDescriptorId("test_workflow"), "name", [Step(a, PerformAction(a)) for a in actions], [])
    sb = Subscriber(SubscriberId("test"), {s: Subscription(s) for s in actions})
    rt, _ = RunningTask.empty(wf, evolve(task_dependencies, subscribers_by_event=lambda: {s: [sb] for s in actions}))

    def progress(step: str, fn: Callable[[int], ProgressDone]) -> None:
        # use revers order to test that the correct order is used
        for idx in range(3):
            rt.handle_progress(ActionProgress(step, rt.id, step, sb.id, fn(idx), utc()))

    # report progress start on the collect step
    progress("collect", lambda idx: ProgressDone(str(idx), 0, 100, path=["foo", "bla"]))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["0", "1", "2"]

    # report index as progress on the collect step
    progress("collect", lambda idx: ProgressDone(str(idx), idx, 100, path=["foo", "bla"]))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["2", "1", "0"]

    # report progress done on the collect step
    rt.handle_done(ActionDone("collect", rt.id, "collect", sb.id))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["collect"]
    assert rt.progress.overall_progress().percentage == 100

    # report progress done on the encode step
    progress("encode", lambda idx: ProgressDone(str(idx), 0, 100, path=["foo", "bla"]))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["collect", "0", "1", "2"]

    # report index as progress on the collect step
    progress("collect", lambda idx: ProgressDone(str(idx), idx, 100, path=["foo", "bla"]))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["collect", "2", "1", "0"]

    rt.handle_done(ActionDone("encode", rt.id, "encode", sb.id))
    assert [x["name"] for x in rt.progress_json()["parts"]] == ["collect", "encode"]
    assert rt.progress.overall_progress().percentage == 100


def test_emitting_task_progress(
    workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]
) -> None:
    task, sub, _, _ = workflow_instance
    # after the task is created, there is not emitted progress
    assert task.not_emitted_progress() is not None
    # no progress update, nothing to emit
    assert task.not_emitted_progress() is None
    assert task.not_emitted_progress() is None
    # add progress updates
    task.handle_progress(ActionProgress("collect", task.id, "collect", sub.id, ProgressDone("collect", 0, 100), utc()))
    assert task.not_emitted_progress() is not None
    # no progress update, nothing to emit
    assert task.not_emitted_progress() is None
    assert task.not_emitted_progress() is None


def test_abort(workflow_instance: Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]) -> None:
    task, _, _, _ = workflow_instance
    result = task.current_state.abort()
    assert len(result) == 1
    assert isinstance(result[0], SendMessage)
    # noinspection PyUnresolvedReferences
    assert isinstance(result[0].message, ActionAbort)
