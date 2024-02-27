import asyncio
import logging
from datetime import timedelta
from typing import List

import pytest
from pytest import LogCaptureFixture

from fixcore.analytics import AnalyticsEventSender, InMemoryEventSender
from fixcore.cli.cli import CLIService
from tests.fixcore.utils import eventually
from fixcore.db.jobdb import JobDb
from fixcore.db.runningtaskdb import RunningTaskDb
from fixcore.system_start import empty_config
from fixcore.ids import SubscriberId, TaskDescriptorId
from fixcore.message_bus import MessageBus, Event, Message, ActionDone, Action, ActionInfo, ActionError, CoreMessage
from fixcore.model.db_updater import GraphMerger
from fixcore.task.scheduler import APScheduler
from fixcore.task.subscribers import SubscriptionHandler
from fixcore.task.task_description import (
    Workflow,
    EventTrigger,
    TimeTrigger,
    Job,
    TaskSurpassBehaviour,
    ExecuteCommand,
    RunningTask,
)
from fixcore.task.task_handler import TaskHandlerService
from tests.fixcore.message_bus_test import wait_for_message


@pytest.mark.asyncio
async def test_run_job(task_handler: TaskHandlerService, all_events: List[Message]) -> None:
    await task_handler.handle_event(Event("start me up"))
    started: Event = await wait_for_message(all_events, "task_started", Event)
    await wait_for_message(all_events, "task_end", Event)
    assert started.data["task"] == "Speakable name of workflow"


@pytest.mark.asyncio
async def test_recover_workflow(
    running_task_db: RunningTaskDb,
    job_db: JobDb,
    message_bus: MessageBus,
    event_sender: AnalyticsEventSender,
    subscription_handler: SubscriptionHandler,
    graph_merger: GraphMerger,
    all_events: List[Message],
    cli: CLIService,
    test_workflow: Workflow,
) -> None:
    def handler() -> TaskHandlerService:
        th = TaskHandlerService(
            running_task_db,
            job_db,
            message_bus,
            event_sender,
            subscription_handler,
            graph_merger,
            APScheduler(),
            cli,
            empty_config(),
        )
        th.task_descriptions = [test_workflow]
        return th

    await subscription_handler.add_subscription(SubscriberId("sub_1"), "start_collect", True, timedelta(seconds=30))
    sub1 = await subscription_handler.add_subscription(SubscriberId("sub_1"), "collect", True, timedelta(seconds=30))
    sub2 = await subscription_handler.add_subscription(SubscriberId("sub_2"), "collect", True, timedelta(seconds=30))

    async with handler() as wf1:
        # kick off a new workflow
        await wf1.handle_event(Event("start me up"))
        assert len(wf1.tasks) == 1
        # expect a start_collect action message
        a: Action = await wait_for_message(all_events, "start_collect", Action)
        await wf1.handle_action_done(ActionDone(a.message_type, a.task_id, a.step_name, sub1.id, dict(a.data)))

        # expect a collect action message
        b: Action = await wait_for_message(all_events, "collect", Action)
        await wf1.handle_action_done(ActionDone(b.message_type, b.task_id, b.step_name, sub1.id, dict(b.data)))

    # subscriber 3 is also registering for collect
    # since the collect phase is already started, it should not participate in this round
    sub3 = await subscription_handler.add_subscription(SubscriberId("sub_3"), "collect", True, timedelta(seconds=30))

    # simulate a restart, wf1 is stopped and wf2 needs to recover from database
    async with handler() as wf2:
        assert len(wf2.tasks) == 1
        wfi = list(wf2.tasks.values())[0]
        assert wfi.current_state.name == "act"
        await wf2.list_all_pending_actions_for(sub1)
        await wf2.list_all_pending_actions_for(sub2)
        await wf2.list_all_pending_actions_for(sub3)
        assert (await wf2.list_all_pending_actions_for(sub1)) == []
        assert (await wf2.list_all_pending_actions_for(sub2)) == [Action("collect", wfi.id, "act", {})]
        assert (await wf2.list_all_pending_actions_for(sub3)) == []
        await wf2.handle_action_done(ActionDone("collect", wfi.id, "act", sub2.id, {}))
        # expect an event workflow_end
        await wait_for_message(all_events, "task_end", Event)
        # all workflow instances are gone
    assert len(wf2.tasks) == 0

    # simulate a restart, wf3 should start from a clean slate, since all instances are done
    async with handler() as wf3:
        assert len(wf3.tasks) == 0


@pytest.mark.asyncio
async def test_wait_for_running_job(
    task_handler: TaskHandlerService, test_workflow: Workflow, all_events: List[Message]
) -> None:
    test_workflow.on_surpass = TaskSurpassBehaviour.Wait
    task_handler.task_descriptions = [test_workflow]
    # subscribe as collect handler - the workflow will need to wait for this handler
    sub = await task_handler.subscription_handler.add_subscription(
        SubscriberId("sub_1"), "collect", True, timedelta(seconds=30)
    )
    await task_handler.handle_event(Event("start me up"))
    # check, that the workflow has started
    running_before = await task_handler.running_tasks()
    assert len(running_before) == 1
    act: Action = await wait_for_message(all_events, "collect", Action)
    # pull the same trigger: the workflow can not be started, since there is already one in progress -> wait
    await task_handler.handle_event(Event("start me up"))
    # report success of the only subscriber
    await task_handler.handle_action_done(ActionDone("collect", act.task_id, act.step_name, sub.id, dict(act.data)))
    # check overdue tasks: wipe finished tasks and eventually start waiting tasks
    await task_handler.check_running_tasks()
    # check, that the workflow has started
    running_after = await task_handler.running_tasks()
    assert len(running_after) == 1
    t_before, t_after = running_before[0], running_after[0]
    assert t_before.descriptor.id == t_after.descriptor.id and t_before.id != t_after.id


@pytest.mark.asyncio
async def test_handle_failing_task_command(task_handler: TaskHandlerService, caplog: LogCaptureFixture) -> None:
    caplog.set_level(logging.WARN)
    # This job will fail. Take a very long timeout - to avoid a timeout
    job = Job(TaskDescriptorId("fail"), ExecuteCommand("non_existing_command"), timedelta(hours=4))
    task_handler.task_descriptions = [job]
    assert len(await task_handler.running_tasks()) == 0
    await task_handler.start_task(job, "test fail")
    assert len(await task_handler.running_tasks()) == 1
    # The task is executed async - let's wait here directly
    update_task = (next(iter(task_handler.tasks.values()))).update_task
    assert update_task
    await update_task
    await task_handler.check_running_tasks()
    assert len(await task_handler.running_tasks()) == 0
    # One warning has been emitted
    assert len(caplog.records) == 1
    assert "Command non_existing_command failed with error" in caplog.records[0].message


@pytest.mark.asyncio
async def test_handle_failing_actor(
    task_handler: TaskHandlerService, test_workflow: Workflow, event_sender: InMemoryEventSender
) -> None:
    sub = await task_handler.subscription_handler.add_subscription(
        SubscriberId("sub_1"), "collect", True, timedelta(seconds=30)
    )
    info = await task_handler.start_task(test_workflow, "test")
    assert info is not None
    await asyncio.sleep(0.1)
    task = info.running_task
    await task_handler.handle_action_info(ActionInfo("collect", task.id, "act", sub.id, "error", "wrong!"))
    assert [e.kind for e in event_sender.events] == ["task-handler.task-started", "error.action"]
    await task_handler.handle_action_error(ActionError("collect", task.id, "act", sub.id, "wrong!"))
    assert [e.kind for e in event_sender.events] == ["task-handler.task-started", "error.action", "error.action"]


@pytest.mark.asyncio
async def test_default_workflow_triggers() -> None:
    workflows = {wf.name: wf for wf in TaskHandlerService.known_workflows(empty_config())}
    assert workflows["collect"].triggers == [EventTrigger("start_collect_workflow")]
    assert workflows["cleanup"].triggers == [EventTrigger("start_cleanup_workflow")]
    assert workflows["metrics"].triggers == [EventTrigger("start_metrics_workflow")]
    assert workflows["collect_and_cleanup"].triggers == [
        EventTrigger("start_collect_and_cleanup_workflow"),
        TimeTrigger("0 * * * *"),
    ]


@pytest.mark.asyncio
async def test_validate_add_delete_job(task_handler: TaskHandlerService) -> None:
    # add a job with a invalid name: should fail if the name contains invalid characters
    with pytest.raises(AttributeError):
        await task_handler.add_job(Job(TaskDescriptorId("foo:bar"), ExecuteCommand("echo foo"), timedelta(hours=4)))

    # add a job with a valid name: should succeed if the validation disabled
    await task_handler.add_job(
        Job(TaskDescriptorId("foo:bar"), ExecuteCommand("echo foo"), timedelta(hours=4)), force=True
    )

    # valid job name should not throw an exception
    await task_handler.add_job(Job(TaskDescriptorId("foobar"), ExecuteCommand("echo foo"), timedelta(hours=4)))

    # delete a job with a invalid name: should fail if the name contains invalid characters
    with pytest.raises(AttributeError):
        await task_handler.delete_job("foo:bar")

    # delete a job with a valid name: should succeed if the validation disabled
    await task_handler.delete_job("foobar", force=True)

    # force delete a job should not throw an exception
    await task_handler.delete_job("foo:bar", force=True)


@pytest.mark.asyncio
async def test_wait_for_collect_done(
    task_handler: TaskHandlerService, message_bus: MessageBus, graph_merger: GraphMerger
) -> None:
    # Test 1: start a task without any ongoing graph merges
    # start task
    task = await task_handler.start_task_by_descriptor_id(TaskDescriptorId("wait_for_collect_done"))
    assert task is not None
    rt: RunningTask = task.running_task
    assert rt in await task_handler.running_tasks()
    # no collect is in progress. The task should be finished immediately.
    await message_bus.emit_event("collected", {})
    await eventually(lambda: rt.current_step.name == "task_end")

    # Test 2: start a task with an ongoing graph merge operations. The task should wait for the merge to finish.
    # start task
    task = await task_handler.start_task_by_descriptor_id(TaskDescriptorId("wait_for_collect_done"))
    assert task is not None
    rt = task.running_task
    assert rt in await task_handler.running_tasks()
    # fake some ongoing imports in graph merger
    graph_merger.running_imports[rt.id] = 42
    # send event to finish task
    await message_bus.emit_event("collected", {})
    # sleep a little bit to make sure the task is not finished
    await asyncio.sleep(0.1)
    await eventually(lambda: rt.current_step.name == "wait_for_collect_done")
    # signal, that the import is finished
    await message_bus.emit_event(CoreMessage.GraphMergeCompleted, dict(task_id=rt.id))
    # make sure the task finishes
    await eventually(lambda: rt.current_step.name == "task_end")
