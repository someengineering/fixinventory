from datetime import timedelta

import pytest
from argparse import ArgumentParser, Namespace
from pytest import fixture
from typing import AsyncGenerator

from core.cli.cli import CLI
from core.db.runningtaskdb import RunningTaskDb
from core.error import ParseError
from core.event_bus import EventBus, Event, Message, ActionDone, Action
from core.task.model import Subscriber
from core.task.scheduler import Scheduler
from core.task.subscribers import SubscriptionHandler
from core.task.task_description import Workflow, Step, PerformAction, EventTrigger, StepErrorBehaviour, TimeTrigger
from core.task.task_handler import TaskHandler
from tests.core.db.entitydb import InMemoryDb

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import filled_graph_db, graph_db, test_db, foo_model

# noinspection PyUnresolvedReferences
from tests.core.cli.cli_test import cli, cli_deps

# noinspection PyUnresolvedReferences
from tests.core.event_bus_test import event_bus, all_events, wait_for_message

# noinspection PyUnresolvedReferences
from tests.core.db.runningtaskdb_test import running_task_db


@fixture
async def subscription_handler(event_bus: EventBus) -> SubscriptionHandler:
    in_mem = InMemoryDb(Subscriber, lambda x: x.id)
    result = SubscriptionHandler(in_mem, event_bus)
    return result


@fixture
def task_handler_args() -> Namespace:
    args = ArgumentParser()
    TaskHandler.add_args(args)
    return args.parse_args("")


@fixture
async def task_handler(
    running_task_db: RunningTaskDb,
    event_bus: EventBus,
    subscription_handler: SubscriptionHandler,
    cli: CLI,
    test_workflow: Workflow,
    task_handler_args: Namespace,
) -> AsyncGenerator[TaskHandler, None]:
    wfh = TaskHandler(running_task_db, event_bus, subscription_handler, Scheduler(), cli, task_handler_args)
    wfh.task_descriptions = [test_workflow]
    async with wfh:
        yield wfh


@fixture
def test_workflow() -> Workflow:
    return Workflow(
        "test_workflow",
        "Speakable name of workflow",
        [
            Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
            Step("act", PerformAction("collect"), timedelta(seconds=10)),
            Step("done", PerformAction("collect_done"), timedelta(seconds=10), StepErrorBehaviour.Stop),
        ],
        [EventTrigger("start me up")],
    )


@pytest.mark.asyncio
async def test_run_job(task_handler: TaskHandler, all_events: list[Message]) -> None:
    await task_handler.handle_event(Event("start me up"))
    started: Event = await wait_for_message(all_events, "task_started", Event)
    await wait_for_message(all_events, "task_end", Event)
    assert started.data["task"] == "Speakable name of workflow"


@pytest.mark.asyncio
async def test_parse_job_line_event_trigger(task_handler: TaskHandler) -> None:
    job = await task_handler.parse_job_line("test", 'cleanup_plan : match kind == "node" | clean')
    assert job.trigger == EventTrigger("cleanup_plan")
    assert job.command.command == 'match kind == "node" | clean'
    assert job.wait is None


@pytest.mark.asyncio
async def test_parse_job_line_time_trigger(task_handler: TaskHandler) -> None:
    job = await task_handler.parse_job_line("test", '0 5 * * sat : match t2 == "node" | clean')
    assert job.trigger == TimeTrigger("0 5 * * sat")
    assert job.command.command == 'match t2 == "node" | clean'
    assert job.wait is None
    with pytest.raises(ParseError):
        await task_handler.parse_job_line("test", '0 5 invalid_cron_expr * sat : match t2 == "node" | clean')


@pytest.mark.asyncio
async def test_parse_job_line_event_and_time_trigger(task_handler: TaskHandler) -> None:
    job = await task_handler.parse_job_line("test", '0 5 * * sat cleanup_plan : match t2 == "node" | clean')
    assert job.trigger == TimeTrigger("0 5 * * sat")
    assert job.command.command == 'match t2 == "node" | clean'
    assert job.wait[0] == EventTrigger("cleanup_plan")  # type: ignore
    with pytest.raises(ParseError):
        await task_handler.parse_job_line("test", '0 5 invalid_cron_expr * sat cleanup_plan:match t2 == "node" | clean')


@pytest.mark.asyncio
async def test_recover_workflow(
    running_task_db: RunningTaskDb,
    event_bus: EventBus,
    subscription_handler: SubscriptionHandler,
    all_events: list[Message],
    cli: CLI,
    task_handler_args: Namespace,
) -> None:
    def handler() -> TaskHandler:
        return TaskHandler(running_task_db, event_bus, subscription_handler, Scheduler(), cli, task_handler_args)

    await subscription_handler.add_subscription("sub_1", "start_collect", True, timedelta(seconds=30))
    sub1 = await subscription_handler.add_subscription("sub_1", "collect", True, timedelta(seconds=30))
    sub2 = await subscription_handler.add_subscription("sub_2", "collect", True, timedelta(seconds=30))

    async with handler() as wf1:
        # kick off a new workflow
        await wf1.handle_event(Event("start_collect_workflow"))
        assert len(wf1.tasks) == 1
        # expect a start_collect action message
        a: Action = await wait_for_message(all_events, "start_collect", Action)
        await wf1.handle_action_done(ActionDone(a.message_type, a.task_id, a.step_name, sub1.id, dict(a.data)))

        # expect a collect action message
        b: Action = await wait_for_message(all_events, "collect", Action)
        await wf1.handle_action_done(ActionDone(b.message_type, b.task_id, b.step_name, sub1.id, dict(b.data)))

    # subscriber 3 is also registering for collect
    # since the collect phase is already started, it should not participate in this round
    sub3 = await subscription_handler.add_subscription("sub_3", "collect", True, timedelta(seconds=30))

    # simulate a restart, wf1 is stopped and wf2 needs to recover from database
    async with handler() as wf2:
        assert len(wf2.tasks) == 1
        wfi = list(wf2.tasks.values())[0]
        assert wfi.current_state.name == "act"
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
