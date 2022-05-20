import asyncio
import logging
from asyncio import Task
from datetime import timedelta
from typing import Optional, List

from resotocore.message_bus import MessageBus, CoreMessage, Message
from resotocore.ids import SubscriberId
from resotocore.task import TaskHandler
from resotocore.task.task_description import PerformAction, Workflow
from resotocore.util import uuid_str

log = logging.getLogger(__name__)


def wait_and_start(
    workflows: List[Workflow],
    task_handler: TaskHandler,
    message_bus: MessageBus,
    wait_after_connect: timedelta = timedelta(seconds=10),
) -> Task[None]:
    """
    This function is used to trigger workflows automatically, when the related subscribing actor connects.
    Such behaviour can be useful during startup, when we do not want to wait until the next scheduled time triggers.
    Note: this is a one_off action: after the initial connect has happened, the task will complete.

    :param workflows: the known workflows.
    :param task_handler: the job handler to start the workflow.
    :param message_bus: the message bus to listen for incoming subscribers.
    :param wait_after_connect: amount of time to wait between connect and workflow trigger.
    :return: running task that will succeed once the first subscribing actor connects.
    """

    log.info("Wait for subscribing actors to start the related workflow")
    # get all action message types the workflows are waiting for
    wait_for = {s.action.message_type: wf for wf in workflows for s in wf.steps if isinstance(s.action, PerformAction)}

    def workflow_if_actor(msg: Message) -> Optional[Workflow]:
        channels: Optional[List[str]] = msg.data.get("channels")
        if channels:
            for ch in channels:
                if ch in wait_for:
                    return wait_for[ch]
        return None

    async def wait_for_subscriber() -> None:
        subscriber_id = SubscriberId(f"resotocore.wait_for_actor_{uuid_str()}")
        async with message_bus.subscribe(subscriber_id, [CoreMessage.Connected]) as bus:
            while True:
                message = await bus.get()
                maybe_workflow = workflow_if_actor(message)
                if maybe_workflow:
                    log.info(
                        f"Subscribed actor for workflow {maybe_workflow.name} connected. "
                        f"Wait for {wait_after_connect} seconds."
                    )
                    # wait before we start the workflow
                    await asyncio.sleep(wait_after_connect.total_seconds())
                    log.info(f"Start workflow {maybe_workflow.name}")
                    # start the workflow
                    await task_handler.start_task_by_descriptor_id(maybe_workflow.id)
                    # exit the loop and destroy the listener
                    break
        log.info("task done")

    return asyncio.create_task(wait_for_subscriber())
