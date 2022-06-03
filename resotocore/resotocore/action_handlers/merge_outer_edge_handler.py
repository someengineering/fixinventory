from resotocore.db.model import QueryModel
from resotocore.message_bus import MessageBus, Action
import logging
import asyncio
from asyncio import Task, Future
from typing import Callable, Optional
from contextlib import suppress
from datetime import timedelta
from resotocore.model.graph_access import ByNodeId, NodeSelector
from resotocore.query.model import Query
from resotocore.task.model import Subscriber
from resotocore.ids import SubscriberId
from resotocore.task.task_handler import TaskHandlerService
from resotocore.ids import TaskId
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.db.db_access import DbAccess
from resotocore.model.model_handler import ModelHandler


log = logging.getLogger(__name__)

subscriber_id = SubscriberId("resotocore")
merge_outer_edges = "merge_outer_edges"


class MergeOuterEdgesHandler:
    def __init__(
        self,
        message_bus: MessageBus,
        subscription_handler: SubscriptionHandler,
        task_handler_service: TaskHandlerService,
        db_access: DbAccess,
        model_handler: ModelHandler,
        parse_query: Callable[[str], Query],
    ):
        self.message_bus = message_bus
        self.merge_outer_edges_listener: Optional[Task[None]] = None
        self.subscription_handler = subscription_handler
        self.subscriber: Optional[Subscriber] = None
        self.task_handler_service = task_handler_service
        self.db_access = db_access
        self.model_handler = model_handler
        self.parse_query = parse_query

    async def merge_outer_edges(self, task_id: TaskId) -> None:
        pending_outer_edge_db = self.db_access.get_pending_outer_edge_db()
        pending_edges = await pending_outer_edge_db.get(task_id)
        model = await self.model_handler.load_model()
        created_edges = 0
        if pending_edges:
            graph_db = self.db_access.get_graph_db(pending_edges.graph)

            async def find_node_id(selector: NodeSelector) -> Optional[str]:
                if isinstance(selector, ByNodeId):
                    node = await graph_db.get_node(model, selector.value)
                    return node.get("id") if node else None
                else:
                    query = self.parse_query(selector.query)
                    async with await graph_db.search_list(QueryModel(query, model)) as cursor:
                        async for node in cursor:
                            return node.get("id", None)  # type: ignore
                    return None

            for edge in pending_edges.edges:
                from_id = await find_node_id(edge.from_node)
                to_id = await find_node_id(edge.to_node)
                if from_id and to_id:
                    await graph_db.create_edge(model, from_id, to_id, edge.edge_type)

            log.info(
                f"MergeOuterEdgesHandler: created {created_edges}/{len(pending_edges.edges)} edges in task id {task_id}"
            )
        else:
            log.info(f"MergeOuterEdgesHandler: no pending edges for task id {task_id} found.")

    async def __handle_events(self, subscription_done: Future[None]) -> None:
        async with self.message_bus.subscribe(subscriber_id, [merge_outer_edges]) as events:
            subscription_done.set_result(None)
            while True:
                event = await events.get()
                if isinstance(event, Action) and event.message_type == merge_outer_edges:
                    await self.merge_outer_edges(event.task_id)
                    await self.task_handler_service.handle_action_done(event.done(subscriber_id))

    async def start(self) -> None:
        subscription_done = asyncio.get_event_loop().create_future()
        self.subscriber = await self.subscription_handler.add_subscription(
            subscriber_id, merge_outer_edges, True, timedelta(seconds=30)
        )
        self.merge_outer_edges_listener = asyncio.create_task(
            self.__handle_events(subscription_done), name=subscriber_id
        )
        await subscription_done

    async def stop(self) -> None:
        if self.merge_outer_edges_listener:
            with suppress(Exception):
                self.merge_outer_edges_listener.cancel()
        if self.subscriber:
            await self.subscription_handler.remove_subscription(subscriber_id, merge_outer_edges)
