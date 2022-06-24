from resotocore.db.model import QueryModel
from resotocore.message_bus import MessageBus, Action
import logging
import asyncio
from asyncio import Task, Future
from typing import Optional, Tuple, List
from contextlib import suppress
from datetime import timedelta
from resotocore.model.graph_access import ByNodeId, NodeSelector
from resotocore.task.model import Subscriber
from resotocore.ids import NodeId, SubscriberId
from resotocore.task.task_handler import TaskHandlerService
from resotocore.ids import TaskId
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.db.db_access import DbAccess
from resotocore.model.model_handler import ModelHandler
from resotocore.query.query_parser import parse_query


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
    ):
        self.message_bus = message_bus
        self.merge_outer_edges_listener: Optional[Task[None]] = None
        self.subscription_handler = subscription_handler
        self.subscriber: Optional[Subscriber] = None
        self.task_handler_service = task_handler_service
        self.db_access = db_access
        self.model_handler = model_handler

    async def merge_outer_edges(self, task_id: TaskId) -> Tuple[int, int]:
        pending_outer_edge_db = self.db_access.pending_deferred_edge_db
        pending_edges = await pending_outer_edge_db.get(task_id)
        model = await self.model_handler.load_model()
        if pending_edges:
            graph_db = self.db_access.get_graph_db(pending_edges.graph)

            async def find_node_id(selector: NodeSelector) -> Optional[NodeId]:
                try:
                    if isinstance(selector, ByNodeId):
                        node = await graph_db.get_node(model, selector.value)
                        return node.get("id") if node else None
                    else:
                        query = parse_query(selector.query).with_limit(2)
                        async with await graph_db.search_list(QueryModel(query, model)) as cursor:
                            results = [node async for node in cursor]
                            if len(results) > 1:
                                log.warning(
                                    f"task_id: {task_id}: node selector {selector.query} returned more than one node."
                                    "The edge was not created."
                                )
                                return None

                        return next(iter(results), {}).get("id", None)  # type: ignore
                except Exception as e:
                    log.warning(f"task_id: {task_id}: Error {e} when finding node {selector}")
                    return None

            edges: List[Tuple[NodeId, NodeId, str]] = []
            for edge in pending_edges.edges:
                from_id = await find_node_id(edge.from_node)
                to_id = await find_node_id(edge.to_node)
                if from_id and to_id:
                    edges.append((from_id, to_id, edge.edge_type))

            updated, deleted = await graph_db.update_deferred_edges(edges, pending_edges.created_at)

            log.info(
                f"MergeOuterEdgesHandler: updated {updated}/{len(pending_edges.edges)},"
                f"  deleted {deleted} edges in task id {task_id}"
            )

            return (updated, deleted)
        else:
            log.info(f"MergeOuterEdgesHandler: no pending edges for task id {task_id} found.")

            return (0, 0)

    async def mark_done(self, task_id: TaskId) -> None:
        pending_outer_edge_db = self.db_access.pending_deferred_edge_db
        await pending_outer_edge_db.delete(task_id)

    async def __handle_events(self, subscription_done: Future[None]) -> None:
        async with self.message_bus.subscribe(subscriber_id, [merge_outer_edges]) as events:
            subscription_done.set_result(None)
            while True:
                event = await events.get()
                if isinstance(event, Action) and event.message_type == merge_outer_edges:
                    await self.merge_outer_edges(event.task_id)
                    await self.mark_done(event.task_id)
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
