import asyncio
import logging
from asyncio import Task, Future
from collections import defaultdict
from contextlib import suppress
from datetime import timedelta
from typing import Optional, Tuple, List, Dict

from attr import frozen

from fixcore.db.db_access import DbAccess
from fixcore.db.model import QueryModel
from fixcore.ids import NodeId, SubscriberId
from fixcore.ids import TaskId
from fixcore.message_bus import MessageBus, Action
from fixcore.model.graph_access import ByNodeId, NodeSelector, DeferredEdge
from fixcore.model.model_handler import ModelHandler
from fixcore.query.query_parser import parse_query
from fixcore.service import Service
from fixcore.task.model import Subscriber
from fixcore.task.subscribers import SubscriptionHandler
from fixcore.task.task_handler import TaskHandlerService
from fixcore.types import EdgeType

log = logging.getLogger(__name__)

subscriber_id = SubscriberId("fixcore")
merge_deferred_edges = "merge_deferred_edges"


@frozen
class DeferredMergeResult:
    processed: int
    updated: int
    deleted: int


class MergeDeferredEdgesHandler(Service):
    def __init__(
        self,
        message_bus: MessageBus,
        subscription_handler: SubscriptionHandler,
        task_handler_service: TaskHandlerService,
        db_access: DbAccess,
        model_handler: ModelHandler,
    ):
        super().__init__()
        self.message_bus = message_bus
        self.merge_deferred_edges_listener: Optional[Task[None]] = None
        self.subscription_handler = subscription_handler
        self.subscriber: Optional[Subscriber] = None
        self.task_handler_service = task_handler_service
        self.db_access = db_access
        self.model_handler = model_handler

    async def merge_deferred_edges(self, task_ids: List[TaskId]) -> DeferredMergeResult:
        deferred_outer_edge_db = self.db_access.deferred_outer_edge_db
        pending_edges = []
        for task_id in task_ids:
            pending_edges.extend(await deferred_outer_edge_db.all_for_task(task_id))
        if pending_edges:
            processed = 0
            first = min(pending_edges, key=lambda x: x.created_at)
            graph_db = self.db_access.get_graph_db(first.graph)
            model = await self.model_handler.load_model(first.graph)

            async def find_node_id(selector: NodeSelector) -> Optional[NodeId]:
                try:
                    if isinstance(selector, ByNodeId):
                        node = await graph_db.get_node(model, selector.value)
                        return node.get("id") if node else None
                    else:
                        query = parse_query(selector.query).with_limit(2)
                        async with await graph_db.search_list(QueryModel(query, model), consistent=True) as cursor:
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

            edges: Dict[EdgeType, List[Tuple[NodeId, NodeId, DeferredEdge]]] = defaultdict(list)
            for pending_edge in pending_edges:
                for edge in pending_edge.edges:
                    from_id = await find_node_id(edge.from_node)
                    to_id = await find_node_id(edge.to_node)
                    processed += 1
                    if from_id and to_id:
                        edges[edge.edge_type].append((from_id, to_id, edge))

            # apply edges in graph
            updated, deleted = await graph_db.update_deferred_edges(edges, first.created_at)
            # delete processed edge definitions
            for task_id in task_ids:
                await deferred_outer_edge_db.delete_for_task(task_id)
            log.info(f"DeferredEdges: {processed} edges: {updated} updated, {deleted} deleted. ({task_ids})")
            return DeferredMergeResult(processed, updated, deleted)
        else:
            log.info(f"MergeOuterEdgesHandler: no pending edges found. ({task_ids})")
            return DeferredMergeResult(0, 0, 0)

    async def __handle_events(self, subscription_done: Future[None]) -> None:
        async with self.message_bus.subscribe(subscriber_id, [merge_deferred_edges]) as events:
            subscription_done.set_result(None)
            while True:
                event = await events.get()
                if isinstance(event, Action) and event.message_type == merge_deferred_edges:
                    await self.merge_deferred_edges([event.task_id])
                    await self.task_handler_service.handle_action_done(event.done(subscriber_id))

    async def start(self) -> None:
        subscription_done = asyncio.get_event_loop().create_future()
        self.subscriber = await self.subscription_handler.add_subscription(
            subscriber_id, merge_deferred_edges, True, timedelta(seconds=30)
        )
        self.merge_deferred_edges_listener = asyncio.create_task(
            self.__handle_events(subscription_done), name=subscriber_id
        )
        await subscription_done

    async def stop(self) -> None:
        if self.merge_deferred_edges_listener:
            with suppress(Exception):
                self.merge_deferred_edges_listener.cancel()
        if self.subscriber:
            await self.subscription_handler.remove_subscription(subscriber_id, merge_deferred_edges)
