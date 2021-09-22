import asyncio
import json
import logging
import re
import string
import uuid
import os
from datetime import timedelta
from random import SystemRandom
from typing import AsyncGenerator, Callable, Awaitable, Any, Optional, Sequence

import yaml
from aiohttp import web, WSMsgType, WSMessage
from aiohttp.web_exceptions import HTTPRedirection
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse
from aiohttp_swagger3 import SwaggerFile, SwaggerUiSettings
from aiostream import stream
from networkx import MultiDiGraph
from networkx.readwrite import cytoscape_data

from core import feature
from core.cli.cli import CLI
from core.db.db_access import DbAccess
from core.db.model import QueryModel
from core.error import NotFoundError
from core.event_bus import EventBus, Message, ActionDone, Action, ActionError
from core.model.graph_access import GraphBuilder
from core.model.model import Kind, Model
from core.worker_task_queue import (
    WorkerTaskDescription,
    WorkerTaskQueue,
    WorkerTask,
    WorkerTaskResult,
    WorkerTaskInProgress,
)
from core.types import Json
from core.model.model_handler import ModelHandler
from core.model.typed_model import to_js, from_js, to_js_str
from core.query.query_parser import parse_query
from core.task.model import Subscription
from core.task.subscribers import SubscriptionHandler
from core.task.task_handler import TaskHandler
from core.util import force_gen, uuid_str

log = logging.getLogger(__name__)
RequestHandler = Callable[[Request], Awaitable[StreamResponse]]


class Api:
    def __init__(
        self,
        db: DbAccess,
        model_handler: ModelHandler,
        subscription_handler: SubscriptionHandler,
        workflow_handler: TaskHandler,
        event_bus: EventBus,
        worker_task_queue: WorkerTaskQueue,
        cli: CLI,
    ):
        self.db = db
        self.model_handler = model_handler
        self.subscription_handler = subscription_handler
        self.workflow_handler = workflow_handler
        self.event_bus = event_bus
        self.worker_task_queue = worker_task_queue
        self.cli = cli
        self.app = web.Application(middlewares=[self.error_handler])
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../static")
        self.app.add_routes(
            [
                # Model operations
                web.get("/model", self.get_model),
                web.get("/model/uml", self.model_uml),
                web.patch("/model", self.update_model),
                # CRUD Graph operations
                web.get("/graph", self.list_graphs),
                web.get("/graph/{graph_id}", self.get_node),
                web.post("/graph/{graph_id}", self.create_graph),
                web.delete("/graph/{graph_id}", self.wipe),
                # No section of the graph
                web.post("/graph/{graph_id}/query", self.query),
                web.post("/graph/{graph_id}/query/raw", self.raw),
                web.post("/graph/{graph_id}/query/explain", self.explain),
                web.post("/graph/{graph_id}/query/list", self.query_list),
                web.post("/graph/{graph_id}/query/graph", self.query_graph_stream),
                web.post("/graph/{graph_id}/query/aggregate", self.query_aggregation),
                web.get("/graph/{graph_id}/search", self.search_graph),
                web.post("/graph/{graph_id}/merge", self.merge_graph),
                web.post("/graph/{graph_id}/batch/merge", self.update_merge_graph_batch),
                web.get("/graph/{graph_id}/batch", self.list_batches),
                web.post("/graph/{graph_id}/batch/{batch_id}", self.commit_batch),
                web.delete("/graph/{graph_id}/batch/{batch_id}", self.abort_batch),
                web.post("/graph/{graph_id}/node/{node_id}/under/{parent_node_id}", self.create_node),
                web.get("/graph/{graph_id}/node/{node_id}", self.get_node),
                web.patch("/graph/{graph_id}/node/{node_id}", self.update_node),
                web.delete("/graph/{graph_id}/node/{node_id}", self.delete_node),
                # specific section of the graph
                web.patch("/graph/{graph_id}/{section}/node/{node_id}", self.update_node),
                web.post("/graph/{graph_id}/{section}/query", self.query),
                web.post("/graph/{graph_id}/{section}/query/raw", self.raw),
                web.post("/graph/{graph_id}/{section}/query/explain", self.explain),
                web.post("/graph/{graph_id}/{section}/query/list", self.query_list),
                web.post("/graph/{graph_id}/{section}/query/graph", self.query_graph_stream),
                web.post("/graph/{graph_id}/{section}/query/aggregate", self.query_aggregation),
                # Subscriptions
                web.get("/subscribers", self.list_all_subscriptions),
                web.get("/subscribers/for/{event_type}", self.list_subscription_for_event),
                # Subscription
                web.get("/subscriber/{subscriber_id}", self.get_subscriber),
                web.put("/subscriber/{subscriber_id}", self.update_subscriber),
                web.delete("/subscriber/{subscriber_id}", self.delete_subscriber),
                web.post("/subscriber/{subscriber_id}/{event_type}", self.add_subscription),
                web.delete("/subscriber/{subscriber_id}/{event_type}", self.delete_subscription),
                web.get("/subscriber/{subscriber_id}/handle", self.handle_subscribed),
                # CLI
                web.post("/cli/evaluate", self.evaluate),
                web.post("/cli/execute", self.execute),
                # Event operations
                web.get("/events", self.handle_events),
                # Worker operations
                web.get("/work/queue", self.handle_work_tasks),
                web.get("/work/create", self.create_work),
                web.get("/work/list", self.list_work),
                # Serve static filed
                web.get("", self.redirect_to_api_doc),
                web.static("/static", static_path),
            ]
        )
        SwaggerFile(
            self.app,
            spec_file=f"{static_path}/api-doc.yaml",
            swagger_ui_settings=SwaggerUiSettings(path="/api-doc", layout="BaseLayout", docExpansion="none"),
        )

    async def list_all_subscriptions(self, _: Request) -> StreamResponse:
        subscribers = await self.subscription_handler.all_subscribers()
        return web.json_response(to_js(subscribers))

    async def get_subscriber(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        subscriber = await self.subscription_handler.get_subscriber(subscriber_id)
        return self.optional_json(subscriber, f"No subscriber with id {subscriber_id}")

    async def list_subscription_for_event(self, request: Request) -> StreamResponse:
        event_type = request.match_info["event_type"]
        subscribers = await self.subscription_handler.list_subscriber_for(event_type)
        return web.json_response(to_js(subscribers))

    async def update_subscriber(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        body = await request.json()
        subscriptions = from_js(body, list[Subscription])
        sub = await self.subscription_handler.update_subscriptions(subscriber_id, subscriptions)
        return web.json_response(to_js(sub))

    async def delete_subscriber(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        await self.subscription_handler.remove_subscriber(subscriber_id)
        return web.HTTPNoContent()

    async def add_subscription(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        event_type = request.match_info["event_type"]
        timeout = timedelta(seconds=int(request.query.get("timeout", "60")))
        wait_for_completion = request.query.get("wait_for_completion", "true").lower() != "false"
        sub = await self.subscription_handler.add_subscription(subscriber_id, event_type, wait_for_completion, timeout)
        return web.json_response(to_js(sub))

    async def delete_subscription(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        event_type = request.match_info["event_type"]
        sub = await self.subscription_handler.remove_subscription(subscriber_id, event_type)
        return web.json_response(to_js(sub))

    async def handle_subscribed(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        subscriber = await self.subscription_handler.get_subscriber(subscriber_id)
        if subscriber_id in self.event_bus.active_listener:
            log.info(f"There is already a listener for subscriber: {subscriber_id}. Reject.")
            return web.HTTPTooManyRequests(text="Only one connection per subscriber is allowed!")
        elif subscriber and subscriber.subscriptions:
            pending = await self.workflow_handler.list_all_pending_actions_for(subscriber)
            return await self.listen_to_events(request, subscriber_id, list(subscriber.subscriptions.keys()), pending)
        else:
            return web.HTTPNotFound(text=f"No subscriber with this id: {subscriber_id} or no subscriptions")

    async def redirect_to_api_doc(self, request: Request) -> StreamResponse:
        raise web.HTTPFound("api-doc")

    async def handle_events(self, request: Request) -> StreamResponse:
        show = request.query["show"].split(",") if "show" in request.query else ["*"]
        return await self.listen_to_events(request, str(uuid.uuid1()), show)

    async def listen_to_events(
        self,
        request: Request,
        listener_id: str,
        event_types: list[str],
        initial_messages: Optional[Sequence[Message]] = None,
    ) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async def receive() -> None:
            async for msg in ws:
                try:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.info(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                        js = json.loads(msg.data)
                        if "data" in js:
                            js["data"]["subscriber_id"] = listener_id
                        message: Message = from_js(js, Message)
                        if isinstance(message, Action):
                            raise AttributeError("Actors should not emit action messages. ")
                        elif isinstance(message, ActionDone):
                            await self.workflow_handler.handle_action_done(message)
                        elif isinstance(message, ActionError):
                            await self.workflow_handler.handle_action_error(message)
                        else:
                            await self.event_bus.emit(message)
                except Exception as ex:
                    # do not allow any exception - it will destroy the async fiber and cleanup
                    log.info(f"Got an exception for event listener: {listener_id}. Hang up. {ex}")
                    await ws.close()

        async def send() -> None:
            try:
                with self.event_bus.subscribe(listener_id, event_types) as events:
                    while True:
                        event = await events.get()
                        await ws.send_str(to_js_str(event) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Got an exception for event sender: {listener_id}. Hang up. {ex}")
                await ws.close()

        if initial_messages:
            for msg in initial_messages:
                await ws.send_str(to_js_str(msg) + "\n")
        await asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        return ws

    async def handle_work_tasks(
        self,
        request: Request,
    ) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        worker_id = uuid_str()
        task_param = request.query.get("task")
        if not task_param:
            raise AttributeError("A worker needs to define at least one task that it can perform")
        attrs = {k: v for k, v in request.query.items() if k != "task"}
        task_descriptions = [WorkerTaskDescription(name, attrs) for name in re.split("\\s*,\\s*", task_param)]

        async def receive() -> None:
            async for msg in ws:
                try:
                    if isinstance(msg, WSMessage) and msg.type == WSMsgType.TEXT and len(msg.data.strip()) > 0:
                        log.info(f"Incoming message: type={msg.type} data={msg.data} extra={msg.extra}")
                        tr = from_js(json.loads(msg.data), WorkerTaskResult)
                        if tr.result == "error":
                            error = tr.error if tr.error else "worker signalled error without detailed error message"
                            await self.worker_task_queue.error_task(worker_id, tr.task_id, error)
                        elif tr.result == "done":
                            await self.worker_task_queue.acknowledge_task(worker_id, tr.task_id, tr.data)
                        else:
                            log.info(f"Do not understand this message: {msg.data}")

                except Exception as ex:
                    # do not allow any exception - it will destroy the async fiber and cleanup
                    log.debug(f"Error handling {worker_id}. Hang up. {ex}")
                    await ws.close()

        async def send() -> None:
            try:
                async with self.worker_task_queue.attach(worker_id, task_descriptions) as tasks:
                    while True:
                        task = await tasks.get()
                        await ws.send_str(to_js_str(task.to_json()) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.debug(f"Error handling event sender: {worker_id}. Hang up. {ex}")
                await ws.close()

        await asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        return ws

    async def create_work(self, request: Request) -> StreamResponse:
        attrs = {k: v for k, v in request.query.items() if k != "task"}
        future = asyncio.get_event_loop().create_future()
        task = WorkerTask(uuid_str(), "test", attrs, {"some": "data"}, future, timedelta(seconds=3))
        await self.worker_task_queue.add_task(task)
        await future
        return web.HTTPOk()

    async def list_work(self, request: Request) -> StreamResponse:
        def wt_to_js(ip: WorkerTaskInProgress) -> Json:
            return {
                "task": ip.task.to_json(),
                "worker": ip.worker.worker_id,
                "retry_counter": ip.retry_counter,
                "deadline": to_js(ip.deadline),
            }

        return web.json_response([wt_to_js(ot) for ot in self.worker_task_queue.outstanding_tasks.values()])

    async def model_uml(self, request: Request) -> StreamResponse:
        show = request.query["show"].split(",") if "show" in request.query else None
        result = await self.model_handler.uml_image(show)
        response = web.StreamResponse()
        response.headers["Content-Type"] = "image/svg+xml"
        await response.prepare(request)
        await response.write_eof(result)
        return response

    async def get_model(self, _: Request) -> StreamResponse:
        md = await self.model_handler.load_model()
        return web.json_response(to_js(md))

    async def update_model(self, request: Request) -> StreamResponse:
        js = await request.json()
        kinds: list[Kind] = from_js(js, list[Kind])
        model = await self.model_handler.update_model(kinds)
        return web.json_response(to_js(model))

    async def get_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        node_id = request.match_info.get("node_id", "root")
        graph = self.db.get_graph_db(graph_id)
        node = await graph.get_node(node_id)
        if node is None:
            return web.HTTPNotFound(text=f"No such node with id {node_id} in graph {graph_id}")
        else:
            return web.json_response(node)

    async def create_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        node_id = request.match_info.get("node_id", "some_existing")
        parent_node_id = request.match_info.get("parent_node_id", "root")
        graph = self.db.get_graph_db(graph_id)
        item = await request.json()
        md = await self.model_handler.load_model()
        node = await graph.create_node(md, node_id, item, parent_node_id)
        return web.json_response(node)

    async def update_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        node_id = request.match_info.get("node_id", "some_existing")
        section = request.match_info.get("section")
        graph = self.db.get_graph_db(graph_id)
        patch = await request.json()
        md = await self.model_handler.load_model()
        node = await graph.update_node(md, node_id, patch, section)
        return web.json_response(node)

    async def delete_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        node_id = request.match_info.get("node_id", "some_existing")
        if node_id == "root":
            raise AttributeError("Root node can not be deleted!")
        graph = self.db.get_graph_db(graph_id)
        await graph.delete_node(node_id)
        return web.HTTPNoContent()

    async def list_graphs(self, _: Request) -> StreamResponse:
        return web.json_response(await self.db.list_graphs())

    async def create_graph(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        if "_" in graph_id:
            raise AttributeError("Graph name should not have underscores!")
        graph = await self.db.create_graph(graph_id)
        root = await graph.get_node("root")
        return web.json_response(root)

    async def merge_graph(self, request: Request) -> StreamResponse:
        log.info("Received merge_graph request")
        md = await self.model_handler.load_model()
        graph = await self.read_graph(request, md)
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        _, info = await graph_db.merge_graph(graph, md)
        return web.json_response(to_js(info))

    async def update_merge_graph_batch(self, request: Request) -> StreamResponse:
        log.info("Received put_sub_graph_batch request")
        md = await self.model_handler.load_model()
        graph = await self.read_graph(request, md)
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        rnd = "".join(SystemRandom().choice(string.ascii_letters) for _ in range(12))
        batch_id = request.query.get("batch_id", rnd)
        _, info = await graph_db.merge_graph(graph, md, batch_id)
        return web.json_response(to_js(info), headers={"BatchId": batch_id})

    async def list_batches(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        batch_updates = await graph_db.list_in_progress_batch_updates()
        return web.json_response(batch_updates)

    async def commit_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        batch_id = request.match_info.get("batch_id", "some_existing")
        await graph_db.commit_batch_update(batch_id)
        return web.HTTPOk(body="Batch committed.")

    async def abort_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        batch_id = request.match_info.get("batch_id", "some_existing")
        await graph_db.abort_batch_update(batch_id)
        return web.HTTPOk(body="Batch aborted.")

    async def raw(self, request: Request) -> StreamResponse:
        query_string = await request.text()
        section = request.match_info.get("section")
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        m = await self.model_handler.load_model()
        q = parse_query(query_string)
        query, bind_vars = graph_db.to_query(QueryModel(q, m, section))
        return web.json_response({"query": query, "bind_vars": bind_vars})

    async def explain(self, request: Request) -> StreamResponse:
        section = request.match_info.get("section")
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = await graph_db.explain(QueryModel(q, m, section))
        return web.json_response(result)

    async def search_graph(self, request: Request) -> StreamResponse:
        if not feature.DB_SEARCH:
            raise AttributeError("This feature is not enabled!")
        if "term" not in request.query:
            raise AttributeError("Expect query parameter term to be defined!")
        query_string = request.query.get("term", "")
        limit = int(request.query.get("limit", "10"))
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        result = graph_db.search(query_string, limit)
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (to_js(a) async for a in result))

    async def query_list(self, request: Request) -> StreamResponse:
        section = request.match_info.get("section")
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = graph_db.query_list(QueryModel(q, m, section))
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (to_js(a) async for a in result))

    async def cytoscape(self, request: Request) -> StreamResponse:
        section = request.match_info.get("section")
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        result = await graph_db.query_graph(QueryModel(q, m, section))
        node_link_data = cytoscape_data(result)
        return web.json_response(node_link_data)

    async def query_graph_stream(self, request: Request) -> StreamResponse:
        section = request.match_info.get("section")
        query_string = await request.text()
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        gen = graph_db.query_graph_gen(QueryModel(q, m, section))
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, (item async for _, item in gen))

    async def query_aggregation(self, request: Request) -> StreamResponse:
        section = request.match_info.get("section")
        query_string = await request.text()
        q = parse_query(query_string)
        m = await self.model_handler.load_model()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "ns"))
        gen = graph_db.query_aggregation(QueryModel(q, m, section))
        # noinspection PyTypeChecker
        return await self.stream_response_from_gen(request, gen)

    async def query(self, request: Request) -> StreamResponse:
        if request.headers.get("format") == "cytoscape":
            return await self.cytoscape(request)
        if request.headers.get("format") == "graph":
            return await self.query_graph_stream(request)
        elif request.headers.get("format") == "list":
            return await self.query_list(request)
        else:
            return web.HTTPPreconditionFailed(text="Define format header. `format: [graph|list|cytoscape]`")

    async def wipe(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "ns")
        if "truncate" in request.query:
            await self.db.get_graph_db(graph_id).wipe()
            return web.HTTPOk(body="Graph truncated.")
        else:
            await self.db.delete_graph(graph_id)
            return web.HTTPOk(body="Graph deleted.")

    async def evaluate(self, request: Request) -> StreamResponse:
        # all query parameter become the env of this command
        env = request.query
        command = await request.text()
        parsed = await self.cli.evaluate_cli_command(command, **env)
        # simply return the structure: outer array lines, inner array commands
        # if the structure is returned, it means the command could be evaluated.
        return web.json_response([{part.name: arg for part, arg in line.parts_with_args} for line in parsed])

    async def execute(self, request: Request) -> StreamResponse:
        # all query parameter become the env of this command
        env = request.query
        command = await request.text()
        # we want to eagerly evaluate the command, so that parse exceptions will throw directly here
        parsed = await self.cli.evaluate_cli_command(command, **env)
        # flat the results from the different command lines
        result = stream.concat(stream.iterate(p.generator for p in parsed))
        async with result.stream() as streamer:
            return await self.stream_response_from_gen(request, streamer)

    @staticmethod
    async def read_graph(request: Request, md: Model) -> MultiDiGraph:
        async def stream_to_graph() -> MultiDiGraph:
            builder = GraphBuilder(md)
            async for line in request.content:
                if len(line.strip()) == 0:
                    continue
                builder.add_from_json(json.loads(line))
            log.info(f"Graph read into memory ({builder.nodes} nodes, {builder.edges} edges)")
            builder.check_complete()
            return builder.graph

        async def json_to_graph() -> MultiDiGraph:
            json_array = await request.json()
            log.info("Json read into memory")
            builder = GraphBuilder(md)
            if isinstance(json_array, list):
                for doc in json_array:
                    builder.add_from_json(doc)
            log.info(f"Graph read into memory ({builder.nodes} nodes, {builder.edges} edges)")
            builder.check_complete()
            return builder.graph

        if request.content_type == "application/json":
            return await json_to_graph()
        elif request.content_type == "application/x-ndjson":
            return await stream_to_graph()
        else:
            raise AttributeError("Can not read graph. Currently supported formats: json and ndjson!")

    @staticmethod
    def optional_json(o: Any, hint: str) -> StreamResponse:
        if o:
            return web.json_response(to_js(o))
        else:
            return web.HTTPNotFound(text=hint)

    @staticmethod
    async def stream_response_from_gen(request: Request, gen_in: AsyncGenerator[Json, None]) -> StreamResponse:
        gen = await force_gen(gen_in)

        async def respond_json() -> StreamResponse:
            response = web.StreamResponse(status=200, headers={"Content-Type": "application/json"})
            await response.prepare(request)
            await response.write("[".encode("utf-8"))
            first = True
            async for item in gen:
                js = json.dumps(to_js(item))
                sep = "," if not first else ""
                await response.write(f"{sep}\n{js}".encode("utf-8"))
                first = False
            await response.write_eof("]".encode("utf-8"))
            return response

        async def respond_ndjson() -> StreamResponse:
            response = web.StreamResponse(status=200, headers={"Content-Type": "application/x-ndjson"})
            await response.prepare(request)
            async for item in gen:
                js = json.dumps(to_js(item))
                await response.write(f"{js}\n".encode("utf-8"))
            await response.write_eof()
            return response

        async def respond_yaml() -> StreamResponse:
            response = web.StreamResponse(status=200, headers={"Content-Type": "text/yaml"})
            await response.prepare(request)
            flag = False
            async for item in gen:
                yml = yaml.dump(to_js(item), default_flow_style=False, sort_keys=False)
                sep = "---\n" if flag else ""
                await response.write(f"{sep}{yml}".encode("utf-8"))
                flag = True
            await response.write_eof()
            return response

        accept = request.headers.get("accept")
        if accept == "application/x-ndjson":
            return await respond_ndjson()
        elif accept == "application/json":
            return await respond_json()
        else:
            return await respond_yaml()

    @staticmethod
    async def error_handler(_: Any, handler: RequestHandler) -> RequestHandler:
        async def middleware_handler(request: Request) -> StreamResponse:
            try:
                response = await handler(request)
                return response
            except HTTPRedirection as e:
                # redirects are implemented as exceptions in aiohttp for whatever reason...
                raise e
            except NotFoundError as e:
                kind = type(e).__name__
                message = f"Error: {kind}\nMessage: {str(e)}"
                log.info(f"Request {request} has failed with exception: {message}", exc_info=e)
                return web.HTTPNotFound(text=message)
            except Exception as e:
                kind = type(e).__name__
                message = f"Error: {kind}\nMessage: {str(e)}"
                log.warning(f"Request {request} has failed with exception: {message}", exc_info=e)
                return web.HTTPBadRequest(text=message)

        return middleware_handler
