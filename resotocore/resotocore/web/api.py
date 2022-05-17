import asyncio
import json
import logging
import os
import re
import shutil
import string
import tempfile
import uuid
from asyncio import Future
from contextlib import suppress
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from random import SystemRandom
from typing import AsyncGenerator, Any, Optional, Sequence, Union, List, Dict, AsyncIterator, Tuple, Callable, Awaitable

import prometheus_client
import yaml
from aiohttp import (
    web,
    WSMsgType,
    WSMessage,
    MultipartWriter,
    AsyncIterablePayload,
    BufferedReaderPayload,
    MultipartReader,
    ClientSession,
)
from aiohttp.abc import AbstractStreamWriter
from aiohttp.hdrs import METH_ANY
from aiohttp.web import Request, StreamResponse
from aiohttp.web_exceptions import HTTPNotFound, HTTPNoContent, HTTPOk, HTTPNotAcceptable
from aiohttp.web_routedef import AbstractRouteDef
from aiohttp_swagger3 import SwaggerFile, SwaggerUiSettings
from aiostream.core import Stream
from networkx.readwrite import cytoscape_data
from resotolib.jwt import encode_jwt

from resotocore.analytics import AnalyticsEventSender
from resotocore.cli.cli import CLI
from resotocore.cli.command import ListCommand, alias_names
from resotocore.cli.model import (
    ParsedCommandLine,
    CLIContext,
    OutputTransformer,
    PreserveOutputFormat,
    CLICommand,
    InternalPart,
    AliasTemplate,
)
from resotocore.config import ConfigHandler, ConfigValidation, ConfigEntity
from resotocore.console_renderer import ConsoleColorSystem, ConsoleRenderer
from resotocore.core_config import CoreConfig
from resotocore.db.db_access import DbAccess
from resotocore.db.graphdb import GraphDB
from resotocore.db.model import QueryModel
from resotocore.message_bus import MessageBus, Message, ActionDone, Action, ActionError
from resotocore.model.db_updater import merge_graph_process
from resotocore.model.graph_access import Section
from resotocore.model.model import Kind
from resotocore.model.model_handler import ModelHandler
from resotocore.model.typed_model import to_json, from_js, to_js_str, to_js
from resotocore.query import QueryParser
from resotocore.task.model import Subscription
from resotocore.task.subscribers import SubscriptionHandler
from resotocore.task.task_handler import TaskHandlerService
from resotocore.types import Json, JsonElement
from resotocore.util import uuid_str, force_gen, rnd_str, if_set, duration
from resotocore.web import auth
from resotocore.web.certificate_handler import CertificateHandler
from resotocore.web.content_renderer import result_binary_gen, single_result
from resotocore.web.directives import (
    metrics_handler,
    error_handler,
    on_response_prepare,
    cors_handler,
    enable_compression,
    default_middleware,
)
from resotocore.web.tsdb import tsdb
from resotocore.worker_task_queue import (
    WorkerTaskDescription,
    WorkerTaskQueue,
    WorkerTask,
    WorkerTaskResult,
    WorkerTaskInProgress,
)

log = logging.getLogger(__name__)


def section_of(request: Request) -> Optional[str]:
    section = request.match_info.get("section", request.query.get("section"))
    if section and section != "/" and section not in Section.content:
        raise AttributeError(f"Given section does not exist: {section}")
    return section


class Api:
    def __init__(
        self,
        db: DbAccess,
        model_handler: ModelHandler,
        subscription_handler: SubscriptionHandler,
        workflow_handler: TaskHandlerService,
        message_bus: MessageBus,
        event_sender: AnalyticsEventSender,
        worker_task_queue: WorkerTaskQueue,
        cert_handler: CertificateHandler,
        config_handler: ConfigHandler,
        cli: CLI,
        query_parser: QueryParser,
        config: CoreConfig,
    ):
        self.db = db
        self.model_handler = model_handler
        self.subscription_handler = subscription_handler
        self.workflow_handler = workflow_handler
        self.message_bus = message_bus
        self.event_sender = event_sender
        self.worker_task_queue = worker_task_queue
        self.cert_handler = cert_handler
        self.config_handler = config_handler
        self.cli = cli
        self.query_parser = query_parser
        self.config = config
        self.app = web.Application(
            # note on order: the middleware is passed in the order provided.
            middlewares=[
                metrics_handler,
                auth.auth_handler(config),
                cors_handler,
                error_handler(config, event_sender),
                default_middleware(self),
            ]
        )
        self.app.on_response_prepare.append(on_response_prepare)
        self.session: Optional[ClientSession] = None
        self.in_shutdown = False
        self.websocket_handler: Dict[str, Tuple[Future[Any], web.WebSocketResponse]] = {}
        path_part = config.api.web_path.strip().strip("/").strip()
        web_path = "" if path_part == "" else f"/{path_part}"
        self.__add_routes(web_path)

    def __add_routes(self, prefix: str) -> None:
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../static")
        ui_route: List[AbstractRouteDef] = (
            [web.static(f"{prefix}/ui/", self.config.api.ui_path)]
            if self.config.api.ui_path and Path(self.config.api.ui_path).exists()
            else [web.get(f"{prefix}/ui/index.html", self.no_ui)]
        )
        tsdb_route = (
            [web.route(METH_ANY, prefix + "/tsdb/{tail:.+}", tsdb(self))] if self.config.api.tsdb_proxy_url else []
        )
        self.app.add_routes(
            [
                # Model operations
                web.get(prefix + "/model", self.get_model),
                web.get(prefix + "/model/uml", self.model_uml),
                web.patch(prefix + "/model", self.update_model),
                # CRUD Graph operations
                web.get(prefix + "/graph", self.list_graphs),
                web.get(prefix + "/graph/{graph_id}", self.get_node),
                web.post(prefix + "/graph/{graph_id}", self.create_graph),
                web.delete(prefix + "/graph/{graph_id}", self.wipe),
                # search the graph
                web.post(prefix + "/graph/{graph_id}/search/raw", self.raw),
                web.post(prefix + "/graph/{graph_id}/search/explain", self.explain),
                web.post(prefix + "/graph/{graph_id}/search/list", self.query_list),
                web.post(prefix + "/graph/{graph_id}/search/graph", self.query_graph_stream),
                web.post(prefix + "/graph/{graph_id}/search/aggregate", self.query_aggregation),
                # maintain the graph
                web.patch(prefix + "/graph/{graph_id}/nodes", self.update_nodes),
                web.post(prefix + "/graph/{graph_id}/merge", self.merge_graph),
                web.post(prefix + "/graph/{graph_id}/batch/merge", self.update_merge_graph_batch),
                web.get(prefix + "/graph/{graph_id}/batch", self.list_batches),
                web.post(prefix + "/graph/{graph_id}/batch/{batch_id}", self.commit_batch),
                web.delete(prefix + "/graph/{graph_id}/batch/{batch_id}", self.abort_batch),
                # node specific actions
                web.post(prefix + "/graph/{graph_id}/node/{node_id}/under/{parent_node_id}", self.create_node),
                web.get(prefix + "/graph/{graph_id}/node/{node_id}", self.get_node),
                web.patch(prefix + "/graph/{graph_id}/node/{node_id}", self.update_node),
                web.delete(prefix + "/graph/{graph_id}/node/{node_id}", self.delete_node),
                web.patch(prefix + "/graph/{graph_id}/node/{node_id}/section/{section}", self.update_node),
                # Subscriptions
                web.get(prefix + "/subscribers", self.list_all_subscriptions),
                web.get(prefix + "/subscribers/for/{event_type}", self.list_subscription_for_event),
                # Subscription
                web.get(prefix + "/subscriber/{subscriber_id}", self.get_subscriber),
                web.put(prefix + "/subscriber/{subscriber_id}", self.update_subscriber),
                web.delete(prefix + "/subscriber/{subscriber_id}", self.delete_subscriber),
                web.post(prefix + "/subscriber/{subscriber_id}/{event_type}", self.add_subscription),
                web.delete(prefix + "/subscriber/{subscriber_id}/{event_type}", self.delete_subscription),
                web.get(prefix + "/subscriber/{subscriber_id}/handle", self.handle_subscribed),
                # CLI
                web.post(prefix + "/cli/evaluate", self.evaluate),
                web.post(prefix + "/cli/execute", self.execute),
                web.get(prefix + "/cli/info", self.cli_info),
                # Event operations
                web.get(prefix + "/events", self.handle_events),
                # Worker operations
                web.get(prefix + "/work/queue", self.handle_work_tasks),
                web.get(prefix + "/work/create", self.create_work),
                web.get(prefix + "/work/list", self.list_work),
                # Serve static filed
                web.get(prefix, self.redirect_to_api_doc),
                web.static(prefix + "/static", static_path),
                # metrics
                web.get(prefix + "/metrics", self.metrics),
                # config operations
                web.get(prefix + "/configs", self.list_configs),
                web.put(prefix + "/config/{config_id}", self.put_config),
                web.get(prefix + "/config/{config_id}", self.get_config),
                web.patch(prefix + "/config/{config_id}", self.patch_config),
                web.delete(prefix + "/config/{config_id}", self.delete_config),
                # config model operations
                web.get(prefix + "/configs/validation", self.list_config_models),
                web.get(prefix + "/configs/model", self.get_configs_model),
                web.patch(prefix + "/configs/model", self.update_configs_model),
                web.put(prefix + "/config/{config_id}/validation", self.put_config_validation),
                web.get(prefix + "/config/{config_id}/validation", self.get_config_validation),
                # ca operations
                web.get(prefix + "/ca/cert", self.certificate),
                web.post(prefix + "/ca/sign", self.sign_certificate),
                # system operations
                web.get(prefix + "/system/ping", self.ping),
                web.get(prefix + "/system/ready", self.ready),
                # forwards
                web.get(prefix + "/tsdb", self.forward("/tsdb/")),
                web.get(prefix + "/ui", self.forward("/ui/index.html")),
                web.get(prefix + "/ui/", self.forward("/ui/index.html")),
                *ui_route,
                *tsdb_route,
            ]
        )
        SwaggerFile(
            self.app,
            spec_file=f"{static_path}/api-doc.yaml",
            swagger_ui_settings=SwaggerUiSettings(path=prefix + "/api-doc", layout="BaseLayout", docExpansion="none"),
        )

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        if not self.in_shutdown:
            self.in_shutdown = True
            for ws_id in list(self.websocket_handler):
                await self.clean_ws_handler(ws_id)
            if self.session:
                await self.session.close()

    async def clean_ws_handler(self, ws_id: str) -> None:
        with suppress(Exception):
            handler = self.websocket_handler.get(ws_id)
            if handler:
                self.websocket_handler.pop(ws_id, None)
                future, ws = handler
                future.cancel()
                log.info(f"Cleanup ws handler: {ws_id} ({len(self.websocket_handler)} active)")
                if not ws.closed:
                    await ws.close()

    @staticmethod
    def forward(to: str) -> Callable[[Request], Awaitable[StreamResponse]]:
        async def forward_to(_: Request) -> StreamResponse:
            return web.HTTPFound(to)

        return forward_to

    @staticmethod
    async def ping(_: Request) -> StreamResponse:
        return web.HTTPOk(text="pong", content_type="text/plain")

    @staticmethod
    async def ready(_: Request) -> StreamResponse:
        return web.HTTPOk(text="ok")

    async def list_configs(self, request: Request) -> StreamResponse:
        return await self.stream_response_from_gen(request, self.config_handler.list_config_ids())

    async def get_config(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        accept = request.headers.get("accept", "application/json")
        not_found = HTTPNotFound(text="No config with this id")
        if accept == "application/yaml":
            yml = await self.config_handler.config_yaml(config_id)
            return web.Response(body=yml.encode("utf-8"), content_type="application/yaml") if yml else not_found
        else:
            config = await self.config_handler.get_config(config_id)
            if config:
                headers = {"Resoto-Config-Revision": config.revision}
                return await single_result(request, config.config, headers)
            else:
                return not_found

    async def put_config(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        validate = request.query.get("validate", "true").lower() != "false"
        config = await self.json_from_request(request)
        result = await self.config_handler.put_config(ConfigEntity(config_id, config), validate)
        headers = {"Resoto-Config-Revision": result.revision}
        return await single_result(request, result.config, headers)

    async def patch_config(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        patch = await self.json_from_request(request)
        updated = await self.config_handler.patch_config(ConfigEntity(config_id, patch))
        headers = {"Resoto-Config-Revision": updated.revision}
        return await single_result(request, updated.config, headers)

    async def delete_config(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        await self.config_handler.delete_config(config_id)
        return HTTPNoContent()

    async def list_config_models(self, request: Request) -> StreamResponse:
        return await self.stream_response_from_gen(request, self.config_handler.list_config_validation_ids())

    async def get_config_validation(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        model = await self.config_handler.get_config_validation(config_id)
        return await single_result(request, to_js(model)) if model else HTTPNotFound(text="No model for this config.")

    async def get_configs_model(self, request: Request) -> StreamResponse:
        model = await self.config_handler.get_configs_model()
        return await single_result(request, to_js(model))

    async def update_configs_model(self, request: Request) -> StreamResponse:
        js = await self.json_from_request(request)
        kinds: List[Kind] = from_js(js, List[Kind])
        model = await self.config_handler.update_configs_model(kinds)
        return await single_result(request, to_js(model))

    async def put_config_validation(self, request: Request) -> StreamResponse:
        config_id = request.match_info["config_id"]
        js = await self.json_from_request(request)
        js["id"] = config_id
        config_model = from_js(js, ConfigValidation)
        model = await self.config_handler.put_config_validation(config_model)
        return await single_result(request, to_js(model))

    async def certificate(self, _: Request) -> StreamResponse:
        cert, fingerprint = self.cert_handler.authority_certificate
        headers = {
            "SHA256-Fingerprint": fingerprint,
            "Content-Disposition": 'attachment, filename="resoto_root_ca.pem"',
        }
        if self.config.args.psk:
            headers["Authorization"] = "Bearer " + encode_jwt({"sha256_fingerprint": fingerprint}, self.config.args.psk)
        return HTTPOk(headers=headers, body=cert, content_type="application/x-pem-file")

    async def sign_certificate(self, request: Request) -> StreamResponse:
        csr_bytes = await request.content.read()
        cert, fingerprint = self.cert_handler.sign(csr_bytes)
        headers = {"SHA256-Fingerprint": fingerprint}
        return HTTPOk(headers=headers, body=cert, content_type="application/x-pem-file")

    @staticmethod
    async def metrics(_: Request) -> StreamResponse:
        resp = web.Response(body=prometheus_client.generate_latest())
        resp.content_type = prometheus_client.CONTENT_TYPE_LATEST
        return resp

    async def list_all_subscriptions(self, request: Request) -> StreamResponse:
        subscribers = await self.subscription_handler.all_subscribers()
        return await single_result(request, to_json(subscribers))

    async def get_subscriber(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        subscriber = await self.subscription_handler.get_subscriber(subscriber_id)
        return self.optional_json(subscriber, f"No subscriber with id {subscriber_id}")

    async def list_subscription_for_event(self, request: Request) -> StreamResponse:
        event_type = request.match_info["event_type"]
        subscribers = await self.subscription_handler.list_subscriber_for(event_type)
        return await single_result(request, to_json(subscribers))

    async def update_subscriber(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        body = await self.json_from_request(request)
        subscriptions = from_js(body, List[Subscription])
        sub = await self.subscription_handler.update_subscriptions(subscriber_id, subscriptions)
        return await single_result(request, to_json(sub))

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
        return await single_result(request, to_js(sub))

    async def delete_subscription(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        event_type = request.match_info["event_type"]
        sub = await self.subscription_handler.remove_subscription(subscriber_id, event_type)
        return await single_result(request, to_js(sub))

    async def handle_subscribed(self, request: Request) -> StreamResponse:
        subscriber_id = request.match_info["subscriber_id"]
        subscriber = await self.subscription_handler.get_subscriber(subscriber_id)
        if subscriber_id in self.message_bus.active_listener:
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
        event_types: List[str],
        initial_messages: Optional[Sequence[Message]] = None,
    ) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        wsid = uuid_str()

        async def receive() -> None:
            try:
                async for msg in ws:
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
                            await self.message_bus.emit(message)
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Receive: message listener {listener_id}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        async def send() -> None:
            try:
                async with self.message_bus.subscribe(listener_id, event_types) as events:
                    while True:
                        event = await events.get()
                        await ws.send_str(to_js_str(event) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Send: message listener {listener_id}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(wsid)

        if initial_messages:
            for msg in initial_messages:
                await ws.send_str(to_js_str(msg) + "\n")

        to_wait = asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        self.websocket_handler[wsid] = (to_wait, ws)
        await to_wait
        return ws

    async def handle_work_tasks(self, request: Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        worker_id = uuid_str()
        task_param = request.query.get("task")
        if not task_param:
            raise AttributeError("A worker needs to define at least one task that it can perform")
        attrs = {k: re.split("\\s*,\\s*", v) for k, v in request.query.items() if k != "task"}
        task_descriptions = [WorkerTaskDescription(name, attrs) for name in re.split("\\s*,\\s*", task_param)]

        async def receive() -> None:
            try:
                async for msg in ws:
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
                log.info(f"Receive: worker:{worker_id}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(worker_id)

        async def send() -> None:
            try:
                async with self.worker_task_queue.attach(worker_id, task_descriptions) as tasks:
                    while True:
                        task = await tasks.get()
                        await ws.send_str(to_js_str(task.to_json()) + "\n")
            except Exception as ex:
                # do not allow any exception - it will destroy the async fiber and cleanup
                log.info(f"Send: worker:{worker_id}: {ex}. Hang up.")
            finally:
                await self.clean_ws_handler(worker_id)

        to_wait = asyncio.gather(asyncio.create_task(receive()), asyncio.create_task(send()))
        self.websocket_handler[worker_id] = (to_wait, ws)
        await to_wait
        return ws

    async def create_work(self, request: Request) -> StreamResponse:
        attrs = {k: v for k, v in request.query.items() if k != "task"}
        future = asyncio.get_event_loop().create_future()
        task = WorkerTask(uuid_str(), "test", attrs, {"some": "data", "foo": "bla"}, future, timedelta(seconds=3))
        await self.worker_task_queue.add_task(task)
        await future
        return web.HTTPOk()

    async def list_work(self, request: Request) -> StreamResponse:
        def wt_to_js(ip: WorkerTaskInProgress) -> Json:
            return {
                "task": ip.task.to_json(),
                "worker": ip.worker.worker_id,
                "retry_counter": ip.retry_counter,
                "deadline": to_json(ip.deadline),
            }

        return web.json_response([wt_to_js(ot) for ot in self.worker_task_queue.outstanding_tasks.values()])

    async def model_uml(self, request: Request) -> StreamResponse:
        output = request.query.get("output", "svg")
        show = request.query["show"].split(",") if "show" in request.query else None
        hide = request.query["hide"].split(",") if "hide" in request.query else None
        with_inheritance = request.query.get("with_inheritance", "true") != "false"
        with_base_classes = request.query.get("with_base_classes", "true") != "false"
        with_subclasses = request.query.get("with_subclasses", "false") != "false"
        dependency = set(request.query["dependency"].split(",")) if "dependency" in request.query else None
        with_predecessors = request.query.get("with_predecessors", "false") != "false"
        with_successors = request.query.get("with_successors", "false") != "false"
        with_properties = request.query.get("with_properties", "true") != "false"
        link_classes = request.query.get("link_classes", "false") != "false"
        result = await self.model_handler.uml_image(
            output=output,
            show_packages=show,
            hide_packages=hide,
            with_inheritance=with_inheritance,
            with_base_classes=with_base_classes,
            with_subclasses=with_subclasses,
            dependency_edges=dependency,
            with_predecessors=with_predecessors,
            with_successors=with_successors,
            with_properties=with_properties,
            link_classes=link_classes,
        )
        response = web.StreamResponse()
        mt = {"svg": "image/svg+xml", "png": "image/png"}
        response.headers["Content-Type"] = mt[output]
        await response.prepare(request)
        await response.write_eof(result)
        return response

    async def get_model(self, request: Request) -> StreamResponse:
        md = await self.model_handler.load_model()
        return await single_result(request, to_js(md.kinds.values()))

    async def update_model(self, request: Request) -> StreamResponse:
        js = await self.json_from_request(request)
        kinds: List[Kind] = from_js(js, List[Kind])
        model = await self.model_handler.update_model(kinds)
        return await single_result(request, to_js(model))

    async def get_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        node_id = request.match_info.get("node_id", "root")
        graph = self.db.get_graph_db(graph_id)
        model = await self.model_handler.load_model()
        node = await graph.get_node(model, node_id)
        if node is None:
            return web.HTTPNotFound(text=f"No such node with id {node_id} in graph {graph_id}")
        else:
            return await single_result(request, node)

    async def create_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        node_id = request.match_info.get("node_id", "some_existing")
        parent_node_id = request.match_info.get("parent_node_id", "root")
        graph = self.db.get_graph_db(graph_id)
        item = await self.json_from_request(request)
        md = await self.model_handler.load_model()
        node = await graph.create_node(md, node_id, item, parent_node_id)
        return await single_result(request, node)

    async def update_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        node_id = request.match_info.get("node_id", "some_existing")
        section = section_of(request)
        graph = self.db.get_graph_db(graph_id)
        patch = await self.json_from_request(request)
        md = await self.model_handler.load_model()
        node = await graph.update_node(md, node_id, patch, False, section)
        return await single_result(request, node)

    async def delete_node(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        node_id = request.match_info.get("node_id", "some_existing")
        if node_id == "root":
            raise AttributeError("Root node can not be deleted!")
        graph = self.db.get_graph_db(graph_id)
        await graph.delete_node(node_id)
        return web.HTTPNoContent()

    async def update_nodes(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        allowed = {*Section.content, "id", "revision"}
        updates: Dict[str, Json] = {}
        async for elem in self.to_json_generator(request):
            keys = set(elem.keys())
            assert keys.issubset(allowed), f"Invalid json. Allowed keys are: {allowed}"
            assert "id" in elem, f"No id given for element {elem}"
            assert keys.intersection(Section.content), f"No update provided for element {elem}"
            uid = elem["id"]
            assert uid not in updates, f"Only one update allowed per id! {elem}"
            del elem["id"]
            updates[uid] = elem
        db = self.db.get_graph_db(graph_id)
        model = await self.model_handler.load_model()
        result_gen = db.update_nodes(model, updates)
        return await self.stream_response_from_gen(request, result_gen)

    async def list_graphs(self, request: Request) -> StreamResponse:
        graphs = await self.db.list_graphs()
        return await single_result(request, graphs)

    async def create_graph(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        if "_" in graph_id:
            raise AttributeError("Graph name should not have underscores!")
        graph = await self.db.create_graph(graph_id)
        model = await self.model_handler.load_model()
        root = await graph.get_node(model, "root")
        return web.json_response(root)

    async def merge_graph(self, request: Request) -> StreamResponse:
        log.info("Received merge_graph request")
        graph_id = request.match_info.get("graph_id", "resoto")
        db = self.db.get_graph_db(graph_id)
        it = self.to_line_generator(request)
        info = await merge_graph_process(
            db, self.event_sender, self.config, it, self.config.graph_update.merge_max_wait_time(), None
        )
        return web.json_response(to_js(info))

    async def update_merge_graph_batch(self, request: Request) -> StreamResponse:
        log.info("Received put_sub_graph_batch request")
        graph_id = request.match_info.get("graph_id", "resoto")
        db = self.db.get_graph_db(graph_id)
        rnd = "".join(SystemRandom().choice(string.ascii_letters) for _ in range(12))
        batch_id = request.query.get("batch_id", rnd)
        it = self.to_line_generator(request)
        info = await merge_graph_process(
            db, self.event_sender, self.config, it, self.config.graph_update.merge_max_wait_time(), batch_id
        )
        return web.json_response(to_json(info), headers={"BatchId": batch_id})

    async def list_batches(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "resoto"))
        batch_updates = await graph_db.list_in_progress_updates()
        return web.json_response([b for b in batch_updates if b.get("is_batch")])

    async def commit_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "resoto"))
        batch_id = request.match_info.get("batch_id", "some_existing")
        await graph_db.commit_batch_update(batch_id)
        return web.HTTPOk(body="Batch committed.")

    async def abort_batch(self, request: Request) -> StreamResponse:
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "resoto"))
        batch_id = request.match_info.get("batch_id", "some_existing")
        await graph_db.abort_update(batch_id)
        return web.HTTPOk(body="Batch aborted.")

    async def graph_query_model_from_request(self, request: Request) -> Tuple[GraphDB, QueryModel]:
        section = section_of(request)
        query_string = await request.text()
        graph_db = self.db.get_graph_db(request.match_info.get("graph_id", "resoto"))
        q = await self.query_parser.parse_query(query_string, section, **request.query)
        m = await self.model_handler.load_model()
        return graph_db, QueryModel(q, m)

    async def raw(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        with_edges = request.query.get("edges") is not None
        query, bind_vars = await graph_db.to_query(query_model, with_edges)
        return web.json_response({"query": query, "bind_vars": bind_vars})

    async def explain(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        result = await graph_db.explain(query_model)
        return web.json_response(to_js(result))

    async def query_list(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        count = request.query.get("count", "true").lower() != "false"
        timeout = if_set(request.query.get("search_timeout"), duration)
        async with await graph_db.search_list(query_model, count, timeout) as cursor:
            return await self.stream_response_from_gen(request, cursor, cursor.count())

    async def cytoscape(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        result = await graph_db.search_graph(query_model)
        node_link_data = cytoscape_data(result)
        return web.json_response(node_link_data)

    async def query_graph_stream(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        count = request.query.get("count", "true").lower() != "false"
        timeout = if_set(request.query.get("search_timeout"), duration)
        async with await graph_db.search_graph_gen(query_model, count, timeout) as cursor:
            return await self.stream_response_from_gen(request, cursor, cursor.count())

    async def query_aggregation(self, request: Request) -> StreamResponse:
        graph_db, query_model = await self.graph_query_model_from_request(request)
        async with await graph_db.search_aggregation(query_model) as gen:
            return await self.stream_response_from_gen(request, gen)

    @staticmethod
    async def no_ui(_: Request) -> StreamResponse:
        return HTTPNotFound(
            text="The UI has not been configured and is not available. "
            "Please revisit your configuration (e.g. using the CLI command `config edit resoto.core`) "
            "and check the key: `api.ui_path`"
        )

    async def wipe(self, request: Request) -> StreamResponse:
        graph_id = request.match_info.get("graph_id", "resoto")
        if "truncate" in request.query:
            await self.db.get_graph_db(graph_id).wipe()
            return web.HTTPOk(body="Graph truncated.")
        else:
            await self.db.delete_graph(graph_id)
            return web.HTTPOk(body="Graph deleted.")

    async def cli_info(self, _: Request) -> StreamResponse:
        def cmd_json(cmd: CLICommand) -> Json:
            return {
                "name": cmd.name,
                "info": cmd.info(),
                "help": cmd.help(),
                "args": to_js(cmd.args_info(), force_dict=True),
                "source": cmd.allowed_in_source_position,
            }

        def alias_json(cmd: AliasTemplate) -> Json:
            return {"name": cmd.name, "info": cmd.info, "help": cmd.help()}

        commands = [cmd_json(cmd) for cmd in self.cli.direct_commands.values() if not isinstance(cmd, InternalPart)]
        replacements = self.cli.replacements()
        return web.json_response(
            {
                "commands": commands,
                "replacements": replacements,
                "alias_names": alias_names(),
                "alias_templates": [alias_json(alias) for alias in self.cli.alias_templates.values()],
            }
        )

    @staticmethod
    def cli_context_from_request(request: Request) -> CLIContext:
        try:
            columns = int(request.headers.get("Resoto-Shell-Columns", "120"))
            rows = int(request.headers.get("Resoto-Shell-Rows", "50"))
            terminal = request.headers.get("Resoto-Shell-Terminal", "false") == "true"
            colors = ConsoleColorSystem.from_name(request.headers.get("Resoto-Shell-Color-System", "monochrome"))
            renderer = ConsoleRenderer(width=columns, height=rows, color_system=colors, terminal=terminal)
            return CLIContext(env=dict(request.query), console_renderer=renderer, source="api")
        except Exception as ex:
            log.debug("Could not create CLI context.", exc_info=ex)
            return CLIContext(
                env=dict(request.query), console_renderer=ConsoleRenderer.default_renderer(), source="api"
            )

    async def evaluate(self, request: Request) -> StreamResponse:
        ctx = self.cli_context_from_request(request)
        command = await request.text()
        parsed = await self.cli.evaluate_cli_command(command, ctx)

        def line_to_js(line: ParsedCommandLine) -> Json:
            parsed_commands = to_json(line.parsed_commands.commands)
            execute_commands = [{"cmd": part.command.name, "arg": part.arg} for part in line.executable_commands]
            return {"parsed": parsed_commands, "execute": execute_commands, "env": line.parsed_commands.env}

        return web.json_response([line_to_js(line) for line in parsed])

    async def execute(self, request: Request) -> StreamResponse:
        temp_dir: Optional[str] = None
        try:
            ctx = self.cli_context_from_request(request)
            if request.content_type.startswith("text"):
                command = (await request.text()).strip()
            elif request.content_type.startswith("multipart"):
                command = request.headers["Resoto-Shell-Command"].strip()
                temp = tempfile.mkdtemp()
                temp_dir = temp
                files = {}
                # for now we assume that all multi-parts are file uploads
                async for part in MultipartReader(request.headers, request.content):
                    name = part.name
                    if not name:
                        raise AttributeError("Multipart request: content disposition name is required!")
                    path = os.path.join(temp, rnd_str())  # use random local path to avoid clashes
                    files[name] = path
                    with open(path, "wb") as writer:
                        while not part.at_eof():
                            writer.write(await part.read_chunk())
                ctx = replace(ctx, uploaded_files=files)
            else:
                raise AttributeError(f"Not able to handle: {request.content_type}")

            # we want to eagerly evaluate the command, so that parse exceptions will throw directly here
            parsed = await self.cli.evaluate_cli_command(command, ctx)
            return await self.execute_parsed(request, command, parsed)
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir)

    async def execute_parsed(self, request: Request, command: str, parsed: List[ParsedCommandLine]) -> StreamResponse:
        # make sure, all requirements are fulfilled
        not_met_requirements = [not_met for line in parsed for not_met in line.unmet_requirements]
        # what is the accepted content type
        # only required for multipart requests
        boundary = "----cli"
        mp_response = web.StreamResponse(
            status=200, reason="OK", headers={"Content-Type": f"multipart/mixed;boundary={boundary}"}
        )

        async def list_or_gen(current: ParsedCommandLine) -> Tuple[Optional[int], Stream]:
            maybe_count, out_gen = await current.execute()
            if (
                request.headers.get("accept") == "text/plain"
                and current.executable_commands
                and not isinstance(current.executable_commands[-1].command, (OutputTransformer, PreserveOutputFormat))
            ):
                out_gen = await ListCommand(self.cli.dependencies).parse(ctx=current.ctx).flow(out_gen)

            return maybe_count, out_gen

        if not_met_requirements:
            requirements = [req for line in parsed for cmd in line.executable_commands for req in cmd.action.required]
            data = {"command": command, "env": dict(request.query), "required": to_json(requirements)}
            return web.json_response(data, status=424)
        elif len(parsed) == 1:
            first_result = parsed[0]
            count, generator = await list_or_gen(first_result)
            # flat the results from 0 or 1
            async with generator.stream() as streamer:
                gen = await force_gen(streamer)
                if first_result.produces.json:
                    return await self.stream_response_from_gen(request, gen, count)
                elif first_result.produces.file_path:
                    await mp_response.prepare(request)
                    await Api.multi_file_response(first_result, gen, boundary, mp_response)
                    return mp_response
                else:
                    raise AttributeError(f"Can not handle type: {first_result.produces}")
        elif len(parsed) > 1:
            await mp_response.prepare(request)
            for single in parsed:
                count, generator = await list_or_gen(single)
                async with generator.stream() as streamer:
                    gen = await force_gen(streamer)
                    if single.produces.json:
                        with MultipartWriter(repr(single.produces), boundary) as mp:
                            content_type, result_stream = await result_binary_gen(request, gen)
                            mp.append_payload(
                                AsyncIterablePayload(result_stream, content_type=content_type, headers=single.envelope)
                            )
                            await mp.write(mp_response, close_boundary=True)
                    elif single.produces.file_path:
                        await Api.multi_file_response(single, gen, boundary, mp_response)
                    else:
                        raise AttributeError(f"Can not handle type: {single.produces}")
            await mp_response.write_eof()
            return mp_response
        else:
            raise AttributeError("No command could be parsed!")

    @classmethod
    async def json_from_request(cls, request: Request) -> Json:
        if request.content_type in ["application/json"]:
            return await request.json()  # type: ignore
        elif request.content_type in ["application/yaml", "text/yaml"]:
            text = await request.text()
            return yaml.safe_load(text)  # type: ignore
        else:
            raise HTTPNotAcceptable(text="Only support json")

    @classmethod
    async def to_json_generator(cls, request: Request) -> AsyncGenerator[Json, None]:
        async for line in cls.to_line_generator(request):
            yield json.loads(line) if isinstance(line, bytes) else line

    @staticmethod
    def to_line_generator(request: Request) -> AsyncGenerator[Union[bytes, Json], None]:
        async def stream_lines() -> AsyncGenerator[Union[bytes, Json], None]:
            async for line in request.content:
                if len(line.strip()) == 0:
                    continue
                yield line

        async def stream_json_array() -> AsyncGenerator[Union[bytes, Json], None]:
            js_elem = await request.json()
            if isinstance(js_elem, list):
                for doc in js_elem:
                    yield doc
            elif isinstance(js_elem, dict):
                yield js_elem
            else:
                log.warning(f"Received json is neither array nor document: {js_elem}! Ignore.")

        if request.content_type == "application/json":
            return stream_json_array()
        elif request.content_type in ["application/x-ndjson", "application/ndjson"]:
            return stream_lines()
        else:
            raise AttributeError("Can not read graph. Currently supported formats: json and ndjson!")

    @staticmethod
    def optional_json(o: Any, hint: str) -> StreamResponse:
        if o:
            return web.json_response(to_json(o))
        else:
            return web.HTTPNotFound(text=hint)

    @staticmethod
    async def stream_response_from_gen(
        request: Request,
        gen_in: AsyncIterator[JsonElement],
        count: Optional[int] = None,
        additional_header: Optional[Dict[str, str]] = None,
    ) -> StreamResponse:
        # force the async generator, to get an early exception in case of failure
        gen = await force_gen(gen_in)
        content_type, result_gen = await result_binary_gen(request, gen)
        count_header = {"Resoto-Shell-Element-Count": str(count)} if count else {}
        hdr = additional_header or {}
        response = web.StreamResponse(status=200, headers={**hdr, "Content-Type": content_type, **count_header})
        enable_compression(request, response)
        writer: AbstractStreamWriter = await response.prepare(request)  # type: ignore
        cr = "\n".encode("utf-8")
        async for data in result_gen:
            await writer.write(data + cr)
        await response.write_eof()
        return response

    @staticmethod
    async def multi_file_response(
        cmd_line: ParsedCommandLine, results: AsyncIterator[str], boundary: str, response: StreamResponse
    ) -> None:
        async for file_path in results:
            path = Path(file_path)
            if not (path.exists() and path.is_file()):
                raise HTTPNotFound(text=f"No file with this path: {file_path}")
            with open(path.absolute(), "rb") as content:
                with MultipartWriter(boundary=boundary) as mp:
                    pl = BufferedReaderPayload(
                        content, content_type="application/octet-stream", filename=path.name, headers=cmd_line.envelope
                    )
                    mp.append_payload(pl)
                    await mp.write(response, close_boundary=True)
