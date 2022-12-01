from __future__ import annotations
import json
import queue
import threading
import time
from typing import Callable, Dict, Optional, List, Any
from urllib.parse import urlunsplit, urlsplit

import jsons
import websocket
from attrs import define, field
from resotolib.args import ArgumentParser
from resotolib.baseresources import BaseResource
from resotolib.config import current_config
from resotolib.core.ca import TLSData
from resotolib.core.model_export import node_to_dict, node_from_dict
from resotolib.event import EventType, remove_event_listener, add_event_listener, Event
from resotolib.jwt import encode_jwt_to_headers
from resotolib.logger import log
from resotolib.core.custom_command import CommandDefinition
from resotolib.types import Json, JsonElement


@define
class CoreTaskResult:
    task_id: str
    data: JsonElement = None
    error: Optional[str] = None

    def to_json(self) -> Json:
        if self.error:
            return {"task_id": self.task_id, "result": "error", "error": self.error}
        else:
            return {"task_id": self.task_id, "result": "done", "data": self.data}


@define
class CoreTaskHandler:
    name: str
    info: str
    description: str
    handler: Callable[[Json], JsonElement]
    expect_node_result: bool = False
    filter: Dict[str, List[str]] = field(factory=dict)
    allowed_on_kind: Optional[str] = None
    args_description: Dict[str, str] = field(factory=dict)

    def execute(self, message: Json) -> CoreTaskResult:
        task_id = message["task_id"]  # fail if there is no task_id
        try:
            task_data: Json = message.get("data", {})
            result = self.handler(task_data)
            return CoreTaskResult(task_id=task_id, data=result)
        except Exception as e:
            log.debug(f"Error while executing task {self.name}: {e}")
            return CoreTaskResult(task_id=task_id, error=str(e))

    def matches(self, js: Json) -> bool:
        attrs: Json = js.get("attrs")
        if js.get("task_name") != self.name or not isinstance(attrs, dict):
            return False
        return all((attrs.get(n) in f) for n, f in self.filter.items())

    def core_json(self) -> Json:
        return {
            "name": self.name,
            "info": self.info,
            "description": self.description,
            "filter": self.filter,
            "expect_node_result": self.expect_node_result,
            "args_description": self.args_description,
            "allowed_on_kind": self.allowed_on_kind,
        }

    @staticmethod
    def from_definition(target: Any, wtd: CommandDefinition) -> CoreTaskHandler:
        def handle_message(message: Json) -> JsonElement:
            node_data = message.get("node", {})
            args = message.get("args", [])
            return wtd.fn(target, current_config(), node_data, args)

        def handle_resource(message: Json) -> JsonElement:
            node_data = message.get("node", {})
            node = node_from_dict(node_data, include_select_ancestors=True) if node_data else None
            args = message.get("args", [])
            result = wtd.fn(target, current_config(), node, args)
            # expect either a base resource or json element as result
            if isinstance(result, BaseResource):
                return node_to_dict(result)
            else:
                return result

        to_call = handle_resource if wtd.expect_resource else handle_message
        return CoreTaskHandler(
            name=wtd.name,
            info=wtd.info,
            args_description=wtd.args_description,
            description=wtd.description,
            filter=wtd.filter,
            expect_node_result=wtd.expect_node_result,
            allowed_on_kind=wtd.allowed_on_kind,
            handler=to_call,
        )


class CoreTasks(threading.Thread):
    def __init__(
        self,
        identifier: str,
        resotocore_ws_uri: str,
        task_handler: List[CoreTaskHandler],
        max_workers: int = 20,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.resotocore_ws_uri = resotocore_ws_uri
        self.task_handler = task_handler
        self.max_workers = max_workers
        self.tls_data = tls_data
        self.ws = None
        self.shutdown_event = threading.Event()
        self.queue: queue.Queue[Json] = queue.Queue()

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        for i in range(self.max_workers):
            threading.Thread(target=self.worker, daemon=True, name=f"worker-{i}").start()

        while not self.shutdown_event.is_set():
            log.debug("Connecting to resotocore task queue")
            try:
                self.connect()
            except Exception as e:
                log.error(e)
            time.sleep(1)

    def worker(self) -> None:
        while not self.shutdown_event.is_set():
            message = self.queue.get()
            log.debug(f"{self.identifier} received: {message}")
            for handler in self.task_handler:
                if handler.matches(message):
                    try:
                        result = handler.execute(message)
                        log.debug(f"Sending reply {result.to_json()}")
                        self.ws.send(json.dumps(result.to_json()))
                    except Exception as ex:
                        log.exception(f"Something went wrong while processing {message}")
                        if task_id := message.get("task_id"):
                            self.ws.send(jsons.dumps(CoreTaskResult(task_id, error=str(ex)).to_json()))
                    break
            self.queue.task_done()

    def connect(self) -> None:
        resotocore_ws_uri_split = urlsplit(self.resotocore_ws_uri)
        scheme = resotocore_ws_uri_split.scheme
        netloc = resotocore_ws_uri_split.netloc
        path = resotocore_ws_uri_split.path + "/work/queue"
        ws_uri = urlunsplit((scheme, netloc, path, "", ""))

        log.debug(f"{self.identifier} connecting to {ws_uri}")
        headers = {}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        self.ws = websocket.WebSocketApp(
            ws_uri,
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
        )
        sslopt = None
        if self.tls_data:
            sslopt = {"ca_certs": self.tls_data.ca_cert_path}
        self.ws.run_forever(sslopt=sslopt, ping_interval=20, ping_timeout=10, ping_payload="ping")

    def shutdown(self, event: Event = None) -> None:
        log.debug("Received shutdown event - shutting down resotocore task queue listener")
        self.shutdown_event.set()
        if self.ws:
            self.ws.close()

    def on_message(self, ws, message):
        try:
            message: Json = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        self.queue.put(message)

    def on_error(self, ws, e):
        log.debug(f"{self.identifier} event bus error: {e!r}")

    def on_close(self, ws, close_status_code, close_msg):
        log.debug(f"{self.identifier} disconnected from resotocore task queue")

    def on_open(self, ws):
        log.debug(f"{self.identifier} connected to resotocore, register at task queue")
        # when we are connected, we register at the task queue
        # by sending all task handler definitions
        ws.send(json.dumps([handler.core_json() for handler in self.task_handler]))

    def on_ping(self, ws, message):
        log.debug(f"{self.identifier} tasks ping from resotocore message bus")

    def on_pong(self, ws, message):
        log.debug(f"{self.identifier} tasks pong from resotocore message bus")
