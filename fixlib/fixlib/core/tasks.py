from __future__ import annotations

import json
import queue
import threading
import time
from typing import Callable, Dict, Optional, List, Any
from urllib.parse import urlunsplit, urlsplit

from attrs import define, field
from websocket import WebSocketApp, WebSocket  # type: ignore

from fixlib.args import ArgumentParser
from fixlib.baseresources import BaseResource
from fixlib.config import current_config
from fixlib.core.ca import TLSData
from fixlib.core.custom_command import CommandDefinition
from fixlib.core.model_export import node_to_dict, node_from_dict
from fixlib.event import EventType, remove_event_listener, add_event_listener, Event
from fixlib.json import to_json_str
from fixlib.jwt import encode_jwt_to_headers
from fixlib.logger import log
from fixlib.types import Json, JsonElement


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
            log.debug(f"Error while executing task {self.name}: {e}", exc_info=True)
            return CoreTaskResult(task_id=task_id, error=str(e))

    def matches(self, js: Json) -> bool:
        attrs: Json = js.get("attrs", {})
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
            return wtd.fn(target, current_config(), node_data, args)  # type: ignore

        def handle_resource(message: Json) -> JsonElement:
            node_data = message.get("node", {})
            node = node_from_dict(node_data, include_select_ancestors=True) if node_data else None
            args = message.get("args", [])
            result = wtd.fn(target, current_config(), node, args)
            # expect either a base resource or json element as result
            if isinstance(result, BaseResource):
                return node_to_dict(result)
            else:
                return result  # type: ignore

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
        fixcore_ws_uri: str,
        task_handler: List[CoreTaskHandler],
        max_workers: int = 20,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.fixcore_ws_uri = fixcore_ws_uri
        self.task_handler = task_handler
        self.max_workers = max_workers
        self.tls_data = tls_data
        self.ws: Optional[WebSocketApp] = None
        self.shutdown_event = threading.Event()
        self.queue: queue.Queue[Json] = queue.Queue()
        self.__connected = False

    def connected(self) -> bool:
        return self.__connected

    def __del__(self) -> None:
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        for i in range(self.max_workers):
            threading.Thread(target=self.worker, daemon=True, name=f"worker-{i}").start()

        while not self.shutdown_event.is_set():
            log.debug("Connecting to fixcore task queue")
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
                        if self.ws:
                            log.debug(f"Sending reply {result.to_json()}")
                            self.ws.send(json.dumps(result.to_json()))
                    except Exception as ex:
                        log.exception(f"Something went wrong while processing {message}")
                        if (task_id := message.get("task_id")) and self.ws is not None:
                            self.ws.send(to_json_str(CoreTaskResult(task_id, error=str(ex)).to_json()))
                    break
            self.queue.task_done()

    def connect(self) -> None:
        fixcore_ws_uri_split = urlsplit(self.fixcore_ws_uri)
        scheme = fixcore_ws_uri_split.scheme
        netloc = fixcore_ws_uri_split.netloc
        path = fixcore_ws_uri_split.path + "/work/queue"
        ws_uri = urlunsplit((scheme, netloc, path, "", ""))

        log.debug(f"{self.identifier} connecting to {ws_uri}")
        headers: Dict[str, str] = {}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        self.ws = WebSocketApp(
            ws_uri,
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
        )
        sslopt: Dict[Any, Any] = {}
        if self.tls_data:
            sslopt = {"ca_certs": self.tls_data.ca_cert_path}
        self.ws.run_forever(sslopt=sslopt, ping_interval=20, ping_timeout=10, ping_payload="ping")

    def shutdown(self, _: Optional[Event] = None) -> None:
        log.debug("Received shutdown event - shutting down fixcore task queue listener")
        self.shutdown_event.set()
        if self.ws:
            self.ws.close()

    def on_message(self, _: WebSocket, message: str) -> None:
        try:
            jsom_message: Json = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        self.queue.put(jsom_message)

    def on_error(self, _: WebSocket, e: Exception) -> None:
        log.debug(f"{self.identifier} event bus error: {e!r}")

    def on_close(self, _: WebSocket, close_status_code: int, close_msg: str) -> None:
        self.__connected = False
        log.debug(f"{self.identifier} disconnected from fixcore task queue")

    def on_open(self, ws: WebSocket) -> None:
        self.__connected = True
        log.debug(f"{self.identifier} connected to fixcore, register at task queue")
        # when we are connected, we register at the task queue
        # by sending all task handler definitions
        ws.send(json.dumps([handler.core_json() for handler in self.task_handler]))

    def on_ping(self, _: WebSocket, message: str) -> None:
        log.debug(f"{self.identifier} tasks ping from fixcore message bus")

    def on_pong(self, _: WebSocket, message: str) -> None:
        log.debug(f"{self.identifier} tasks pong from fixcore message bus")
