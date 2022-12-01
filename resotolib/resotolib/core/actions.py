import threading
import time
from contextlib import suppress
from logging import Logger
from queue import Queue

import websocket
import requests
import json
from concurrent.futures import ThreadPoolExecutor

from attr import define, evolve, field

from resotolib.core.progress import Progress, ProgressDone
from resotolib.logger import log
from resotolib.event import EventType, remove_event_listener, add_event_listener, Event
from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.core.ca import TLSData
from typing import Callable, Dict, Optional, List

from resotolib.types import Json
from resotolib.utils import utc_str


@define(frozen=True)
class CoreFeedback:
    task_id: str
    step_name: str
    message_type: str
    core_messages: Queue[Json]
    context: List[str] = field(factory=list)

    def progress_done(self, name: str, current: int, total: int, context: Optional[List[str]] = None) -> None:
        self.progress(ProgressDone(name, current, total, path=context or self.context))

    def progress(self, progress: Progress) -> None:
        message = {
            "kind": "action_progress",
            "message_type": self.message_type,
            "data": {
                "task": self.task_id,
                "step": self.step_name,
                "context": self.context,
                "progress": progress.to_json(),
                "at": utc_str(),
            },
        }
        self.core_messages.put(message)

    def info(self, message: str, logger: Optional[Logger] = None) -> None:
        if logger:
            logger.warning(self.context_str + message)
        self._info_message("info", message)

    def error(self, message: str, logger: Optional[Logger] = None) -> None:
        if logger:
            logger.error(self.context_str + message)
        self._info_message("error", message)

    @property
    def context_str(self) -> str:
        return "[" + (":".join(self.context)) + "] " if self.context else ""

    def _info_message(self, level: str, message: str) -> None:
        self.core_messages.put(
            {
                "kind": "action_info",
                "message_type": self.message_type,
                "data": {
                    "task": self.task_id,
                    "step": self.step_name,
                    "level": level,
                    "message": self.context_str + message,
                },
            }
        )

    def with_context(self, *context: str) -> "CoreFeedback":
        return evolve(self, context=list(context))


class CoreActions(threading.Thread):
    def __init__(
        self,
        identifier: str,
        resotocore_uri: str,
        resotocore_ws_uri: str,
        actions: Dict,
        incoming_messages: Optional[Queue[Json]] = None,
        message_processor: Optional[Callable] = None,
        tls_data: Optional[TLSData] = None,
        max_concurrent_actions: int = 5,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.resotocore_uri = resotocore_uri
        self.resotocore_ws_uri = resotocore_ws_uri
        self.actions = actions
        self.message_processor = message_processor
        self.ws = None
        self.incoming_messages = incoming_messages
        self.tls_data = tls_data
        self.shutdown_event = threading.Event()
        # one thread is taken by the queue listener
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_actions + 1, thread_name_prefix=self.identifier)

    def run(self) -> None:
        def listen_on_queue(in_messages: Queue) -> None:
            while not self.shutdown_event.is_set():
                with suppress(Exception):
                    message = in_messages.get(timeout=1)
                    log.debug("Got feedback message. Send it to core", message)
                    self.ws.send(json.dumps(message))

        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        if self.incoming_messages:
            self.executor.submit(listen_on_queue, self.incoming_messages)
        while not self.shutdown_event.is_set():
            log.debug("Connecting to resotocore message bus")
            try:
                self.connect()
            except Exception as e:
                log.error(e)
            time.sleep(1)

    def wait_for_ws(self, timeout: int = 10) -> bool:
        start = time.time()
        while self.ws is None and time.time() - start < timeout and not self.shutdown_event.is_set():
            time.sleep(0.1)
        return self.ws is not None

    def connect(self) -> None:
        for event, data in self.actions.items():
            if not isinstance(data, dict):
                data = None
            self.register(event, data)

        ws_uri = f"{self.resotocore_ws_uri}/subscriber/{self.identifier}/handle"
        log.debug(f"{self.identifier} connecting to {ws_uri}")
        headers = {}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        try:
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
        finally:
            self.ws = None

    def shutdown(self, event: Event = None) -> None:
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)
        log.debug("Received shutdown event - shutting down resotocore message bus listener")
        self.shutdown_event.set()
        for core_action in self.actions.keys():
            try:
                self.unregister(core_action)
            except Exception as e:
                log.error(e)
        self.executor.shutdown(wait=False, cancel_futures=True)
        if self.ws:
            self.ws.close()

    def register(self, action: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} registering for {action} actions ({data})")
        return self.registration(action, requests.post, data)

    def unregister(self, action: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} unregistering from {action} actions ({data})")
        return self.registration(action, requests.delete, data)

    def registration(self, action: str, client: Callable, data: Optional[Dict] = None) -> bool:
        url = f"{self.resotocore_uri}/subscriber/{self.identifier}/{action}"
        headers = {"accept": "application/json"}

        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        verify = None
        if self.tls_data:
            verify = self.tls_data.ca_cert_path

        r = client(url, headers=headers, params=data, verify=verify)
        if r.status_code != 200:
            raise RuntimeError(f'Error during (un)registration for "{action}"' f" actions: {r.content.decode('utf-8')}")
        return True

    def on_message(self, _: websocket.WebSocketApp, message: str) -> None:
        self.executor.submit(self.process_message, message)

    def process_message(self, message: str) -> None:
        try:
            message: Json = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        log.debug(f"{self.identifier} received: {message}")
        if self.message_processor is not None and callable(self.message_processor):
            try:
                result = self.message_processor(message)
                if self.wait_for_ws():
                    log.debug(f"Sending reply {result}")
                    self.ws.send(json.dumps(result))
                else:
                    log.error(f"Unable to send reply {result}")
            except Exception:
                log.exception(f"Something went wrong while processing {message}")

    def on_error(self, _: websocket.WebSocketApp, e: Exception) -> None:
        log.debug(f"{self.identifier} message bus error: {e!r}")

    def on_close(self, _: websocket.WebSocketApp, close_status_code: int, close_msg: str):
        log.debug(f"{self.identifier} disconnected from resotocore message bus: {close_status_code}: {close_msg}")

    def on_open(self, _: websocket.WebSocketApp) -> None:
        log.debug(f"{self.identifier} connected to resotocore message bus")

    def on_ping(self, _: websocket.WebSocketApp, message: str) -> None:
        log.debug(f"{self.identifier} actions ping from resotocore message bus")

    def on_pong(self, _: websocket.WebSocketApp, message: str) -> None:
        log.debug(f"{self.identifier} actions pong from resotocore message bus")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--resotocore-subscriber-id",
            help="resotocore actions subscriber identifier (default: worker)",
            default="worker",
            dest="resotocore_subscriber_id",
        )
