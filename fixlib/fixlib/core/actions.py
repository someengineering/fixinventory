import threading
import time
from contextlib import suppress, AbstractContextManager
from itertools import islice
from logging import Logger
from queue import Queue

from websocket import WebSocketApp, WebSocket  # type: ignore
import requests
import json
from concurrent.futures import ThreadPoolExecutor

from attr import define, evolve, field
from requests import Response

from fixlib.core.progress import Progress, ProgressDone
from fixlib.logger import log
from fixlib.event import EventType, remove_event_listener, add_event_listener, Event
from fixlib.args import ArgumentParser
from fixlib.jwt import encode_jwt_to_headers
from fixlib.core.ca import TLSData
from typing import Callable, Dict, Optional, List, Any, Set

from fixlib.types import Json
from fixlib.utils import utc_str


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
            logger.warning(self.context_str + message, exc_info=True)
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
                    "message": self.context_str + message[0:500],  # truncate message to 500 characters
                },
            }
        )

    def with_context(self, *context: str) -> "CoreFeedback":
        return evolve(self, context=list(context))

    def child_context(self, *context: str) -> "CoreFeedback":
        return self.with_context(*(self.context + list(context)))


@define
class ErrorSummary:
    error: str
    message: str
    info: bool
    region: Optional[str] = None
    service_actions: Dict[str, Set[str]] = field(factory=dict)


class ErrorAccumulator:
    def __init__(self) -> None:
        self.regional_errors: Dict[Optional[str], Dict[str, ErrorSummary]] = {}

    def add_error(
        self, as_info: bool, error_kind: str, service: str, action: str, message: str, region: Optional[str] = None
    ) -> None:
        if region not in self.regional_errors:
            self.regional_errors[region] = {}
        regional_errors = self.regional_errors[region]

        key = f"{error_kind}:{message}:{as_info}"
        if key not in regional_errors:
            regional_errors[key] = ErrorSummary(error_kind, message, as_info, region, {service: {action}})
        else:
            summary = regional_errors[key]
            if service not in summary.service_actions:
                summary.service_actions[service] = {action}
            else:
                summary.service_actions[service].add(action)

    def report_region(self, core_feedback: CoreFeedback, region: Optional[str]) -> None:
        if regional_errors := self.regional_errors.get(region):
            # reset errors for this region
            self.regional_errors[region] = {}
            # add region as context
            feedback = core_feedback.child_context(region) if region else core_feedback
            # send to core
            for err in regional_errors.values():
                srv_acts = []
                for service, actions in islice(err.service_actions.items(), 10):
                    suffix = " and more" if len(actions) > 3 else ""
                    srv_acts.append(service + ": " + ", ".join(islice(actions, 3)) + suffix)
                message = f"[{err.error}] {err.message} Services and actions affected: {', '.join(srv_acts)}"
                if len(err.service_actions) > 10:
                    message += " and more..."
                if err.info:
                    feedback.info(message)
                else:
                    feedback.error(message)

    def report_all(self, core_feedback: CoreFeedback) -> None:
        for region in self.regional_errors.keys():
            self.report_region(core_feedback, region)


class SuppressWithFeedback(AbstractContextManager[None]):
    def __init__(self, message: str, feedback: CoreFeedback, logger: Optional[Logger] = None) -> None:
        self.message = message
        self.feedback = feedback
        self.logger = logger

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Optional[bool]:
        if exc_type is not None:
            self.feedback.error(f"{self.message}: {exc_val}", self.logger)
            return True  # suppress exception
        return None


class CoreActions(threading.Thread):
    def __init__(
        self,
        identifier: str,
        fixcore_uri: str,
        fixcore_ws_uri: str,
        actions: Dict[str, Json],
        incoming_messages: Optional[Queue[Json]] = None,
        message_processor: Optional[Callable[[Json], Any]] = None,
        tls_data: Optional[TLSData] = None,
        max_concurrent_actions: int = 5,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.fixcore_uri = fixcore_uri
        self.fixcore_ws_uri = fixcore_ws_uri
        self.actions = actions
        self.message_processor = message_processor
        self.ws: Optional[WebSocketApp] = None
        self.incoming_messages = incoming_messages
        self.tls_data = tls_data
        self.shutdown_event = threading.Event()
        # one thread is taken by the queue listener
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_actions + 1, thread_name_prefix=self.identifier)
        self.__connected = False

    def connected(self) -> bool:
        return self.__connected

    def run(self) -> None:
        def listen_on_queue(in_messages: Queue[Json]) -> None:
            while not self.shutdown_event.is_set():
                with suppress(Exception):
                    message = in_messages.get(timeout=1)
                    log.debug("Got feedback message. Send it to core", message)
                    if self.ws:
                        self.ws.send(json.dumps(message))

        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        if self.incoming_messages:
            self.executor.submit(listen_on_queue, self.incoming_messages)
        while not self.shutdown_event.is_set():
            log.debug("Connecting to fixcore message bus")
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

        ws_uri = f"{self.fixcore_ws_uri}/subscriber/{self.identifier}/handle"
        log.debug(f"{self.identifier} connecting to {ws_uri}")
        headers: Dict[str, str] = {}
        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)
        try:
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
        finally:
            self.ws = None

    def shutdown(self, _: Optional[Event] = None) -> None:
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)
        log.debug("Received shutdown event - shutting down fixcore message bus listener")
        self.shutdown_event.set()
        self.executor.shutdown(wait=False, cancel_futures=True)
        if self.ws:
            self.ws.close()

    def register(self, action: str, data: Optional[Dict[str, str]] = None) -> bool:
        log.debug(f"{self.identifier} registering for {action} actions ({data})")
        return self.registration(action, requests.post, data)

    def unregister(self, action: str, data: Optional[Dict[str, str]] = None) -> bool:
        log.debug(f"{self.identifier} unregistering from {action} actions ({data})")
        return self.registration(action, requests.delete, data)

    def registration(
        self,
        action: str,
        client: Callable[..., Response],
        data: Optional[Dict[str, str]] = None,
    ) -> bool:
        url = f"{self.fixcore_uri}/subscriber/{self.identifier}/{action}"
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

    def on_message(self, _: WebSocket, message: str) -> None:
        self.executor.submit(self.process_message, message)

    def process_message(self, message: str) -> None:
        try:
            json_message: Json = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        log.debug(f"{self.identifier} received: {message}")
        if self.message_processor is not None and callable(self.message_processor):
            try:
                result: Json = self.message_processor(json_message)
                if result is None:
                    return
                if self.wait_for_ws() and self.ws:
                    log.debug(f"Sending reply {result}")
                    self.ws.send(json.dumps(result))
                else:
                    log.error(f"Unable to send reply {result}")
            except Exception:
                log.exception(f"Something went wrong while processing {message}")

    def on_error(self, _: WebSocket, e: Exception) -> None:
        log.debug(f"{self.identifier} message bus error: {e!r}")

    def on_close(self, _: WebSocket, close_status_code: int, close_msg: str) -> None:
        self.__connected = False
        log.debug(f"{self.identifier} disconnected from fixcore message bus: {close_status_code}: {close_msg}")

    def on_open(self, _: WebSocket) -> None:
        self.__connected = True
        log.debug(f"{self.identifier} connected to fixcore message bus")

    def on_ping(self, _: WebSocket, message: str) -> None:
        log.debug(f"{self.identifier} actions ping from fixcore message bus")

    def on_pong(self, _: WebSocket, message: str) -> None:
        log.debug(f"{self.identifier} actions pong from fixcore message bus")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--fixcore-subscriber-id",
            help="fixcore actions subscriber identifier (default: worker)",
            default="worker",
            dest="fixcore_subscriber_id",
        )
