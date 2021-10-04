import os
import threading
import queue
import time
import websocket
import requests
import json
from cklib.logging import log
from cklib.utils import RWLock
from cklib.args import ArgumentParser
from cklib.jwt import encode_jwt_to_headers
from collections import defaultdict
from threading import Thread, Lock
from typing import Callable, Dict, Iterable, Optional, List
from enum import Enum
from urllib.parse import urlunsplit, urlencode, urlsplit


class EventType(Enum):
    """Defines Event Types

    Event().data definitions for EventType:
    STARTUP: None
    SHUTDOWN: {'reason': 'reason for shutdown', 'emergency': True/False}
    START_COLLECT: None
    COLLECT_BEGIN: cklib.graph.Graph
    COLLECT_FINISH: cklib.graph.Graph
    CLEANUP_PLAN: cklib.graph.Graph
    CLEANUP_BEGIN: cklib.graph.Graph
    CLEANUP_FINISH: cklib.graph.Graph
    PROCESS_BEGIN: cklib.graph.Graph
    PROCESS_FINISH: cklib.graph.Graph
    GENERATE_METRICS: cklib.graph.Graph
    """

    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    START_COLLECT = "start_collect"
    COLLECT_BEGIN = "collect_begin"
    COLLECT_FINISH = "collect_finish"
    CLEANUP_PLAN = "cleanup_plan"
    CLEANUP_BEGIN = "cleanup_begin"
    CLEANUP_FINISH = "cleanup_finish"
    PROCESS_BEGIN = "process_begin"
    PROCESS_FINISH = "process_finish"
    GENERATE_METRICS = "generate_metrics"


class Event:
    """An Event"""

    def __init__(self, event_type: EventType, data=None) -> None:
        self.event_type = event_type
        self.data = data


_events = defaultdict(dict)
_events_lock = RWLock()


def event_listener_registered(event_type: EventType, listener: Callable) -> bool:
    """Return whether listener is registered to event"""
    if _events is None:
        return False
    return event_type in _events.keys() and listener in _events[event_type].keys()


def dispatch_event(event: Event, blocking: bool = False) -> None:
    """Dispatch an Event"""
    waiting_str = "" if blocking else "not "
    log.debug(
        f"Dispatching event {event.event_type.name} and {waiting_str}waiting for"
        " listeners to return"
    )

    if event.event_type not in _events.keys():
        return

    with _events_lock.read_access:
        # Event listeners might unregister themselves during event dispatch
        # so we will work on a shallow copy while processing the current event.
        listeners = dict(_events[event.event_type])

    threads = {}
    for listener, listener_data in listeners.items():
        try:
            if listener_data["pid"] != os.getpid():
                continue

            if listener_data["one-shot"] and not listener_data["lock"].acquire(
                blocking=False
            ):
                log.error(
                    f"Not calling one-shot listener {listener} of type"
                    f" {type(listener)} - can't acquire lock"
                )
                continue

            log.debug(
                f"Calling listener {listener} of type {type(listener)}"
                f" (blocking: {listener_data['blocking']})"
            )
            thread_name = (
                f"{event.event_type.name.lower()}_event"
                f"-{getattr(listener, '__name__', 'anonymous')}"
            )
            t = Thread(target=listener, args=[event], name=thread_name)
            if blocking or listener_data["blocking"]:
                threads[t] = listener
            t.start()
        except Exception:
            log.exception("Caught unhandled event callback exception")
        finally:
            if listener_data["one-shot"]:
                log.debug(
                    f"One-shot specified for event {event.event_type.name} "
                    f"listener {listener} - removing event listener"
                )
                remove_event_listener(event.event_type, listener)
                listener_data["lock"].release()

    start_time = time.time()
    for thread, listener in threads.items():
        timeout = start_time + listeners[listener]["timeout"] - time.time()
        if timeout < 1:
            timeout = 1
        log.debug(
            f"Waiting up to {timeout:.2f}s for event listener {thread.name} to finish"
        )
        thread.join(timeout)
        log.debug(
            f"Event listener {thread.name} finished (timeout: {thread.is_alive()})"
        )


def add_event_listener(
    event_type: EventType,
    listener: Callable,
    blocking: bool = False,
    timeout: int = None,
    one_shot: bool = False,
) -> bool:
    """Add an Event Listener"""
    if not callable(listener):
        log.error(
            f"Error registering {listener} of type {type(listener)} with event"
            f" {event_type.name}"
        )
        return False

    if timeout is None:
        if hasattr(ArgumentParser.args, "event_timeout"):
            timeout = ArgumentParser.args.event_timeout
        else:
            timeout = 900

    log.debug(
        f"Registering {listener} with event {event_type.name}"
        f" (blocking: {blocking}, one-shot: {one_shot})"
    )
    with _events_lock.write_access:
        if not event_listener_registered(event_type, listener):
            _events[event_type][listener] = {
                "blocking": blocking,
                "timeout": timeout,
                "one-shot": one_shot,
                "lock": Lock(),
                "pid": os.getpid(),
            }
            return True
        return False


def remove_event_listener(event_type: EventType, listener: Callable) -> bool:
    """Remove an Event Listener"""
    with _events_lock.write_access:
        if event_listener_registered(event_type, listener):
            log.debug(f"Removing {listener} from event {event_type.name}")
            del _events[event_type][listener]
            if len(_events[event_type]) == 0:
                del _events[event_type]
            return True
        return False


def list_event_listeners() -> Iterable:
    with _events_lock.read_access:
        for event_type, listeners in _events.items():
            for listener, listener_data in listeners.items():
                yield (
                    f"{event_type.name}: {listener}, "
                    f"blocking: {listener_data['blocking']}, "
                    f"one-shot: {listener_data['one-shot']}"
                )


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--event-timeout",
        help="Event Listener Timeout in seconds (default 900)",
        default=900,
        dest="event_timeout",
        type=int,
    )


class CkEvents(threading.Thread):
    def __init__(
        self,
        identifier: str,
        ckcore_uri: str,
        ckcore_ws_uri: str,
        actions: Dict,
        message_processor: Optional[Callable] = None,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.ckcore_uri = ckcore_uri
        self.ckcore_ws_uri = ckcore_ws_uri
        self.actions = actions
        self.message_processor = message_processor
        self.ws = None
        self.shutdown_event = threading.Event()

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        while not self.shutdown_event.is_set():
            log.info("Connecting to ckcore message bus")
            try:
                self.connect()
            except Exception as e:
                log.error(e)
            time.sleep(10)

    def connect(self) -> None:
        for event, data in self.actions.items():
            if not isinstance(data, dict):
                data = None
            self.register(event, data)

        ws_uri = f"{self.ckcore_ws_uri}/subscriber/{self.identifier}/handle"
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
        )
        self.ws.run_forever()

    def shutdown(self, event: Event = None) -> None:
        log.debug("Received shutdown event - shutting down ckcore message bus listener")
        self.shutdown_event.set()
        for core_action in self.actions.keys():
            try:
                self.unregister(core_action)
            except RuntimeError as e:
                log.error(e)
        if self.ws:
            self.ws.close()

    def register(self, action: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} registering for {action} actions ({data})")
        return self.registration(action, requests.post, data)

    def unregister(self, action: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} unregistering from {action} actions ({data})")
        return self.registration(action, requests.delete, data)

    def registration(
        self, action: str, client: Callable, data: Optional[Dict] = None
    ) -> bool:
        url = f"{self.ckcore_uri}/subscriber/{self.identifier}/{action}"
        headers = {"accept": "application/json"}

        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        r = client(url, headers=headers, params=data)
        if r.status_code != 200:
            raise RuntimeError(
                f'Error during registration/unregistration for "{action}"'
                f" actions: {r.content.decode('utf-8')}"
            )
        return True

    def dispatch_event(self, message: Dict) -> bool:
        if self.ws is None:
            return False
        ws = websocket.create_connection(f"{self.ckcore_ws_uri}/events")
        ws.send(json.dumps(message))
        ws.close()
        return True

    def on_message(self, ws, message):
        try:
            message: Dict = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        log.debug(f"{self.identifier} received: {message}")
        if self.message_processor is not None and callable(self.message_processor):
            try:
                result = self.message_processor(message)
                log.debug(f"Sending reply {result}")
                ws.send(json.dumps(result))
            except Exception:
                log.exception(f"Something went wrong while processing {message}")

    def on_error(self, ws, error):
        log.error(f"{self.identifier} message bus error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        log.debug(f"{self.identifier} disconnected from ckcore message bus")

    def on_open(self, ws):
        log.debug(f"{self.identifier} connected to ckcore message bus")


class CkCoreTasks(threading.Thread):
    def __init__(
        self,
        identifier: str,
        ckcore_ws_uri: str,
        tasks: List,
        task_queue_filter: Optional[Dict] = None,
        message_processor: Optional[Callable] = None,
        max_workers: int = 20,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.ckcore_ws_uri = ckcore_ws_uri
        self.tasks = tasks
        if task_queue_filter is None:
            task_queue_filter = {}
        self.task_queue_filter = task_queue_filter
        self.message_processor = message_processor
        self.max_workers = max_workers
        self.ws = None
        self.shutdown_event = threading.Event()
        self.queue = queue.Queue()

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        for i in range(self.max_workers):
            threading.Thread(
                target=self.worker, daemon=True, name=f"worker-{i}"
            ).start()

        while not self.shutdown_event.is_set():
            log.info("Connecting to ckcore task queue")
            try:
                self.connect()
            except Exception as e:
                log.error(e)
            time.sleep(10)

    def worker(self) -> None:
        while not self.shutdown_event.is_set():
            message = self.queue.get()
            log.debug(f"{self.identifier} received: {message}")
            if self.message_processor is not None and callable(self.message_processor):
                try:
                    result = self.message_processor(message)
                    log.debug(f"Sending reply {result}")
                    self.ws.send(json.dumps(result))
                except Exception:
                    log.exception(f"Something went wrong while processing {message}")
            self.queue.task_done()

    def connect(self) -> None:
        ckcore_ws_uri_split = urlsplit(self.ckcore_ws_uri)
        scheme = ckcore_ws_uri_split.scheme
        netloc = ckcore_ws_uri_split.netloc
        path = "/work/queue"
        query = urlencode({"task": ",".join(self.tasks)} | self.task_queue_filter)
        ws_uri = urlunsplit((scheme, netloc, path, query, ""))

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
        )
        self.ws.run_forever()

    def shutdown(self, event: Event = None) -> None:
        log.debug("Received shutdown event - shutting down ckcore task queue listener")
        self.shutdown_event.set()
        if self.ws:
            self.ws.close()

    def on_message(self, ws, message):
        try:
            message: Dict = json.loads(message)
        except json.JSONDecodeError:
            log.exception(f"Unable to decode received message {message}")
            return
        self.queue.put(message)

    def on_error(self, ws, error):
        log.error(f"{self.identifier} event bus error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        log.debug(f"{self.identifier} disconnected from ckcore task queue")

    def on_open(self, ws):
        log.debug(f"{self.identifier} connected to ckcore task queue")
