import os
import threading
import time
import websocket
import requests
import json
import cloudkeeper.logging
from cloudkeeper.utils import RWLock
from cloudkeeper.args import ArgumentParser
from collections import defaultdict
from threading import Thread, Lock
from typing import Callable, Dict, Iterable, Optional
from enum import Enum

log = cloudkeeper.logging.getLogger(__name__)


class EventType(Enum):
    """Defines Event Types

    Event().data definitions for EventType:
    STARTUP: None
    SHUTDOWN: {'reason': 'reason for shutdown', 'emergency': True/False}
    START_COLLECT: None
    COLLECT_BEGIN: cloudkeeper.graph.Graph
    COLLECT_FINISH: cloudkeeper.graph.Graph
    CLEANUP_PLAN: cloudkeeper.graph.Graph
    CLEANUP_BEGIN: cloudkeeper.graph.Graph
    CLEANUP_FINISH: cloudkeeper.graph.Graph
    PROCESS_BEGIN: cloudkeeper.graph.Graph
    PROCESS_FINISH: cloudkeeper.graph.Graph
    GENERATE_METRICS: cloudkeeper.graph.Graph
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
        timeout = ArgumentParser.args.event_timeout

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


class KeepercoreEvents(threading.Thread):
    def __init__(
        self,
        identifier: str,
        keepercore_uri: str,
        keepercore_ws_uri: str,
        events: Dict,
        message_processor: Optional[Callable] = None,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.keepercore_uri = keepercore_uri
        self.keepercore_ws_uri = keepercore_ws_uri
        self.events = events
        self.message_processor = message_processor
        self.ws = None

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        try:
            self.go()
        except Exception:
            log.exception(f"Caught unhandled events exception in {self.name}")

    def go(self):
        for event, data in self.events.items():
            if not isinstance(data, dict):
                data = None
            self.register(event, data)

        ws_uri = f"{self.keepercore_ws_uri}/subscription/{self.identifier}/handle"
        log.debug(f"{self.identifier} connecting to {ws_uri}")
        self.ws = websocket.WebSocketApp(
            ws_uri,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
        )
        self.ws.run_forever()

    def shutdown(self, event: Event) -> None:
        log.debug(
            f"Received event {event.event_type}"
            " - shutting down keepercore event bus listener"
        )
        if self.ws:
            self.ws.close()
        for core_event in self.events.keys():
            self.unregister(core_event)

    def register(self, event: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} registering for {event} events")
        return self.registration(event, requests.post, data)

    def unregister(self, event: str, data: Optional[Dict] = None) -> bool:
        log.debug(f"{self.identifier} unregistering from {event} events")
        return self.registration(event, requests.delete, data)

    def registration(
        self, event: str, client: Callable, data: Optional[Dict] = None
    ) -> bool:
        url = f"{self.keepercore_uri}/subscription/{self.identifier}/{event}"
        r = client(url, headers={"accept": "application/json"}, json=data)
        if r.status_code != 200:
            log.error(r.content)
            return False
        return True

    def dispatch_event(self, message: Dict) -> bool:
        if self.ws is None:
            return False
        ws = websocket.create_connection(f"{self.keepercore_ws_uri}/events")
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
                self.message_processor(ws, message)
            except Exception:
                log.exception(f"Something went wrong while processing {message}")

    def on_error(self, ws, error):
        log.error(f"{self.identifier} {error}")

    def on_close(self, ws, close_status_code, close_msg):
        log.debug(f"{self.identifier} disconnected: {close_msg}")

    def on_open(self, ws):
        log.debug(f"{self.identifier} connected")
