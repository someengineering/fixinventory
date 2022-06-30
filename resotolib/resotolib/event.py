import os
import time
from resotolib.logger import log
from resotolib.lock import RWLock
from collections import defaultdict
from threading import Thread, Lock
from typing import Callable, Iterable
from enum import Enum


class EventType(Enum):
    """Defines Event Types

    Event().data definitions for EventType:
    STARTUP: None
    SHUTDOWN: {'reason': 'reason for shutdown', 'emergency': True/False}
    START_COLLECT: None
    COLLECT_BEGIN: resotolib.graph.Graph
    COLLECT_FINISH: resotolib.graph.Graph
    CLEANUP_PLAN: resotolib.graph.Graph
    CLEANUP_BEGIN: resotolib.graph.Graph
    CLEANUP_FINISH: resotolib.graph.Graph
    PROCESS_BEGIN: resotolib.graph.Graph
    PROCESS_FINISH: resotolib.graph.Graph
    GENERATE_METRICS: resotolib.graph.Graph
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
    log.debug(f"Dispatching event {event.event_type.name} and {waiting_str}waiting for" " listeners to return")

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

            if listener_data["one-shot"] and not listener_data["lock"].acquire(blocking=False):
                log.error(f"Not calling one-shot listener {listener} of type" f" {type(listener)} - can't acquire lock")
                continue

            log.debug(
                f"Calling listener {listener} of type {type(listener)}" f" (blocking: {listener_data['blocking']})"
            )
            thread_name = f"{event.event_type.name.lower()}_event" f"-{getattr(listener, '__name__', 'anonymous')}"
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
        log.debug(f"Waiting up to {timeout:.2f}s for event listener {thread.name} to finish")
        thread.join(timeout)
        log.debug(f"Event listener {thread.name} finished (timeout: {thread.is_alive()})")


def add_event_listener(
    event_type: EventType,
    listener: Callable,
    blocking: bool = False,
    timeout: int = 900,
    one_shot: bool = False,
) -> bool:
    """Add an Event Listener"""
    if not callable(listener):
        log.error(f"Error registering {listener} of type {type(listener)} with event" f" {event_type.name}")
        return False

    log.debug(f"Registering {listener} with event {event_type.name}" f" (blocking: {blocking}, one-shot: {one_shot})")
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
