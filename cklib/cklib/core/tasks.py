import threading
import queue
import time
import websocket
import json
from cklib.event import EventType, remove_event_listener, add_event_listener, Event
from cklib.logging import log
from cklib.args import ArgumentParser
from cklib.jwt import encode_jwt_to_headers
from typing import Callable, Dict, Optional, List
from urllib.parse import urlunsplit, urlencode, urlsplit


class CoreTasks(threading.Thread):
    def __init__(
        self,
        identifier: str,
        ckcore_ws_uri: str,
        tasks: List,
        task_queue_filter: Optional[Dict[str, List[str]]] = None,
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
        query = urlencode(
            {"task": ",".join(self.tasks)}
            | {k: ",".join(v) for k, v in self.task_queue_filter.items()}
        )
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
