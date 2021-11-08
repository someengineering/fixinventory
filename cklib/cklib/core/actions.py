import threading
import time
import websocket
import requests
import json
from cklib.logging import log
from cklib.event import EventType, remove_event_listener, add_event_listener, Event
from cklib.args import ArgumentParser
from cklib.jwt import encode_jwt_to_headers
from typing import Callable, Dict, Optional


class CoreActions(threading.Thread):
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
            except Exception as e:
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
                f'Error during (un)registration for "{action}"'
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

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--ckcore-subscriber-id",
            help="ckcore actions subscriber identifier (default: worker)",
            default="worker",
            dest="ckcore_subscriber_id",
        )
