import threading
import time
import websocket
import requests
import json
from resotolib.logger import log
from resotolib.event import EventType, remove_event_listener, add_event_listener, Event
from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.core.ca import TLSData
from typing import Callable, Dict, Optional


class CoreActions(threading.Thread):
    def __init__(
        self,
        identifier: str,
        resotocore_uri: str,
        resotocore_ws_uri: str,
        actions: Dict,
        message_processor: Optional[Callable] = None,
        tls_data: Optional[TLSData] = None,
    ) -> None:
        super().__init__()
        self.identifier = identifier
        self.resotocore_uri = resotocore_uri
        self.resotocore_ws_uri = resotocore_ws_uri
        self.actions = actions
        self.message_processor = message_processor
        self.ws = None
        self.tls_data = tls_data
        self.shutdown_event = threading.Event()

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.name = self.identifier
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        while not self.shutdown_event.is_set():
            log.debug("Connecting to resotocore message bus")
            try:
                self.connect()
            except Exception as e:
                log.error(e)
            time.sleep(1)

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
        self.ws.run_forever(
            sslopt=sslopt, ping_interval=30, ping_timeout=10, ping_payload="ping"
        )

    def shutdown(self, event: Event = None) -> None:
        log.debug(
            "Received shutdown event - shutting down resotocore message bus listener"
        )
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
        url = f"{self.resotocore_uri}/subscriber/{self.identifier}/{action}"
        headers = {"accept": "application/json"}

        if getattr(ArgumentParser.args, "psk", None):
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        verify = None
        if self.tls_data:
            verify = self.tls_data.ca_cert_path

        r = client(url, headers=headers, params=data, verify=verify)
        if r.status_code != 200:
            raise RuntimeError(
                f'Error during (un)registration for "{action}"'
                f" actions: {r.content.decode('utf-8')}"
            )
        return True

    def dispatch_event(self, message: Dict) -> bool:
        if self.ws is None:
            return False
        ws = websocket.create_connection(f"{self.resotocore_ws_uri}/events")
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
        log.debug(f"{self.identifier} message bus error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        log.debug(f"{self.identifier} disconnected from resotocore message bus")

    def on_open(self, ws):
        log.debug(f"{self.identifier} connected to resotocore message bus")

    def on_ping(self, ws, message):
        log.debug(f"{self.identifier} actions ping from resotocore message bus")

    def on_pong(self, ws, message):
        log.debug(f"{self.identifier} actions pong from resotocore message bus")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--resotocore-subscriber-id",
            help="resotocore actions subscriber identifier (default: worker)",
            default="worker",
            dest="resotocore_subscriber_id",
        )
