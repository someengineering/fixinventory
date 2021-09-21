import cklib.logging
import threading
import requests
import jwt
import datetime
from functools import partial
from cklib.baseplugin import BasePlugin
from cklib.args import ArgumentParser
from cklib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)

log = cklib.logging.getLogger("cloudkeeper." + __name__)


class RemoteEventCallbackPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "remote_event_callback"
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

        for endpoint in ArgumentParser.args.remote_event_endpoint:
            for event_type in EventType:
                event_prefix = f"{event_type.name.lower()}:"
                if str(endpoint).startswith(event_prefix):
                    endpoint = endpoint[len(event_prefix) :]
                    f = partial(self.remote_event_callback, endpoint)
                    add_event_listener(event_type, f, blocking=False, one_shot=False)
            else:
                log.error(f"Invalid remote event callback endpoint {endpoint}")

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def remote_event_callback(endpoint: str, event: Event):
        log.info(f"Received event {event.event_type.name}: calling {endpoint}")
        try:
            data = {
                "event": event.event_type.name,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
            }
            jwt_token = jwt.encode(
                data, ArgumentParser.args.remote_event_callback_psk
            ).decode("utf-8")

            r = requests.post(
                endpoint,
                json={"jwt": jwt_token},
            )
            if r.status_code != 200:
                log.error(
                    (
                        f"Failure when calling endpoint {endpoint}"
                        f" for event {event.event_type.name}: {r.text}"
                    )
                )
            elif r.json().get("status") == "ok":
                log.debug(
                    f"Successfully called endpoint {endpoint} for event {event.event_type.name}"
                )
            else:
                log.error(
                    f"Failure when calling endpoint {endpoint} for event {event.event_type.name}"
                )
        except Exception:
            log.exception(
                f"An unhandeled exception occured while calling endpoint {endpoint} for event {event.event_type.name}"
            )

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--remote-event-callback-endpoint",
            help="Remote Event Callback Endpoint",
            default=[],
            dest="remote_event_endpoint",
            type=str,
            nargs="+",
        )
        arg_parser.add_argument(
            "--remote-event-callback-psk",
            help="Remote Event Callback pre-shared-key",
            default="cloudkeeper",
            dest="remote_event_callback_psk",
            type=str,
        )

    def shutdown(self, event: Event):
        log.debug(f"Received event {event.event_type} - shutting down example plugin")
        self.exit.set()
