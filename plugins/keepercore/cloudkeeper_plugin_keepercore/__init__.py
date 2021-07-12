import cloudkeeper.logging
import threading
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class KeepercorePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "keepercore"
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(
            EventType.COLLECT_FINISH, self.keepercore_event_handler, blocking=False
        )

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.keepercore_event_handler)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def keepercore_event_handler(event: Event):
        if not ArgumentParser.args.keepercore_uri:
            return

        graph = event.data
        log.info("Keepercore Event Handler called")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--keepercore-uri", help="Keepercore URI", default=None, dest="keepercore_uri"
        )

    def shutdown(self, event: Event):
        log.debug(f"Received event {event.event_type} - shutting down keepercore plugin")
        self.exit.set()
