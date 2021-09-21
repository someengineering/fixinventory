import cklib.logging
import threading
from datetime import datetime, timezone
from cklib.baseplugin import BasePlugin
from cklib.baseresources import *
from cklib.args import ArgumentParser
from cklib.utils import make_valid_timestamp, parse_delta
from cklib.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)

log = cklib.logging.getLogger("cloudkeeper." + __name__)


class CleanupExpiredPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "cleanup_expired"
        self.exit = threading.Event()
        if ArgumentParser.args.cleanup_expired:
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(
                EventType.CLEANUP_PLAN, self.expired_cleanup, blocking=True
            )
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_PLAN, self.expired_cleanup)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def expired_cleanup(event: Event):
        graph = event.data
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        with graph.lock.read_access:
            for node in graph.nodes:
                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)
                if (
                    isinstance(node, BaseResource)
                    and isinstance(cloud, BaseCloud)
                    and isinstance(account, BaseAccount)
                    and isinstance(region, BaseRegion)
                ):
                    if "cloudkeeper:expires" in node.tags or (
                        "expiration" in node.tags and node.tags["expiration"] != "never"
                    ):
                        try:
                            if "cloudkeeper:expires" in node.tags:
                                expires_tag = node.tags["cloudkeeper:expires"]
                                expires = make_valid_timestamp(
                                    datetime.fromisoformat(expires_tag)
                                )
                            else:
                                expires_tag = node.tags["expiration"]
                                expires = make_valid_timestamp(
                                    node.ctime + parse_delta(expires_tag)
                                )

                        except ValueError:
                            log.exception(
                                (
                                    f"Found {node.rtdname} in cloud {cloud.name} "
                                    f"account {account.dname} region {region.name} age {node.age} "
                                    f"with invalid expires tag {expires_tag}"
                                )
                            )
                            continue
                        else:
                            if expires is not None and now > expires:
                                log.debug(
                                    (
                                        f"Found expired resource {node.rtdname} in cloud "
                                        f"{cloud.name} account {account.dname} region {region.name} age {node.age} "
                                        f"with expires tag {expires_tag} - marking for cleanup"
                                    )
                                )
                                node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--cleanup-expired",
            help="Cleanup expired resources (default: False)",
            dest="cleanup_expired",
            action="store_true",
            default=False,
        )

    def shutdown(self, event: Event):
        log.debug(
            f"Received event {event.event_type} - shutting down cleanup expired plugin"
        )
        self.exit.set()
