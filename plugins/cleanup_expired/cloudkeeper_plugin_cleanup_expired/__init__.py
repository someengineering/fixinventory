import logging
import threading
from datetime import datetime, timezone
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import *
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import make_valid_timestamp, parse_delta
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger('cloudkeeper.' + __name__)


class CleanupExpiredPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'cleanup_expired'
        self.exit = threading.Event()
        if ArgumentParser.args.cleanup_expired:
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(EventType.CLEANUP_PLAN, self.expired_cleanup, blocking=True)
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
                if isinstance(node, BaseResource) and isinstance(cloud, BaseCloud) and isinstance(account, BaseAccount) and isinstance(region, BaseRegion):
                    if 'cloudkeeper:expires' in node.tags or ('expiration' in node.tags and node.tags['expiration'] != 'never'):
                        try:
                            if 'cloudkeeper:expires' in node.tags:
                                expires_tag = node.tags['cloudkeeper:expires']
                                expires = make_valid_timestamp(datetime.fromisoformat(expires_tag))
                            else:
                                expires_tag = node.tags['expiration']
                                expires = make_valid_timestamp(node.ctime + parse_delta(expires_tag))

                        except ValueError:
                            log.exception((f'Found {node.resource_type} {node.id} in cloud {cloud.name}'
                                           f' account {account.name} region {region.name} age {node.age} with invalid expires tag {expires_tag}'))
                            continue
                        else:
                            if now > expires:
                                log.debug((f'Found expired resource {node.resource_type} {node.id} in cloud {cloud.name}'
                                           f' account {account.name} region {region.name} age {node.age} with expires tag {expires_tag}'
                                           f' - marking for cleanup'))
                                node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--cleanup-expired', help='Cleanup expired resources (default: False)', dest='cleanup_expired', action='store_true', default=False)

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down cleanup expired plugin')
        self.exit.set()
