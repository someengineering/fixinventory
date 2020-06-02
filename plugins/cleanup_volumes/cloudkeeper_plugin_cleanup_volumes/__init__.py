import logging
import threading
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import BaseVolume
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import parse_delta
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger('cloudkeeper.' + __name__)


class CleanupVolumesPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'cleanup_volumes'
        self.exit = threading.Event()
        if ArgumentParser.args.cleanup_volumes:
            try:
                self.age = parse_delta(ArgumentParser.args.cleanup_volumes_age)
                log.debug(f'Volume Cleanup Plugin Age {self.age}')
                add_event_listener(EventType.SHUTDOWN, self.shutdown)
                add_event_listener(EventType.CLEANUP_PLAN, self.volumes_cleanup, blocking=True)
            except ValueError:
                log.exception(f'Error while parsing Volume Cleanup Age {ArgumentParser.args.volclean_age}')
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_PLAN, self.volumes_cleanup)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def volumes_cleanup(self, event: Event):
        graph = event.data
        log.info('Volume Cleanup called')
        with graph.lock.read_access:
            for node in graph.nodes:
                if (
                    isinstance(node, BaseVolume)
                    and node.volume_status == 'available'
                    and node.age > self.age
                    and node.last_access > self.age
                    and node.last_update > self.age
                ):
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)
                    log.debug((
                        f'Found available volume {node.id} in cloud {cloud.name} account {account.name} region {region.name}'
                        f' with age {node.age}. Last update was {node.last_update} ago and last access {node.last_access}'
                        f' ago both of which is longer than {self.age} - setting to be cleaned')
                    )
                    node.clean = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--cleanup-volumes', help='Cleanup unused Volumes (default: False)', dest='cleanup_volumes', action='store_true', default=False)
        arg_parser.add_argument('--cleanup-volumes-age', help='Cleanup unused Volumes Age (default: 14 days)', default='14 days', dest='cleanup_volumes_age')

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down Volume Cleanup plugin')
        self.exit.set()
