import logging
import threading
from pathlib import Path
from datetime import date
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import *
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger('cloudkeeper.' + __name__)


class LogDumpPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'logdump'
        self.exit = threading.Event()

        if not ArgumentParser.args.logdump_path:
            self.exit.set()
            return

        self.logdump_path = Path(ArgumentParser.args.logdump_path)

        if not self.logdump_path.is_dir():
            raise ValueError(f'Logdump path {ArgumentParser.args.logdump_path} is not a directory')

        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(EventType.PROCESS_FINISH, self.dump_resource_event_logs, blocking=False)

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.dump_resource_event_logs)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def dump_resource_event_logs(self, event: Event):
        graph = event.data
        date_dir = date.today().strftime("%Y/%m/%d")
        log.info('Dumping Event Logs')
        with graph.lock.read_access:
            for node in graph.nodes:
                if isinstance(node, BaseResource) and len(node.event_log) > 0:
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)

                    if not isinstance(cloud, BaseCloud) or not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                        log.error(f'Unable to determine cloud ({cloud}), account ({account}) or region ({region}) for node {node.id}')
                        continue

                    out_dir = self.logdump_path / date_dir / cloud.name / account.name / region.name
                    out_dir.mkdir(parents=True, exist_ok=True)
                    filename = str(node.id).replace('/', '_') + '.log'
                    out_file = out_dir / filename
                    with out_file.open('a') as f:
                        log.debug(f'Writing {out_file}')
                        for event in node.event_log:
                            timestamp = event['timestamp'].isoformat()
                            msg = event['msg']
                            f.write(f'{timestamp} {msg}' + "\n")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--logdump-path', help='Path to Event Log Dump Directory ', default=None, dest='logdump_path')

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down logdump plugin')
        self.exit.set()
