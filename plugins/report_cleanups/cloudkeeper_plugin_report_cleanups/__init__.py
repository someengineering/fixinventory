import csv
import json
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from cloudkeeper.graph import get_resource_attributes
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import BaseResource, BaseCloud, BaseAccount, BaseRegion
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger('cloudkeeper.' + __name__)


class ReportCleanupsPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'report_cleanups'
        self.exit = threading.Event()

        if not ArgumentParser.args.report_cleanups_path:
            self.exit.set()
            return

        self.report_cleanups_path = Path(ArgumentParser.args.report_cleanups_path)
        self.report_cleanups_path.mkdir(parents=True, exist_ok=True)

        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(EventType.CLEANUP_FINISH, self.report_cleanup, blocking=False)

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_FINISH, self.report_cleanup)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def report_cleanup(self, event: Event):
        graph = event.data

        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        report_file_prefix = f'cleanup_report_{now.strftime("%Y-%m-%d_%H-%M-%S")}.'
        report_file = self.report_cleanups_path / (report_file_prefix + ArgumentParser.args.report_cleanups_format)

        log.info(f'Writing Cleanup Report to {report_file}')
        rows = []
        with graph.lock.read_access:
            for node in graph.nodes:
                if isinstance(node, BaseResource) and node.cleaned:
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)

                    if not isinstance(cloud, BaseCloud) or not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                        log.error(f'Unable to determine cloud ({cloud}), account ({account}) or region ({region}) for node {node.dname}')
                        continue

                    row = {
                        'datetime': now.isoformat(),
                        'cloud': cloud.name,
                        'account': account.name,
                        'region': region.name,
                        **get_resource_attributes(node)
                    }
                    rows.append(row)

        with report_file.open('w') as report_file_io:
            if ArgumentParser.args.report_cleanups_format == 'csv':
                fieldnames = ['datetime', 'cloud', 'account', 'region', 'resource_type', 'id', 'name', 'ctime']
                fieldnames.extend(ArgumentParser.args.report_cleanups_add_attr)
                # for CSV we remove any unwanted attributes and initialize wanted missing ones
                # for JSON we leave them all intact
                for row in rows:
                    for attr in list(row.keys()):
                        if attr not in fieldnames:
                            del row[attr]
                    for attr in fieldnames:
                        if attr not in row:
                            row[attr] = ''

                writer = csv.DictWriter(report_file_io, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            elif ArgumentParser.args.report_cleanups_format == 'json':
                json.dump(rows, report_file_io)
            else:
                log.error(f'Unknown output format: {ArgumentParser.args.report_cleanups_format}')

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--report-cleanups-path', help='Path to Cleanup Reports Directory', default=None, dest='report_cleanups_path')
        arg_parser.add_argument('--report-cleanups-format', help='File Format for Cleanup Reports (default: json)',
                                default='json', dest='report_cleanups_format', choices=['json', 'csv'])
        arg_parser.add_argument('--report-cleanups-add-attr', help='Additional resource attributes to include in CSV Cleanup Reports',
                                dest='report_cleanups_add_attr', type=str, default=[], nargs='+')

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type.name} - shutting down Cleanups Report Plugin')
        self.exit.set()
