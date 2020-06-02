from cloudkeeper.args import ArgumentParser
from cloudkeeper.graph import Graph
from cloudkeeper.event import dispatch_event, Event, EventType
from cloudkeeper.baseresources import BaseResource
from defaultlist import defaultlist
from concurrent.futures import ThreadPoolExecutor
from prometheus_client import Summary
import logging

log = logging.getLogger(__name__)

metrics_cleanup = Summary('cloudkeeper_cleanup_seconds', 'Time it took the cleanup() method')


class Cleaner:
    def __init__(self, graph: Graph) -> None:
        self.graph = graph

    @metrics_cleanup.time()
    def cleanup(self) -> None:
        if not ArgumentParser.args.cleanup:
            log.error('Cleanup called but --cleanup flag not provided at startup - ignoring call')
            return

        log.info('Notifying plugins to plan cleanup')
        dispatch_event(Event(EventType.CLEANUP_PLAN, self.graph), blocking=True)
        log.info('Running cleanup')
        dispatch_event(Event(EventType.CLEANUP_BEGIN, self.graph), blocking=True)
        with self.graph.lock.read_access:
            cleanup_nodes = (node for node in self.graph.nodes() if node.clean)
            cleanup_plan = defaultlist(lambda: [])

            for node in cleanup_nodes:
                log.debug(f'Adding node {node.name} to cleanup plan with priority {node.max_graph_depth}')
                cleanup_plan[node.max_graph_depth].append(node)

            for nodes in reversed(cleanup_plan):
                with ThreadPoolExecutor(max_workers=ArgumentParser.args.cleanup_pool_size, thread_name_prefix='cleaner') as executor:
                    executor.map(self.clean, nodes)

        dispatch_event(Event(EventType.CLEANUP_FINISH, self.graph))

    def clean(self, node: BaseResource) -> None:
        if not ArgumentParser.args.cleanup_dry_run:
            log.debug(f'Node {node.id} is marked for removal, calling cleanup method')
            try:
                node.cleanup(self.graph)
            except Exception:
                log.exception(f'An exception occurred when running node cleanup on {node.id}')
        else:
            log.debug(
                f'Node {node.id} is marked for removal, not calling cleanup method because of dry run flag')

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--cleanup', help='Cleanup Resources (default: False)', dest='cleanup', action='store_true', default=False)
        arg_parser.add_argument('--cleanup-pool-size', help='Cleanup Thread Pool Size (default: 10)', dest='cleanup_pool_size', default=10, type=int)
        arg_parser.add_argument('--cleanup-dry-run', help='Cleanup Dry Run (default: False)', dest='cleanup_dry_run', action='store_true', default=False)
