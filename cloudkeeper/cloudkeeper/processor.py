import threading
import logging
import time
import os
from typing import List
from networkx.algorithms.dag import is_directed_acyclic_graph
from cloudkeeper.graph import GraphContainer, sanitize
from cloudkeeper.args import ArgumentParser
from cloudkeeper.cleaner import Cleaner
from cloudkeeper.utils import log_stats
from cloudkeeper.event import dispatch_event, Event, EventType, add_event_listener, remove_event_listener
from prometheus_client import Summary

log = logging.getLogger(__name__)

metrics_collect = Summary('cloudkeeper_collect_seconds', 'Time it took the collect() method')


class Processor(threading.Thread):
    """The Processor is cloudkeeper's logic loop.

    It runs forever or until interrupted and each loop creates fresh instances of each Plugin.
    Each Plugin itself is running as a separate thread. Once all the Plugin collect() threads have finished
    running the Collector retrieves their individual Graphs and merges them into the global Graph.

    After all cloud resources have been collected the cleanup() method is run which creates an instance of the Cleaner()
    which in turn emits a blocking event CLEANUP_BEGIN. After all event listeners have processed the event the Cleaner
    checks which nodes have the .clean property set to True and calls the cleanup() method on those nodes.
    If the node's BaseClass has the delete() method implemented it'll get deleted during this process.
    Finally the CLEANUP_FINISH event is emitted to be consumed by other Plugins that might write reports or send
    notifications about the cleaned up resources.
    """
    def __init__(self, gc: GraphContainer, plugins: List) -> None:
        super().__init__()
        self.name = 'processor'
        self.gc = gc
        self.plugins = plugins
        self.__run = True
        self.__run_event = threading.Event()
        self.__interval = ArgumentParser.args.interval
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(EventType.START_COLLECT, self.start_collect)

    def __del__(self):
        remove_event_listener(EventType.START_COLLECT, self.start_collect)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        num_run = 0
        while self.__run:
            self.__run_event.clear()

            num_run += 1
            time_run_start = time.time()

            log.info(f'Starting processor run {num_run}')
            log_stats()
            dispatch_event(Event(EventType.PROCESS_BEGIN, self.gc.graph))
            self.collect()
            log_stats(garbage_collector_stats=True)
            self.cleanup()
            dispatch_event(Event(EventType.PROCESS_FINISH, self.gc.graph), blocking=True)

            elapsed = int(time.time() - time_run_start)
            log.info(f'Done run {num_run} with {len(self.gc.graph.nodes)} nodes in {elapsed} seconds')
            log_stats(garbage_collector_stats=True)

            if self.__interval > elapsed:
                wait_time = self.__interval - elapsed
                log.debug(f'Waiting {wait_time} seconds before next run')
                self.__run_event.wait(wait_time)

            # If we're only supposed to run once we still wait for interval above.
            # If no wait is desired --interval 0 can be specified.
            if ArgumentParser.args.one_shot:
                reason = 'One shot run specified'
                log.debug(f'Requesting shutdown: {reason}')
                dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}), blocking=True)
        log.debug('Processor thread shut down')

    @metrics_collect.time()
    def collect(self) -> None:
        """collect() is run every loop, collecting Plugin resources.

        Every time collect() is run it creates a new working Graph. It then creates instances of each Plugin
        and starts their thread which in turn runs the Plugin's collect() method. Once all Plugins have finished
        collecting cloud resources, it retrieves the Plugin's Graphs and appends them to its own working Graph.

        At the end the live Graph is swapped with the working Graph.
        """
        gc = GraphContainer(cache_graph=False)  # Create a new graph container to hold the Graph() which we'll swap out at the end
        dispatch_event(Event(EventType.COLLECT_BEGIN, gc.graph))  # Let interested parties know that we're about to start our collect run
        plugins = [Plugin() for Plugin in self.plugins]  # Create instances of each Plugin()
        start_time = time.time()

        # First we run each Collector Plugin
        # Each Plugin is a threading.Thread so we call start() on it
        for plugin in plugins:
            plugin.start()  # Run the collect() method on each plugin which in turn generates a Graph()

        # Now we wait for each Plugin to complete its work or time out
        # Because we always swap out the completed graph at the end of our collect run
        # it doesn't matter in which order we wait for (join) Plugins. I.e. there's no speed
        # advantage in checking for already completed Plugins and collecting slow ones last.
        for plugin in plugins:
            timeout = start_time + ArgumentParser.args.timeout - time.time()
            if timeout < 1:
                timeout = 1
            log.info(f'Waiting for collector thread of plugin {plugin.cloud} to finish')
            plugin.join(timeout)
            if not plugin.is_alive():  # The plugin has finished its work
                if not is_directed_acyclic_graph(plugin.graph):
                    log.error(f'Graph of plugin {plugin.cloud} is not acyclic - ignoring plugin results')
                    continue
                log.info(f'Merging graph of plugin {plugin.cloud} with global graph')
                gc.add(plugin.graph)
                gc.graph.add_edge(gc.GRAPH_ROOT, plugin.root)  # Connect the root of our graph with the plugin's
            else:
                log.error(f'Plugin {plugin.cloud} timed out - discarding Plugin graph')
        sanitize(gc.graph, gc.GRAPH_ROOT)
        dispatch_event(Event(EventType.GENERATE_METRICS, gc.graph), blocking=True)
        dispatch_event(Event(EventType.COLLECT_FINISH, gc.graph), blocking=True)
        self.gc.graph = gc.graph  # Swap the live graph with the newly created one from our current run

    def cleanup(self) -> None:
        """cleanup() is run after collect() and creates a new instance of the Cleaner()
        """
        if ArgumentParser.args.cleanup:
            resource_cleaner = Cleaner(self.gc.graph)
            resource_cleaner.cleanup()

    def shutdown(self, event: Event) -> None:
        log.debug(f'Received signal to shut down collector thread {event.event_type}')
        self.__run = False
        self.__run_event.set()

    def start_collect(self, event: Event) -> None:
        """Event handler for the START_COLLECT event."""
        log.debug(f'Received signal to start collecting {event.event_type}')
        self.__run_event.set()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--interval', help='Collection Interval in seconds (default: 3600)',
                                default=int(os.environ.get('CLOUDKEEPER_INTERVAL', 3600)), dest='interval', type=int)
        arg_parser.add_argument('--timeout', help='Collection Timeout in seconds (default: 10800)',
                                default=int(os.environ.get('CLOUDKEEPER_TIMEOUT', 10800)), dest='timeout', type=int)
        arg_parser.add_argument('--one-shot', help='Only run one collect/cleanup loop (default: False)', dest='one_shot', action='store_true', default=False)
