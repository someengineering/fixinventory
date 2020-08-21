import cloudkeeper.logging
import threading
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = cloudkeeper.logging.getLogger('cloudkeeper.' + __name__)


class ExamplePersistentPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'example_persistent'
        self.exit = threading.Event()
        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(EventType.PROCESS_FINISH, self.example_event_handler, blocking=False)

    def __del__(self):
        remove_event_listener(EventType.PROCESS_FINISH, self.example_event_handler)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    @staticmethod
    def example_event_handler(event: Event):
        if ArgumentParser.args.example_arg:
            graph = event.data
            log.info('Example Persistent Plugin Event Handler called')
            for node in graph.search('resource_type', 'example_account'):
                log.debug(f'Found node {node.dname} of resource type {node.resource_type} created {node.ctime}')

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--example-arg', help='Example Arg', default=None, dest='example_arg')

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down example plugin')
        self.exit.set()
