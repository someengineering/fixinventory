from cloudkeeper.processor import Processor
from cloudkeeper.graph import GraphContainer
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.args import ArgumentParser, get_arg_parser
from cloudkeeper.event import Event, EventType, add_args as event_add_args
import logging
import time
import random
logging.getLogger('cloudkeeper').setLevel(logging.DEBUG)


num_resources = random.randint(1, 100)


class SomeTestResource(BaseResource):
    resource_type = 'some_test_resource'


class SomeTestPlugin(BaseCollectorPlugin):
    cloud = 'test'

    def collect(self) -> None:
        for x in range(num_resources):
            resource = SomeTestResource(f'Example Resource {x}', {})
            self.graph.add_resource(self.root, resource)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--example-region', help='Example Region', dest='example_region', type=str,
                                default=None, nargs='+')


def test_processor():
    arg_parser = get_arg_parser()
    Processor.add_args(arg_parser)
    GraphContainer.add_args(arg_parser)
    event_add_args(arg_parser)
    arg_parser.parse_args()

    graph_container = GraphContainer(cache_graph=False)
    plugins = [SomeTestPlugin]

    processor = Processor(graph_container, plugins)
    processor.daemon = True
    processor.start()
    time.sleep(1)
    assert len(processor.gc.graph.nodes) == num_resources + 2
    processor.shutdown(Event(EventType.SHUTDOWN))
