from cloudkeeperv1.processor import Processor
from cklib.graph import GraphContainer
from cklib.baseplugin import BaseCollectorPlugin
from cklib.baseresources import BaseResource
from cklib.args import ArgumentParser, get_arg_parser
from cklib.event import Event, EventType, add_args as event_add_args
from cklib.cleaner import Cleaner
from dataclasses import dataclass
from typing import ClassVar
import cklib.logging as logging
import time
import random

logging.getLogger("cloudkeeper").setLevel(logging.DEBUG)


num_resources = random.randint(1, 100)


@dataclass(eq=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def delete(self, graph) -> bool:
        return False


class SomeTestPlugin(BaseCollectorPlugin):
    cloud = "test"

    def collect(self) -> None:
        for x in range(num_resources):
            resource = SomeTestResource(f"Example Resource {x}", {})
            self.graph.add_resource(self.root, resource)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--example-region",
            help="Example Region",
            dest="example_region",
            type=str,
            default=None,
            nargs="+",
        )


def test_processor():
    arg_parser = get_arg_parser()
    Processor.add_args(arg_parser)
    GraphContainer.add_args(arg_parser)
    Cleaner.add_args(arg_parser)
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
