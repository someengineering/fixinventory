from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.args import ArgumentParser
from resotolib.baseresources import BaseResource
from typing import ClassVar, Any
from attrs import define


@define(eq=False, slots=False)
class SomeTestResource(BaseResource):
    kind: ClassVar[str] = "some_test_resource"

    def delete(self, graph) -> bool:
        return False


class SomeTestPlugin(BaseCollectorPlugin):
    cloud = "test"

    def collect(self, **kwargs: Any) -> None:
        account = SomeTestResource(id="Example Account", tags={})
        self.graph.add_resource(self.root, account)

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


def test_plugin():
    plugin = SomeTestPlugin()
    plugin.collect()
    assert len(plugin.graph.nodes) == 2
