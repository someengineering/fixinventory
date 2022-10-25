from argparse import ArgumentParser
from queue import Queue

from resotoworker.collect import Collector
from typing import Optional, cast
from resotolib.graph import Graph
from resotolib.config import Config
from test.fakeconfig import FakeConfig
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseAccount
from typing import ClassVar
from attrs import define


@define(eq=False)
class ExampleAccount(BaseAccount):
    kind: ClassVar[str] = "example_account"

    def delete(self, graph: Graph) -> bool:
        return NotImplemented


class ExampleCollectorPlugin(BaseCollectorPlugin):
    cloud = "example"

    def collect(self) -> None:
        account = ExampleAccount(id="Example Account")
        self.graph.add_resource(self.graph.root, account)  # type: ignore

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        pass


def test_collect_and_send() -> None:

    sent_task_id: Optional[str] = None

    def send_to_resotocore(graph: Graph, task_id: str) -> None:
        nonlocal sent_task_id
        sent_task_id = task_id

    config = cast(
        Config,
        FakeConfig(
            values={
                "resotoworker": {"pool_size": 1, "fork_process": False},
                "running_config": None,
            }
        ),
    )

    collector = Collector(config, send_to_resotocore, Queue())

    collector.collect_and_send([ExampleCollectorPlugin], [], "task_123", "collect")

    assert sent_task_id == "task_123"
