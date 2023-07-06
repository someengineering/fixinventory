from argparse import ArgumentParser
from queue import Queue

from resotoworker.collect import Collector
from resotoworker.config import ResotoWorkerConfig
from typing import Optional, cast
from resotolib.graph import Graph, GraphMergeKind
from resotolib.config import Config
from test.fakeconfig import FakeConfig
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import BaseAccount
from typing import ClassVar
from attrs import define

Config.add_config(ResotoWorkerConfig)
Config.init_default_config()


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


class Resotocore:
    def __init__(self) -> None:
        self.sent_task_id: Optional[str] = None

    def send_to_resotocore(self, graph: Graph, task_id: str) -> None:
        self.sent_task_id = task_id

    def create_graph_and_update_model(self) -> None:
        pass


def test_collect_and_send() -> None:
    resotocore = Resotocore()

    config = cast(
        Config,
        FakeConfig(
            values={
                "resotoworker": {"pool_size": 1, "fork_process": False, "graph_merge_kind": GraphMergeKind.cloud},
                "running_config": None,
            }
        ),
    )

    collector = Collector(config, resotocore, Queue())

    collector.collect_and_send([ExampleCollectorPlugin], "task_123", "collect")

    assert resotocore.sent_task_id == "task_123"
