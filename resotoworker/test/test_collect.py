import requests
from argparse import ArgumentParser
from queue import Queue

from resotoworker.collect import Collector
from resotoworker.config import ResotoWorkerConfig
from resotoworker.resotocore import Resotocore
from typing import Optional, cast, Any
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


def make_query(request: requests.Request) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b""
    return resp


class TestResotocore(Resotocore):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sent_task_id: Optional[str] = None

    def send_to_resotocore(self, graph: Graph, task_id: str, tempdir: str) -> None:
        self.sent_task_id = task_id

    def create_graph_and_update_model(self, tempdir: str) -> None:
        pass


def test_collect_and_send() -> None:
    resotocore = TestResotocore(make_query, Config)

    config = cast(
        Config,
        FakeConfig(
            values={
                "resotoworker": {
                    "pool_size": 1,
                    "fork_process": False,
                    "debug_dump_json": False,
                    "graph_merge_kind": GraphMergeKind.cloud,
                    "graph_sender_pool_size": 5,
                    "timeout": 10800,
                    "tempdir": None,
                },
                "running_config": None,
            }
        ),
    )

    collector = Collector(config, resotocore, Queue())

    collector.collect_and_send([ExampleCollectorPlugin], {"task": "task_123", "step": "collect"})

    assert resotocore.sent_task_id == "task_123"
