import requests
from argparse import ArgumentParser
from queue import Queue

from fixworker.collect import Collector
from fixworker.config import FixWorkerConfig
from fixworker.fixcore import FixCore
from typing import Optional, cast, Any
from fixlib.graph import Graph, GraphMergeKind
from fixlib.config import Config
from test.fakeconfig import FakeConfig
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import BaseAccount
from typing import ClassVar
from attrs import define

Config.add_config(FixWorkerConfig)
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


class TestFixCore(FixCore):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sent_task_id: Optional[str] = None

    def send_to_fixcore(self, graph: Graph, task_id: str, tempdir: str) -> None:
        self.sent_task_id = task_id

    def create_graph_and_update_model(self, tempdir: str) -> None:
        pass


def test_collect_and_send() -> None:
    fixcore = TestFixCore(make_query, Config)

    config = cast(
        Config,
        FakeConfig(
            values={
                "fixworker": {
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

    collector = Collector(config, fixcore, Queue())

    collector.collect_and_send([ExampleCollectorPlugin], {"task": "task_123", "step": "collect"})

    assert fixcore.sent_task_id == "task_123"
