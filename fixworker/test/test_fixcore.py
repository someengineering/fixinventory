import json
from argparse import ArgumentParser
from typing import Dict, cast
from fixlib.graph import Graph
from fixworker.fixcore import FixCore
import requests
from test.fakeconfig import FakeConfig
from fixlib.config import Config
from fixlib.baseresources import BaseAccount, GraphRoot
from fixlib.baseplugin import BaseCollectorPlugin
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


def test_fixcore() -> None:
    recorded_headers: Dict[str, str] = {}

    def make_query(request: requests.Request) -> requests.Response:
        nonlocal recorded_headers
        recorded_headers = request.headers
        resp = requests.Response()
        resp.status_code = 200
        resp._content = str.encode(json.dumps("OK"))
        return resp

    config = cast(
        Config,
        FakeConfig(
            values={
                "fixworker": {
                    "graph": "fix",
                    "debug_dump_json": False,
                    "tempdir": None,
                    "graph_merge_kind": "foo_kind",
                },
                "running_config": None,
            }
        ),
    )

    core = FixCore(make_query, config)

    collector = ExampleCollectorPlugin()
    collector.collect()
    graph = Graph(root=GraphRoot(id="graph_root"))
    graph.merge(collector.graph)

    core.send_to_fixcore(graph, "task_123", "/tmp")
    print(recorded_headers)

    assert recorded_headers["Fix-Worker-Task-Id"] == "task_123"
