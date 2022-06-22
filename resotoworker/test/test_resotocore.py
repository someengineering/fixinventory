import json
from typing import Dict, cast
from resotolib.graph import Graph
from resotoworker.resotocore import Resotocore
import requests
from test.fakeconfig import FakeConfig
from resotolib.config import Config


def test_resotocore() -> None:

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
                "resotoworker": {
                    "graph": "resoto",
                    "debug_dump_json": False,
                    "tempdir": "/tmp",
                    "graph_merge_kind": "foo_kind",
                },
                "running_config": None,
            }
        ),
    )

    core = Resotocore(make_query, config)

    core.send_to_resotocore(Graph(), "task_123")
    print(recorded_headers)

    assert recorded_headers["Resoto-Worker-Task-Id"] == "task_123"
