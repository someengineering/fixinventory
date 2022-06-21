from resotoworker.collect import Collector
from typing import Optional, cast
from resotolib.graph import Graph
from resotolib.config import Config
from test.fakeconfig import FakeConfig


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

    collector = Collector(send_to_resotocore, config)

    collector.collect_and_send([], "task_123")

    assert sent_task_id == "task_123"
