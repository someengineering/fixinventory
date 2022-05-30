from dataclasses import dataclass
from resotoworker.collect import Collector
from typing import Dict, Optional, Any, cast
from resotolib.graph import Graph
from resotolib.core.ca import TLSData
from resotolib.config import Config


@dataclass
class ConfigMock:
    values: Dict[str, Any]

    def __getattr__(self, name: str):
        value = self.values[name]
        if isinstance(value, dict):
            return ConfigMock(value)  # type: ignore
        else:
            return value


def test_collect_and_send():

    sent_task_id: Optional[str] = None

    def send_to_resotocore(graph: Graph, task_id: str, tls_data: Optional[TLSData]) -> None:
        nonlocal sent_task_id
        sent_task_id = task_id

    config = cast(Config, ConfigMock(values={
        'resotoworker': {
            'pool_size': 1,
            'fork_process': False
        },
        'running_config': None
        }
    ))

    collector = Collector(send_to_resotocore, config)

    collector.collect_and_send([], "task_123", None)

    assert sent_task_id == "task_123"
