from argparse import Namespace
from dataclasses import dataclass
from typing import Dict, Any

Json = Dict[str, Any]


@dataclass
class LogConfig:
    args: Namespace


class RestartService(SystemExit):
    code = 1

    def __init__(self, reason: str) -> None:
        super().__init__(f"RestartService due to: {reason}")
        self.reason = reason


@dataclass
class Message:
    payload: Json
