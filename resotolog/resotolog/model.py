from argparse import Namespace
from dataclasses import dataclass


@dataclass
class LogConfig:
    args: Namespace


class RestartService(SystemExit):
    code = 1

    def __init__(self, reason: str) -> None:
        super().__init__(f"RestartService due to: {reason}")
        self.reason = reason
