from dataclasses import dataclass, field
from typing import ClassVar, Optional
import sys
import os
from logging import (
    basicConfig,
    getLogger,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
)
from resotolib.args import ArgumentParser


getLogger().setLevel(ERROR)
getLogger("resoto").setLevel(INFO)


def add_args(arg_parser: ArgumentParser) -> None:
    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )
    group.add_argument(
        "--quiet",
        help="Only log errors",
        dest="quiet",
        action="store_true",
        default=False,
    )


def add_config(config) -> None:
    config.add_config(LoggingConfig)


@dataclass
class LoggingConfig:
    kind: ClassVar[str] = "logging"
    verbose: Optional[bool] = field(
        default=False, metadata={"description": "Verbose logging"}
    )
    quiet: Optional[bool] = field(
        default=False, metadata={"description": "Only log errors"}
    )


def setup_logger(proc: str, force: bool = True) -> None:
    log_format = (
        f"%(asctime)s|{proc}|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
    )
    basicConfig(format=log_format, datefmt="%y-%m-%d %H:%M:%S", force=force)
    argv = sys.argv[1:]
    if (
        "-v" in argv
        or "--verbose" in argv
        or os.environ.get("RESOTO_VERBOSE", "false").lower() == "true"
    ):
        getLogger("resoto").setLevel(DEBUG)
    elif "--quiet" in argv or os.environ.get("RESOTO_QUIET", "false").lower() == "true":
        getLogger().setLevel(WARNING)
        getLogger("resoto").setLevel(CRITICAL)


setup_logger("resoto", force=False)
log = getLogger("resoto")
