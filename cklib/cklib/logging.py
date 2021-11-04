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
from cklib.args import ArgumentParser


getLogger().setLevel(ERROR)
getLogger("cloudkeeper").setLevel(INFO)

log = getLogger("cloudkeeper")


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
        help="Quiet logging",
        dest="quiet",
        action="store_true",
        default=False,
    )


def setup_logger(proc: str) -> None:
    log_format = (
        f"%(asctime)s|{proc}|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
    )
    basicConfig(format=log_format, datefmt="%y-%m-%d %H:%M:%S")
    argv = sys.argv[1:]
    if (
        "-v" in argv
        or "--verbose" in argv
        or os.environ.get("CLOUDKEEPER_VERBOSE", "false").lower() == "true"
    ):
        getLogger("cloudkeeper").setLevel(DEBUG)
    elif (
        "--quiet" in argv
        or os.environ.get("CLOUDKEEPER_QUIET", "false").lower() == "true"
    ):
        getLogger().setLevel(WARNING)
        getLogger("cloudkeeper").setLevel(CRITICAL)
