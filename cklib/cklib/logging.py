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

argv = sys.argv[1:]
if (
    "-v" in argv
    or "--verbose" in argv
    or os.environ.get("CLOUDKEEPER_VERBOSE", "False") == "True"
):
    getLogger("cloudkeeper").setLevel(DEBUG)


log = getLogger("cloudkeeper")


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )


def setup_logger(proc: str) -> None:
    log_format = f"%(asctime)s|{proc}|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
    basicConfig(format=log_format, datefmt="%y-%m-%d %H:%M:%S")
