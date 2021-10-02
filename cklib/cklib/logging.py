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


log_format = "%(asctime)s - %(levelname)s - %(process)d/%(threadName)s - %(message)s"
basicConfig(level=WARNING, format=log_format)
getLogger().setLevel(ERROR)
getLogger("cloudkeeper").setLevel(CRITICAL)
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
