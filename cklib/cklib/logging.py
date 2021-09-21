import sys
import os
from logging import (
    basicConfig,
    getLogger,
    Formatter,
    FileHandler,
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

logfile_arg = "--logfile"
if logfile_arg in argv:
    idx = argv.index(logfile_arg)
    if len(argv) > idx + 1:
        logfile = argv[idx + 1]
        log_formatter = Formatter(log_format)
        fh = FileHandler(logfile)
        fh.setFormatter(log_formatter)
        getLogger().addHandler(fh)


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
    arg_parser.add_argument(
        logfile_arg, help="Logfile to log into", dest="logfile", default=None
    )
