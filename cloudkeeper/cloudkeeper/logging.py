import sys
from logging import *
from cloudkeeper.args import ArgumentParser


log_format = "%(asctime)s - %(levelname)s - %(process)d/%(threadName)s - %(message)s"
basicConfig(level=WARN, format=log_format)
getLogger("cloudkeeper").setLevel(INFO)

argv = sys.argv[1:]
if "-v" in argv or "--verbose" in argv:
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


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(logfile_arg, help="Logfile to log into", dest="logfile")
