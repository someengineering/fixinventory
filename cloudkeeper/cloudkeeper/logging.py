import sys
from logging import *
from cloudkeeper.args import ArgumentParser


log_format = '%(asctime)s - %(levelname)s - %(process)d/%(threadName)s - %(message)s'
basicConfig(level=WARN, format=log_format)
getLogger('cloudkeeper').setLevel(INFO)

argv = sys.argv[1:]
if '-v' in argv or '--verbose' in argv:
    getLogger('cloudkeeper').setLevel(DEBUG)

if ArgumentParser.args.logfile:
    log_formatter = Formatter(log_format)
    fh = FileHandler(ArgumentParser.args.logfile)
    fh.setFormatter(log_formatter)
    getLogger().addHandler(fh)


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument('--logfile', help='Logfile to log into', dest='logfile')
