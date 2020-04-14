import argparse
import logging

log = logging.getLogger(__name__)


class Namespace(argparse.Namespace):
    def __getattr__(self, item):
        return None


class ArgumentParser(argparse.ArgumentParser):
    # Class variable containing the last return value of parse_args()
    # If parse_args() hasn't been called yet will return None for any
    # attribute.
    args = Namespace()

    def parse_args(self, *args, **kwargs):
        ret = super().parse_args(*args, **kwargs)
        ArgumentParser.args = ret
        return ret


def get_arg_parser() -> ArgumentParser:
    arg_parser = ArgumentParser(description='Cloudkeeper - Housekeeping for Clouds')
    arg_parser.add_argument('--verbose', '-v', help='Verbose logging', dest='verbose', action='store_true', default=False)
    arg_parser.add_argument('--logfile', help='Logfile to log into', dest='logfile')
    return arg_parser
