import cklib.logging
from typing import Iterable
from cklib.baseplugin import BaseCliPlugin
from cklib.args import ArgumentParser

log = cklib.logging.getLogger("cloudkeeper." + __name__)


class ExampleCliPlugin(BaseCliPlugin):
    def cmd_example_do_nothing(self, items: Iterable, args: str) -> Iterable:
        """Usage: example_do_nothing <args>

        Example command from the example_cli plugin.
        Prints some text followed by the arg that was given.
        """
        log.info("Example CLI command called")
        yield f"Example CLI command: {args}"

    def cmd_example_do_something(self, items: Iterable, args: str) -> Iterable:
        """Usage: | example_do_something |

        Example command from the example_cli plugin.
        Takes input items and passes the first 3 on to
        the next command or output if there is no next
        command.
        """
        i = 0
        for item in items:
            if i < 3:
                yield item
            i += 1

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        arg_parser.add_argument(
            "--example-cli-arg",
            help="Example Cli Command Arg",
            default=None,
            dest="example_cli_arg",
        )
