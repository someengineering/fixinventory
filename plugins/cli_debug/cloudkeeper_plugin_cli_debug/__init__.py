import os
import inspect
import cklib.logging
from pprint import pformat
from pympler import asizeof
from typing import Iterable
from cklib.baseplugin import BaseCliPlugin
from cklib.args import ArgumentParser
from cklib.utils import get_stats, fmt_json


log = cklib.logging.getLogger("cloudkeeper." + __name__)


class CliDebugPlugin(BaseCliPlugin):
    def cmd_debug_close_fd(self, items: Iterable, args: str) -> Iterable:
        """Usage: debug_close_fd <fd>[+]

        Close an open file descriptor.
        If the + arg is given close any file
        descriptor after the one given as well.
        """
        close_after = False
        if args.endswith("+"):
            close_after = True
            args = args[:-1]

        if not args.isnumeric():
            yield "debug_close_fd expects a file descriptor number as arg."
        else:
            fd_num = int(args)

            stats = get_stats()
            all_fds = [
                int(fd) for fd in stats["process"]["parent"]["file_descriptors"].keys()
            ]
            kill_fds = []
            if fd_num in all_fds:
                kill_fds.append(fd_num)
            if close_after:
                kill_fds.extend([fd for fd in all_fds if fd > fd_num])
            for fd in kill_fds:
                yield f"Forcefully closing file descriptor {fd}."
                os.fdopen(fd).close()

    def cmd_debug_proc_info(self, items: Iterable, args: str) -> Iterable:
        """Usage: debug_proc_info

        Show system information.
        """
        yield fmt_json(get_stats(self.graph))

    def cmd_debug_calc_object_byte_size(self, items: Iterable, args: str) -> Iterable:
        """Usage: | debug_calc_object_byte_size |

        Calculate the resources in-memory size in bytes and add it
        as a .debug_byte_size attribute which can then be viewed with
        the dump command.
        """
        for item in items:
            byte_size = asizeof.asizeof(item)
            item.debug_object_byte_size = int(byte_size)
            yield item

    def cmd_debug_dump_members(self, items: Iterable, args: str) -> Iterable:
        """Usage: | debug_getmembers

        Dump all the members of a resource in a list.
        """
        for item in items:
            yield pformat(inspect.getmembers(item))

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass
