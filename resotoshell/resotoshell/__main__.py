import os
import sys
from argparse import Namespace
from signal import SIGTERM
from threading import Event, Thread
from typing import Callable

import resotolib.proc
from resotoclient import ResotoClient
from resotolib.args import ArgumentParser
from resotolib.core import resotocore, add_args as core_add_args, resotocore_is_up
from resotolib.core.ca import TLSData
from resotolib.event import add_event_listener, Event as ResotoEvent, EventType
from resotolib.jwt import add_args as jwt_add_args
from resotolib.logger import log, setup_logger, add_args as logging_add_args
from resotoshell.promptsession import PromptSession
from resotoshell.shell import Shell
from rich.console import Console


def main() -> None:
    resotolib.proc.parent_pid = os.getpid()
    resotolib.proc.initializer()
    setup_logger("resotoshell", json_format=False)
    arg_parser = ArgumentParser(description="resoto shell", env_args_prefix="RESOTOSHELL_")
    core_add_args(arg_parser)
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser, ca_only=True)
    args: Namespace = arg_parser.parse_args()

    if not resotocore_is_up(resotocore.http_uri):
        log.fatal(f"resotocore is not online at {resotocore.http_uri}")
        sys.exit(1)

    client = ResotoClient(
        url=resotocore.http_uri,
        psk=args.psk,
        custom_ca_cert_path=args.ca_cert,
        verify=args.verify_certs,
    )

    def check_system_info() -> None:
        try:
            list(client.cli_execute("system info"))
        except Exception as e:
            log.error(f"resotocore is not accessible: {e}")
            raise e

    try:
        client.start()
        check_system_info()
    except Exception:
        client.shutdown()
        sys.exit(1)
    if args.stdin or not sys.stdin.isatty():
        handle_from_stdin(client)
    else:
        repl(client, args)
    client.shutdown()
    resotolib.proc.kill_children(SIGTERM, ensure_death=True)
    log.debug("Shutdown complete")
    sys.exit(0)


def repl(
    client: ResotoClient,
    args: Namespace,
) -> None:
    shutdown_event = Event()
    shell = Shell(client, True, detect_color_system(args))
    session = PromptSession(client)
    log.debug("Starting interactive session")

    def shutdown(event: ResotoEvent) -> None:
        shutdown_event.set()
        kt = Thread(target=resotolib.proc.delayed_exit, name="shutdown")
        kt.start()

    add_event_listener(EventType.SHUTDOWN, shutdown)

    # send the welcome command to the core
    shell.handle_command("welcome")
    while not shutdown_event.is_set():
        try:
            command = session.prompt()
            if command == "":
                continue
            if command == "quit":
                shutdown_event.set()
                continue
            shell.handle_command(command)
        except KeyboardInterrupt:
            pass
        except EOFError:
            shutdown_event.set()
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")


def handle_from_stdin(client: ResotoClient) -> None:
    shell = Shell(client, False, "monochrome")
    log.debug("Reading commands from STDIN")
    try:
        for command in sys.stdin.readlines():
            command = command.rstrip()
            shell.handle_command(command)
    except KeyboardInterrupt:
        pass
    except (RuntimeError, ValueError) as e:
        log.error(e)
    except Exception:
        log.exception("Caught unhandled exception while processing CLI command")


def detect_color_system(args: Namespace) -> str:
    if args.no_color:
        return "monochrome"
    else:
        lookup = {
            None: "monochrome",
            "standard": "standard",
            "256": "eight_bit",
            "truecolor": "truecolor",
            "windows": "legacy_windows",
        }
        cs = lookup.get(Console().color_system, "standard")
        log.debug(f"Detected color system is: {cs}")
        return cs


def add_args(arg_parser: ArgumentParser) -> None:
    def is_file(message: str) -> Callable[[str], str]:
        def check_file(path: str) -> str:
            if os.path.isfile(path):
                return path
            else:
                raise AttributeError(f"{message}: path {path} is not a directory!")

        return check_file

    arg_parser.add_argument(
        "--resotocore-section",
        help="All queries are interpreted with this section name. If not set, the server default is used.",
        dest="resotocore_section",
    )
    arg_parser.add_argument(
        "--resotocore-graph",
        help="The name of the graph to use by default. If not set, the server default is used.",
        dest="resotocore_graph",
    )
    arg_parser.add_argument(
        "--download-directory",
        help="If files are received, they are written to this directory.",
        default=".",
        dest="download_directory",
    )
    arg_parser.add_argument(
        "--no-color",
        help="Output should be rendered plain without any color escape sequences.",
        dest="no_color",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--stdin",
        help="Read from STDIN instead of opening a shell",
        dest="stdin",
        action="store_true",
        default=False,
    )


if __name__ == "__main__":
    main()
