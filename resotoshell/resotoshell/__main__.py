import os
import pathlib
import sys
import resotolib.signal
from contextlib import nullcontext
from threading import Event, Thread
from typing import Callable, Optional, Dict
from urllib.parse import urlencode
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from resotolib.args import ArgumentParser, Namespace
from resotolib.core import resotocore, add_args as core_add_args, resotocore_is_up
from resotolib.core.ca import TLSData
from resotolib.jwt import add_args as jwt_add_args
from resotolib.logging import log, setup_logger, add_args as logging_add_args
from resotolib.utils import rnd_str
from resotolib.event import add_event_listener, Event as ResotoEvent, EventType
from resotoshell.shell import Shell
from rich.console import Console


def main() -> None:
    resotolib.signal.parent_pid = os.getpid()
    resotolib.signal.initializer()
    setup_logger("resotoshell")
    arg_parser = ArgumentParser(
        description="resoto shell", env_args_prefix="RESOTOSHELL_"
    )
    core_add_args(arg_parser)
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser, ca_only=True)
    args = arg_parser.parse_args()

    if not resotocore_is_up(resotocore.http_uri):
        log.fatal(f"resotocore is not online at {resotocore.http_uri}")
        sys.exit(1)

    tls_data = None
    if resotocore.is_secure:
        tls_data = TLSData(
            common_name="resh",
            resotocore_uri=resotocore.http_uri,
            ca_only=True,
        )
    with tls_data or nullcontext():
        headers = {"Accept": "text/plain"}
        execute_endpoint = f"{args.resotocore_uri}/cli/execute"
        execute_endpoint += f"?resoto_session_id={rnd_str()}"
        if args.resotocore_graph:
            query_string = urlencode({"graph": args.resotocore_graph})
            execute_endpoint += f"&{query_string}"
        if args.resotocore_section:
            query_string = urlencode({"section": args.resotocore_section})
            execute_endpoint += f"&{query_string}"

        if args.stdin:
            handle_from_stdin(execute_endpoint, tls_data, headers)
        else:
            repl(execute_endpoint, tls_data, headers, args)
    resotolib.signal.kill_children(resotolib.signal.SIGTERM, ensure_death=True)
    log.debug("Shutdown complete")
    sys.exit(0)


def repl(
    execute_endpoint: str,
    tls_data: Optional[TLSData],
    headers: Dict[str, str],
    args: Namespace,
) -> None:
    shutdown_event = Event()
    shell = Shell(execute_endpoint, True, detect_color_system(args), tls_data)
    completer = None
    history_file = str(pathlib.Path.home() / ".resotoshell_history")
    history = FileHistory(history_file)
    session = PromptSession(history=history)
    log.debug("Starting interactive session")

    def shutdown(event: ResotoEvent) -> None:
        shutdown_event.set()
        kt = Thread(target=resotolib.signal.delayed_exit, name="shutdown")
        kt.start()

    add_event_listener(EventType.SHUTDOWN, shutdown)

    # send the welcome command to the core
    shell.handle_command("welcome", headers)
    while not shutdown_event.is_set():
        try:
            command = session.prompt("> ", completer=completer)
            if command == "":
                continue
            if command == "quit":
                shutdown_event.set()
                continue
            shell.handle_command(command, headers)
        except KeyboardInterrupt:
            pass
        except EOFError:
            shutdown_event.set()
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")


def handle_from_stdin(
    execute_endpoint: str, tls_data: Optional[TLSData], headers: Dict[str, str]
) -> None:
    shell = Shell(execute_endpoint, False, "monochrome", tls_data)
    log.debug("Reading commands from STDIN")
    try:
        for command in sys.stdin.readlines():
            command = command.rstrip()
            shell.handle_command(command, headers)
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
