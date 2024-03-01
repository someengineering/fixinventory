import asyncio
import os
import sys
from argparse import Namespace
from datetime import datetime
from signal import SIGTERM
from threading import Event
from typing import Tuple

from prompt_toolkit.formatted_text import FormattedText
from fixclient.async_client import FixInventoryClient
from rich.console import Console

import fixlib.proc
from fixlib.args import ArgumentParser
from fixlib.core import fixcore, add_args as core_add_args, wait_for_fixcore
from fixlib.core.ca import TLSData
from fixlib.jwt import add_args as jwt_add_args
from fixlib.logger import log, setup_logger, add_args as logging_add_args
from fixshell import authorized_client
from fixshell.promptsession import PromptSession, core_metadata, FixHistory
from fixshell.shell import Shell, ShutdownShellError
from fixlib.utils import ensure_bw_compat


async def main_async() -> None:
    fixlib.proc.parent_pid = os.getpid()
    setup_logger("fixshell", json_format=False)
    arg_parser = ArgumentParser(description="Fix Inventory Shell", env_args_prefix="FIXSHELL_")
    core_add_args(arg_parser)
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser, ca_only=True)
    args: Namespace = arg_parser.parse_args()
    headers = dict(args.add_headers)

    try:
        wait_for_fixcore(fixcore.http_uri, timeout=args.fixcore_wait, headers=headers)
    except TimeoutError:
        log.fatal(f"fixcore is not online at {fixcore.http_uri}")
        sys.exit(1)
    fixlib.proc.initializer()

    client = await authorized_client.new_client(args)

    async def check_system_info() -> None:
        try:
            async for _ in client.cli_execute("system info"):
                break
        except Exception as e:
            log.error(f"fixcore is not accessible: {e}")
            raise e

    try:
        await client.start()
        await check_system_info()
    except Exception:
        await client.shutdown()
        sys.exit(1)
    if args.stdin or not sys.stdin.isatty():
        await handle_from_stdin(client)
    else:
        cmds, kinds, props = await core_metadata(client)
        history = FixHistory.default()
        session = PromptSession(cmds=cmds, kinds=kinds, props=props, history=history)
        shell = Shell(client, True, detect_color_system(args), history=history, additional_headers=headers)
        await repl(shell, session, args)

    # update the eventually changed auth token
    await authorized_client.update_auth_header(client)
    await client.shutdown()


async def repl(shell: Shell, session: PromptSession, args: Namespace) -> None:
    shutdown_event = Event()

    log.debug("Starting interactive session")

    # send the welcome command to the core
    await shell.handle_command("welcome", no_history=True)

    event_listener = None if args.no_events else asyncio.create_task(attach_to_event_stream(shell, shutdown_event))
    try:
        while not shutdown_event.is_set():
            try:
                await asyncio.sleep(0.1)
                command = await session.prompt()
                if command == "":
                    continue
                if command == "quit":
                    shutdown_event.set()
                    continue
                await shell.handle_command(command)
            except KeyboardInterrupt:
                pass
            except (EOFError, ShutdownShellError):
                shutdown_event.set()
            except (RuntimeError, ValueError) as e:
                log.error(e)
            except Exception:
                log.exception("Caught unhandled exception while processing CLI command")
    finally:
        if event_listener:
            event_listener.cancel()


async def attach_to_event_stream(shell: Shell, shutdown_event: Event) -> None:
    while not shutdown_event.is_set():
        try:
            async for event in shell.client.events({"error"}):
                data = event.get("data", {})
                message = data.get("message")
                context = ",".join([f"{k}={v}" for k, v in data.items() if k != "message"])
                if message:
                    shell.stderr(
                        FormattedText(
                            [
                                ("green", f'{datetime.now().strftime("%H:%M:%S")}'),
                                ("blue", f" {context} "),
                                ("bold red", message),
                            ]
                        )
                    )
        except Exception as ex:
            log.debug("Could not attach to event stream: %s", ex)
            await asyncio.sleep(1)


async def handle_from_stdin(client: FixInventoryClient) -> None:
    shell = Shell(client, False, "monochrome")
    log.debug("Reading commands from STDIN")
    try:
        for command in sys.stdin.readlines():
            command = command.rstrip()
            await shell.handle_command(command)
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
    def header_value(s: str) -> Tuple[str, str]:
        if ":" not in s:
            raise ValueError("Header must be in the format key:value")
        k, v = s.split(":", 1)
        return k, v

    arg_parser.add_argument(
        "--fixcore-section",
        help="All queries are interpreted with this section name. If not set, the server default is used.",
        dest="fixcore_section",
    )
    arg_parser.add_argument(
        "--fixcore-graph",
        help="The name of the graph to use by default. If not set, the server default is used.",
        dest="fixcore_graph",
    )
    arg_parser.add_argument(
        "--fixcore-wait",
        help="How long to wait for fixcore to come online (default: 5 seconds).",
        dest="fixcore_wait",
        type=int,
        default=5,
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
        help="Read from STDIN instead of opening a shell.",
        dest="stdin",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--no-events",
        help="Do not attach to the servers event stream. No event messages will be shown.",
        dest="no_events",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--add-headers",
        help="Add a header to all requests. Format: key:value",
        nargs="*",
        default=[],
        type=header_value,
    )


def main() -> None:
    ensure_bw_compat()
    asyncio.run(main_async())
    fixlib.proc.kill_children(SIGTERM, ensure_death=True)
    log.debug("Shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
