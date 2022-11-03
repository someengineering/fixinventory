import asyncio
import os
import sys
from argparse import Namespace
from datetime import datetime
from signal import SIGTERM
from threading import Event
from typing import Callable

from prompt_toolkit.formatted_text import FormattedText
from resotoclient.async_client import ResotoClient
from rich.console import Console

import resotolib.proc
from resotolib.args import ArgumentParser
from resotolib.core import resotocore, add_args as core_add_args, wait_for_resotocore
from resotolib.core.ca import TLSData
from resotolib.jwt import add_args as jwt_add_args
from resotolib.logger import log, setup_logger, add_args as logging_add_args
from resotoshell.promptsession import PromptSession, core_metadata
from resotoshell.shell import Shell


async def main_async() -> None:
    resotolib.proc.parent_pid = os.getpid()
    setup_logger("resotoshell", json_format=False)
    arg_parser = ArgumentParser(description="resoto shell", env_args_prefix="RESOTOSHELL_")
    core_add_args(arg_parser)
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    TLSData.add_args(arg_parser, ca_only=True)
    args: Namespace = arg_parser.parse_args()

    try:
        wait_for_resotocore(resotocore.http_uri, timeout=args.resotocore_wait)
    except TimeoutError:
        log.fatal(f"resotocore is not online at {resotocore.http_uri}")
        sys.exit(1)
    resotolib.proc.initializer()

    client = ResotoClient(
        url=resotocore.http_uri,
        psk=args.psk,
        custom_ca_cert_path=args.ca_cert,
        verify=args.verify_certs,
    )

    async def check_system_info() -> None:
        try:
            async for line in client.cli_execute("system info"):
                break
        except Exception as e:
            log.error(f"resotocore is not accessible: {e}")
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
        session = PromptSession(cmds=cmds, kinds=kinds, props=props)
        await repl(client, args, session)
    await client.shutdown()


async def repl(client: ResotoClient, args: Namespace, session: PromptSession) -> None:
    shutdown_event = Event()
    shell = Shell(client, True, detect_color_system(args))
    log.debug("Starting interactive session")

    # send the welcome command to the core
    await shell.handle_command("welcome")

    event_listener = (
        None if args.no_events else asyncio.create_task(attach_to_event_stream(client, shell, shutdown_event))
    )
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
            except EOFError:
                shutdown_event.set()
            except (RuntimeError, ValueError) as e:
                log.error(e)
            except Exception:
                log.exception("Caught unhandled exception while processing CLI command")
    finally:
        if event_listener:
            event_listener.cancel()


async def attach_to_event_stream(client: ResotoClient, shell: Shell, shutdown_event: Event) -> None:
    while not shutdown_event.is_set():
        try:
            async for event in client.events({"error"}):
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


async def handle_from_stdin(client: ResotoClient) -> None:
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
        "--resotocore-wait",
        help="How long to wait for resotocore to come online (default: 5 seconds).",
        dest="resotocore_wait",
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


def main() -> None:
    asyncio.run(main_async())
    resotolib.proc.kill_children(SIGTERM, ensure_death=True)
    log.debug("Shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
