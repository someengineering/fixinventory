import sys
import shutil
import pathlib
import requests
from threading import Event
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from cklib.args import get_arg_parser, ArgumentParser
from cklib.logging import log, add_args as logging_add_args
from typing import Dict
from urllib.parse import urlencode


def main() -> None:
    shutdown_event = Event()
    arg_parser = get_arg_parser()
    add_args(arg_parser)
    logging_add_args(arg_parser)
    arg_parser.parse_args()

    headers = {"Content-Type": "text/plain"}
    execute_endpoint = f"{ArgumentParser.args.keepercore_uri}/cli/execute"
    if ArgumentParser.args.keepercore_graph:
        query_string = urlencode({"graph": ArgumentParser.args.keepercore_graph})
        execute_endpoint += f"?{query_string}"

    if ArgumentParser.args.stdin:
        log.debug("Reading commands from STDIN")
        try:
            for command in sys.stdin.readlines():
                command = command.rstrip()
                send_command(command, execute_endpoint, headers, tty=False)
        except KeyboardInterrupt:
            pass
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")
        finally:
            shutdown_event.set()
    else:
        session = completer = None
        history_file = str(pathlib.Path.home() / ".cksh_history")
        history = FileHistory(history_file)
        session = PromptSession(history=history)
        log.debug("Starting interactive session")

    while not shutdown_event.is_set():
        try:
            command = session.prompt("> ", completer=completer)
            if command == "":
                continue
            if command == "quit":
                shutdown_event.set()
                continue

            send_command(command, execute_endpoint, headers)

        except KeyboardInterrupt:
            pass
        except EOFError:
            shutdown_event.set()
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")

    sys.exit(0)


def send_command(
    command: str, execute_endpoint: str, headers: Dict[str, str], tty: bool = True
) -> None:
    if tty:
        update_headers_with_terminal_size(headers)

    log.debug(f'Sending command "{command}" to {execute_endpoint}')

    r = requests.post(
        execute_endpoint,
        data=command,
        headers=headers,
        stream=True,
    )
    if r.status_code != 200:
        print(r.text, file=sys.stderr)
        return

    for line in r.iter_lines():
        if not line:
            continue
        print(line.decode("utf-8"))


def update_headers_with_terminal_size(headers: Dict[str, str]) -> None:
    tty_columns, tty_rows = shutil.get_terminal_size(fallback=(80, 20))
    log.debug(f"Setting columns {tty_columns}, rows {tty_rows}")
    headers.update(
        {
            "Cloudkeeper-Cksh-Columns": str(tty_columns),
            "Cloudkeeper-Cksh-Rows": str(tty_rows),
        }
    )


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--keepercore-uri",
        help="Keepercore URI (default: http://localhost:8080)",
        default="http://localhost:8080",
        dest="keepercore_uri",
    )
    arg_parser.add_argument(
        "--keepercore-ws-uri",
        help="Keepercore Websocket URI (default: ws://localhost:8080)",
        default="ws://localhost:8080",
        dest="keepercore_ws_uri",
    )
    arg_parser.add_argument(
        "--keepercore-graph",
        help="Keepercore graph name (default: ck)",
        default="ck",
        dest="keepercore_graph",
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
