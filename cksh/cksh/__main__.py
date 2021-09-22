import sys
import shutil
import pathlib
import requests
from threading import Event
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from cklib.args import get_arg_parser, ArgumentParser
from cklib.logging import log
from typing import Dict


def main() -> None:
    shutdown_event = Event()
    arg_parser = get_arg_parser()
    add_args(arg_parser)
    arg_parser.parse_args()
    headers = {"Content-Type": "text/plain"}
    execute_endpoint = f"{ArgumentParser.args.keepercore_uri}/cli/execute"

    if ArgumentParser.args.stdin:
        try:
            for command in sys.stdin.readlines():
                command = command.rstrip()
                send_command(command, execute_endpoint, headers)
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


def send_command(command: str, execute_endpoint: str, headers: Dict[str, str]) -> None:
    update_headers_with_terminal_size(headers)
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
    headers.update(
        {
            "Cloudkeeper-Cksh-Columns": str(tty_columns),
            "Cloudkeeper-Cksh-Rows": str(tty_rows),
        }
    )


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--keepercore-uri",
        help="Keepercore URI",
        default="http://localhost:8080",
        dest="keepercore_uri",
    )
    arg_parser.add_argument(
        "--keepercore-ws-uri",
        help="Keepercore Websocket URI",
        default="ws://localhost:8080",
        dest="keepercore_ws_uri",
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
