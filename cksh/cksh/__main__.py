import sys
import shutil
import pathlib
import requests
from threading import Event
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from cklib.args import get_arg_parser, ArgumentParser
from cklib.logging import log
from requests.api import head
from typing import Dict


def main() -> None:
    arg_parser = get_arg_parser()
    add_args(arg_parser)
    arg_parser.parse_args()

    session = completer = None
    history_file = str(pathlib.Path.home() / ".cksh_history")
    history = FileHistory(history_file)
    session = PromptSession(history=history)
    execute_endpoint = f"{ArgumentParser.args.keepercore_uri}/cli/execute"
    shutdown_event = Event()
    headers = {"Content-Type": "text/plain"}

    while not shutdown_event.is_set():
        try:
            cli_input = session.prompt("> ", completer=completer)
            if cli_input == "":
                continue
            if cli_input == "quit":
                shutdown_event.set()
                continue

            update_headers_with_terminal_size(headers)
            r = requests.post(
                execute_endpoint,
                data=cli_input,
                headers=headers,
                stream=True,
            )
            if r.status_code != 200:
                print(r.text, file=sys.stderr)
                continue

            for line in r.iter_lines():
                if not line:
                    continue
                print(line.decode("utf-8"))

        except KeyboardInterrupt:
            pass
        except EOFError:
            shutdown_event.set()
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")

    sys.exit(0)


def update_headers_with_terminal_size(headers: Dict[str, str]) -> None:
    tty_columns, tty_lines = shutil.get_terminal_size(fallback=(80, 20))
    headers.update(
        {
            "Cloudkeeper-Cksh-Columns": str(tty_columns),
            "Cloudkeeper-Cksh-Lines": str(tty_lines),
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


if __name__ == "__main__":
    main()
