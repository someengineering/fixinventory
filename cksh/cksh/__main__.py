import os.path
import re
import sys
import shutil
import pathlib
import requests
from threading import Event
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from requests import Response
from requests_toolbelt import MultipartDecoder
from requests_toolbelt.multipart.decoder import BodyPart

from cklib.args import ArgumentParser
from cklib.logging import log, add_args as logging_add_args
from cklib.jwt import encode_jwt_to_headers
from typing import Dict, Union
from urllib.parse import urlencode, urlsplit


def main() -> None:
    shutdown_event = Event()
    arg_parser = ArgumentParser(
        description="Cloudkeeper Shell", env_args_prefix="CKSH_"
    )
    add_args(arg_parser)
    logging_add_args(arg_parser)
    arg_parser.parse_args()

    headers = {"Accept": "text/plain"}
    execute_endpoint = f"{ArgumentParser.args.ckcore_uri}/cli/execute"
    if ArgumentParser.args.ckcore_graph:
        query_string = urlencode({"graph": ArgumentParser.args.ckcore_graph})
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

    if ArgumentParser.args.psk:
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    log.debug(f'Sending command "{command}" to {execute_endpoint}')

    try:
        r = requests.post(
            execute_endpoint,
            data=command,
            headers=headers,
            stream=True,
        )
    except requests.exceptions.ConnectionError:
        err = (
            "Error: Could not communicate with ckcore"
            f" at {urlsplit(execute_endpoint).netloc}."
            " Is it up and reachable?"
        )
        print(err, file=sys.stderr)
    else:

        if r.status_code != 200:
            print(r.text, file=sys.stderr)
            return
        else:
            handle_result(r)


def handle_result(part: Union[Response, BodyPart], first: bool = True) -> None:
    content_type = part.headers.get("Content-Type", "text/plain")
    if content_type == "text/plain":
        # Received plain text: print it.
        if not first:
            print("---")
        if hasattr(part, "iter_lines"):
            for line in part.iter_lines():
                print(line.decode("utf-8"))
        else:
            print(part.text)
    elif content_type == "application/octet-stream":
        # Received a file - write it to disk.
        disposition = part.headers.get("Content-Disposition")
        match = re.findall('filename="([^"]+)";', disposition if disposition else "")
        name = match[0] if match else "out"
        path = os.path.join(ArgumentParser.args.download_directory, name)
        i = 0
        while os.path.exists(path):
            i += 1
            path = os.path.join(ArgumentParser.args.download_directory, f"{name}-{i}")
        print(f"Received a file {name}, which is stored to {path}.")
        with open(path, "wb+") as fh:
            fh.write(part.content)
    elif content_type.startswith("multipart"):
        # Received a multipart response: parse the parts
        decoder = MultipartDecoder.from_response(part)

        def decode(value: Union[str, bytes]) -> str:
            return value.decode("utf-8") if isinstance(value, bytes) else value

        for num, part in enumerate(decoder.parts):
            part.headers = {decode(k): decode(v) for k, v in part.headers.items()}
            handle_result(part, num == 0)


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
        "--ckcore-uri",
        help="ckcore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="ckcore_uri",
    )
    arg_parser.add_argument(
        "--ckcore-ws-uri",
        help="ckcore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="ckcore_ws_uri",
    )
    arg_parser.add_argument(
        "--ckcore-graph",
        help="ckcore graph name (default: ck)",
        default="ck",
        dest="ckcore_graph",
    )
    arg_parser.add_argument(
        "--psk",
        help="Pre-shared key",
        default=None,
        dest="psk",
    )
    arg_parser.add_argument(
        "--download-directory",
        help="If files are received, they are written to this directory.",
        default=".",
        dest="download_directory",
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
