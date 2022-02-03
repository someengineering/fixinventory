import os.path
import pathlib
import re
import shutil
import sys
from functools import cache
from threading import Event
from typing import Dict, Union, Any, Optional
from urllib.parse import urlencode, urlsplit

import requests
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from requests import Response
from requests_toolbelt import MultipartDecoder, MultipartEncoder
from requests_toolbelt.multipart.decoder import BodyPart
from rich.console import Console

from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers, add_args as jwt_add_args
from resotolib.logging import log, setup_logger, add_args as logging_add_args
from resotolib.utils import rnd_str
from resotoshell.protected_files import validate_paths


def main() -> None:
    setup_logger("resotoshell")
    shutdown_event = Event()
    arg_parser = ArgumentParser(
        description="resoto shell", env_args_prefix="RESOTOSHELL_"
    )
    add_args(arg_parser)
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    arg_parser.parse_args()

    headers = {"Accept": "text/plain"}
    execute_endpoint = f"{ArgumentParser.args.resotocore_uri}/cli/execute"
    execute_endpoint += f"?resoto_session_id={rnd_str()}"
    if ArgumentParser.args.resotocore_graph:
        query_string = urlencode({"graph": ArgumentParser.args.resotocore_graph})
        execute_endpoint += f"&{query_string}"
    if ArgumentParser.args.resotocore_section:
        query_string = urlencode({"section": ArgumentParser.args.resotocore_section})
        execute_endpoint += f"&{query_string}"

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
        completer = None
        history_file = str(pathlib.Path.home() / ".resotoshell_history")
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
    def update_headers_with_terminal_size() -> None:
        tty_columns, tty_rows = shutil.get_terminal_size(fallback=(80, 20))
        log.debug(f"Setting columns {tty_columns}, rows {tty_rows}")
        headers.update(
            {
                "Resoto-Shell-Columns": str(tty_columns),
                "Resoto-Shell-Rows": str(tty_rows),
                "Resoto-Shell-Color-System": color_system(),
                "Resoto-Shell-Terminal": "true",
            }
        )

    def post_request(data: Any, content_type: str) -> Optional[Response]:
        # set tty headers
        if tty:
            update_headers_with_terminal_size()
        # define content-type
        headers["Content-Type"] = content_type
        # sign request
        if ArgumentParser.args.psk:
            encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

        try:
            return requests.post(
                execute_endpoint, data=data, headers=headers, stream=True
            )
        except requests.exceptions.ConnectionError:
            err = (
                "Error: Could not communicate with resotocore"
                f" at {urlsplit(execute_endpoint).netloc}."
                " Is it up and reachable?"
            )
            print(err, file=sys.stderr)

    # files: name -> path
    def encode_files(files: Dict[str, str]) -> MultipartEncoder:
        parts = {
            name: (name, open(path, "rb"), "application/octet-stream")
            for name, path in files.items()
        }
        return MultipartEncoder(parts, "file-upload")

    def handle_response(maybe: Optional[Response], upload: bool = False):
        if maybe is not None:
            with maybe as response:
                if response.status_code == 200:
                    handle_result(response)
                elif response.status_code == 424 and not upload:
                    required = response.json().get("required", [])
                    files = validate_paths({fp["name"]: fp["path"] for fp in required})
                    data = encode_files(files)
                    headers["Ck-Command"] = command
                    mp = post_request(data, "multipart/form-data; boundary=file-upload")
                    handle_response(mp, True)
                else:
                    print(response.text, file=sys.stderr)
                    return

    try:
        handle_response(post_request(command, "text/plain"))
    except Exception as ex:
        print(f"Error performing command: `{command}`\nReason: {ex}")


def handle_result(part: Union[Response, BodyPart], first: bool = True) -> None:
    content_type = part.headers.get("Content-Type", "text/plain")
    line_delimiter = "---"
    if content_type == "text/plain":
        # Received plain text: print it.
        if not first:
            print(line_delimiter)
        if hasattr(part, "iter_lines"):
            for line in part.iter_lines():
                print(line.decode("utf-8"))
        else:
            print(part.text)
    elif content_type == "application/octet-stream":
        # Received a file - write it to disk.
        if not first:
            print(line_delimiter)
        disposition = part.headers.get("Content-Disposition")
        match = re.findall('filename="([^"]+)"', disposition if disposition else "")
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


@cache
def color_system() -> str:
    lookup = {
        None: "monochrome",
        "standard": "standard",
        "256": "eight_bit",
        "truecolor": "truecolor",
        "windows": "legacy_windows",
    }
    return lookup.get(Console().color_system, "standard")


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--resotocore-uri",
        help="resotocore URI (default: http://localhost:8900)",
        default="http://localhost:8900",
        dest="resotocore_uri",
    )
    arg_parser.add_argument(
        "--resotocore-ws-uri",
        help="resotocore Websocket URI (default: ws://localhost:8900)",
        default="ws://localhost:8900",
        dest="resotocore_ws_uri",
    )
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
        "--stdin",
        help="Read from STDIN instead of opening a shell",
        dest="stdin",
        action="store_true",
        default=False,
    )


if __name__ == "__main__":
    main()
