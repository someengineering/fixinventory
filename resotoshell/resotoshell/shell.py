import os.path
import re
import shutil
import sys
from pathlib import Path
from subprocess import call
from tempfile import TemporaryDirectory
from typing import Dict, Union, Optional, Tuple, Any
from urllib.parse import urlsplit

from requests import Response, post
from requests.exceptions import ConnectionError
from requests_toolbelt import MultipartDecoder, MultipartEncoder
from requests_toolbelt.multipart.decoder import BodyPart

from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.logging import log
from resotoshell.protected_files import validate_paths


class Shell:
    def __init__(self, execute_endpoint: str, tty: bool, color_system: str):
        self.execute_endpoint = execute_endpoint
        self.tty = tty
        self.color_system = color_system

    def handle_command(
        self,
        command: str,
        additional_headers: Dict[str, str],
        files: Optional[Dict[str, str]] = None,
    ) -> None:
        headers = {}
        headers.update(additional_headers)

        # set tty headers
        if self.tty:
            tty_columns, tty_rows = shutil.get_terminal_size(fallback=(80, 25))
            log.debug(f"Setting columns {tty_columns}, rows {tty_rows}")
            headers.update(
                {
                    "Resoto-Shell-Columns": str(tty_columns),
                    "Resoto-Shell-Rows": str(tty_rows),
                    "Resoto-Shell-Color-System": self.color_system,
                    "Resoto-Shell-Terminal": "true",
                }
            )

        def post_request(
            data: Union[bytes, Dict[str, str]],
            content_type: str,
        ) -> Optional[Response]:
            # define content-type
            headers["Content-Type"] = content_type
            # sign request
            headers.clear()
            if ArgumentParser.args.psk:
                encode_jwt_to_headers(
                    headers, {}, ArgumentParser.args.psk, expire_in=604800
                )
                print(headers)

            body: Optional[Any] = None
            if isinstance(data, bytes):
                body = data
            elif isinstance(data, dict):
                parts = {
                    name: (name, open(path, "rb"), "application/octet-stream")
                    for name, path in data.items()
                }
                body = MultipartEncoder(parts, "file-upload")
            else:
                raise AttributeError(f"Can not handle data of type: {type(data)}")

            try:
                return post(
                    self.execute_endpoint, data=body, headers=headers, stream=True
                )
            except ConnectionError:
                err = (
                    "Error: Could not communicate with resotocore"
                    f" at {urlsplit(self.execute_endpoint).netloc}."
                    " Is it up and reachable?"
                )
                print(err, file=sys.stderr)

        def handle_response(maybe: Optional[Response], upload: bool = False):
            if maybe is not None:
                with maybe as response:
                    if response.status_code == 200:
                        self.handle_result(response)
                    elif response.status_code == 424 and not upload:
                        required = response.json().get("required", [])
                        to_upload = validate_paths(
                            {fp["name"]: fp["path"] for fp in required}
                        )
                        headers["Resoto-Shell-Command"] = command
                        mp = post_request(
                            to_upload, "multipart/form-data; boundary=file-upload"
                        )
                        handle_response(mp, True)
                    else:
                        print(response.text, file=sys.stderr)
                        return

        try:
            if files:
                headers["Resoto-Shell-Command"] = command
                received_response = post_request(
                    files, "multipart/form-data; boundary=file-upload"
                )
            else:
                received_response = post_request(command.encode("utf-8"), "text/plain")
            handle_response(received_response)
        except Exception as ex:
            print(f"Error performing command: `{command}`\nReason: {ex}")

    def handle_result(
        self, part: Union[Response, BodyPart], first: bool = True
    ) -> None:
        # store the file from the part inside the given directory
        def store_file(directory: str) -> Tuple[str, str]:
            disposition = part.headers.get("Content-Disposition", "")
            match = re.findall('filename="([^"]+)"', disposition)
            name = match[0] if match else "out"
            path = os.path.join(directory, name)
            i = 0
            while os.path.exists(path):
                i += 1
                path = os.path.join(directory, f"{name}-{i}")
            with open(path, "wb+") as fh:
                fh.write(part.content)
            return name, path

        content_type = part.headers.get("Content-Type", "text/plain")
        action = part.headers.get("Resoto-Shell-Action")
        command = part.headers.get("Resoto-Shell-Command")
        line_delimiter = "---"

        # If we get a plain text result, we simply print it to the console.
        if content_type == "text/plain":
            # Received plain text: print it.
            if not first:
                print(line_delimiter)
            if hasattr(part, "iter_lines"):
                for line in part.iter_lines():
                    print(line.decode("utf-8"))
            else:
                print(part.text)
        # File is sent in order to edit and return it.
        # We expect the command to define what should happen with the edited file.
        elif (
            content_type == "application/octet-stream" and action == "edit" and command
        ):
            with TemporaryDirectory() as tmp:
                name, path = store_file(tmp)
                call([os.environ.get("EDITOR", "vi"), path])
                stats = Path(path).lstat()
                if stats.st_mtime != stats.st_ctime:
                    self.handle_command(f"{command} {name}", {}, {name: path})
                else:
                    print("No change made while editing the file. Update aborted.")
        # File is sent: save it to local disk
        elif content_type == "application/octet-stream":
            name, path = store_file(ArgumentParser.args.download_directory)
            print(f"Received a file {name}, which is stored to {path}.")
        # Multipart: handle each part separately
        elif content_type.startswith("multipart"):
            # Received a multipart response: parse the parts
            decoder = MultipartDecoder.from_response(part)

            def decode(value: Union[str, bytes]) -> str:
                return value.decode("utf-8") if isinstance(value, bytes) else value

            for num, part in enumerate(decoder.parts):
                part.headers = {decode(k): decode(v) for k, v in part.headers.items()}
                self.handle_result(part, num == 0)
