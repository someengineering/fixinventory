import os.path
import re
import shutil
import sys
from subprocess import call
from tempfile import TemporaryDirectory
from typing import Dict, Union, Optional, Tuple
from urllib.parse import urlsplit

from requests import Response
from requests.exceptions import ConnectionError
from requests_toolbelt import MultipartDecoder
from requests_toolbelt.multipart.decoder import BodyPart
from resotolib.args import ArgumentParser
from resotolib.utils import sha256sum
from resotolib.logger import log
from resotoshell.protected_files import validate_paths
from resotoclient import ResotoClient


class Shell:
    def __init__(
        self,
        client: ResotoClient,
        tty: bool,
        color_system: str,
        graph: Optional[str] = None,
        section: Optional[str] = None,
    ):
        self.client = client
        self.tty = tty
        self.color_system = color_system
        self.graph = graph
        self.section = section

    def handle_command(
        self,
        command: str,
        additional_headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, str]] = None,
    ) -> None:
        headers: Dict[str, str] = {}
        headers.update({"Accept": "text/plain"})
        headers.update(additional_headers or {})

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

        def handle_response(maybe: Optional[Response], upload: bool = False) -> None:
            if maybe is not None:
                with maybe as response:
                    if response.status_code == 200:
                        self.handle_result(response)
                    elif response.status_code == 424 and not upload:
                        required = response.json().get("required", [])
                        to_upload = validate_paths(
                            {fp["name"]: fp["path"] for fp in required}
                        )
                        mp: Response = self.client.cli_execute_raw(
                            command=command,
                            files=to_upload,
                            graph=self.graph,
                            section=self.section,
                            headers=headers,
                        )
                        handle_response(mp, True)
                    else:
                        log.debug(f"HTTP error, code: {response.status_code}")
                        print(response.text, file=sys.stderr)
                        return

        try:
            received_response = self.client.cli_execute_raw(
                command=command,
                files=files,
                graph=self.graph,
                section=self.section,
                headers=headers,
            )
            handle_response(received_response)
        except ConnectionError:
            err = (
                "Error: Could not communicate with resotocore"
                f" at {urlsplit(self.client.base_url).netloc}."
                " Is it up and reachable?"
            )
            print(err, file=sys.stderr)
        except Exception as ex:
            print(f"Error performing command: `{command}`\nReason: {ex}")

    def handle_result(
        self, part: Union[Response, BodyPart], first: bool = True
    ) -> None:
        # store the file from the part inside the given directory
        def store_file(directory: str) -> Tuple[str, str]:
            disposition = part.headers.get("Content-Disposition", "")
            match = re.findall('filename="([^"]+)"', disposition)
            filename = match[0] if match else "out"
            if "/" in filename:
                raise ValueError(f"Invalid filename: {filename}")
            filepath = os.path.join(directory, filename)
            i = 0
            while os.path.exists(filepath):
                i += 1
                filepath = os.path.join(directory, f"{filename}-{i}")
            with open(filepath, "wb+") as fh:
                fh.write(part.content)
            return filename, filepath

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
                filename, filepath = store_file(tmp)
                original_shasum = sha256sum(filepath)
                call([os.environ.get("EDITOR", "vi"), filepath])
                new_shasum = sha256sum(filepath)
                log.debug(
                    f"Original config sha256: {original_shasum},"
                    f" new sha256: {new_shasum}"
                )
                if new_shasum != original_shasum:
                    self.handle_command(
                        f"{command} {filename}", {}, {filename: filepath}
                    )
                else:
                    print("No change made while editing the file. Update aborted.")
        # File is sent: save it to local disk
        elif content_type == "application/octet-stream":
            filename, filepath = store_file(ArgumentParser.args.download_directory)
            print(f"Received a file {filename}, which is stored to {filepath}.")
        # Multipart: handle each part separately
        elif content_type.startswith("multipart"):
            # Received a multipart response: parse the parts
            decoder = MultipartDecoder.from_response(part)

            def decode(value: Union[str, bytes]) -> str:
                return value.decode("utf-8") if isinstance(value, bytes) else value

            for num, part in enumerate(decoder.parts):
                part.headers = {decode(k): decode(v) for k, v in part.headers.items()}
                self.handle_result(part, num == 0)
