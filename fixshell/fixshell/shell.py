import os.path
import re
import shutil
import sys
from pathlib import Path
from subprocess import call
from tempfile import TemporaryDirectory
from typing import Dict, Union, Optional, Tuple
from urllib import parse
from urllib.parse import urlsplit

import aiohttp
from prompt_toolkit import HTML, ANSI, print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.output import ColorDepth
from fixclient.async_client import HttpResponse
from fixclient.async_client import FixInventoryClient
from rich.markdown import Markdown

from fixlib.args import ArgumentParser
from fixlib.core import CLIEnvelope
from fixlib.logger import log
from fixlib.utils import sha256sum
from fixshell.promptsession import FixHistory
from fixshell.protected_files import validate_paths

color_system_to_color_depth = {
    "monochrome": ColorDepth.DEPTH_1_BIT,
    "standard": ColorDepth.DEPTH_8_BIT,
    "eight_bit": ColorDepth.DEPTH_8_BIT,
    "truecolor": ColorDepth.DEPTH_24_BIT,
    "legacy_windows": ColorDepth.DEPTH_4_BIT,
}


class ShutdownShellError(Exception):
    pass


class Shell:
    def __init__(
        self,
        client: FixInventoryClient,
        tty: bool,
        color_system: str,
        *,
        graph: Optional[str] = None,
        section: Optional[str] = None,
        history: Optional[FixHistory] = None,
        additional_headers: Optional[Dict[str, str]] = None,
    ):
        self.client = client
        self.history = history
        self.tty = tty
        self.color_system = color_system
        self.color_depth = color_system_to_color_depth.get(color_system) or ColorDepth.DEPTH_8_BIT
        self.graph = graph
        self.section = section
        self.additional_headers = additional_headers or {}

    async def handle_command(
        self,
        command: str,
        additional_headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, str]] = None,
        no_history: bool = False,
    ) -> None:
        headers: Dict[str, str] = self.additional_headers.copy()
        headers.update({"Accept": "text/plain"})
        headers.update(additional_headers or {})

        # set tty headers
        if self.tty:
            tty_columns, tty_rows = shutil.get_terminal_size(fallback=(80, 25))
            log.debug(f"Setting columns {tty_columns}, rows {tty_rows}")
            headers.update(
                {
                    "Fix-Shell-Columns": str(tty_columns),
                    "Fix-Shell-Rows": str(tty_rows),
                    "Fix-Shell-Color-System": self.color_system,
                    "Fix-Shell-Terminal": "true",
                }
            )

        async def handle_response(maybe: Optional[HttpResponse], upload: bool = False) -> None:
            if maybe is not None:
                with maybe as response:
                    if response.status_code == 200:
                        # only store history if the command was successful, and no no_history flag was set
                        if self.history and not no_history and CLIEnvelope.no_history not in response.headers:
                            self.history.store_command(command)
                        await self.handle_result(response)
                    elif response.status_code == 424 and not upload:
                        js_data = await response.json()
                        required = js_data.get("required", [])
                        to_upload = validate_paths({fp["name"]: fp["path"] for fp in required})
                        mp: HttpResponse = await self.client.cli_execute_raw(
                            command=command,
                            files=to_upload,
                            graph=self.graph,
                            section=self.section,
                            headers=headers,
                        )
                        await handle_response(mp, True)
                    elif response.status_code == 401:
                        self.stderr("Session invalid. Please restart and login again.")
                        raise ShutdownShellError()
                    else:
                        log.debug(f"HTTP error, code: {response.status_code}")
                        self.stderr(await response.text())
                        return

        try:
            received_response = await self.client.cli_execute_raw(
                command=command,
                files=files,
                graph=self.graph,
                section=self.section,
                headers=headers,
            )
            await handle_response(received_response)
        except ConnectionError:
            err = (
                "Error: Could not communicate with fixcore"
                f" at {urlsplit(self.client.fixcore_url).netloc}."
                " Is it up and reachable?"
            )
            self.stderr(err)
        except ShutdownShellError:
            raise
        except Exception as ex:
            self.stderr(f"Error performing command: `{command}`\nReason: {ex}")

    async def handle_result(
        self,
        response: Union[HttpResponse, aiohttp.BodyPartReader, aiohttp.MultipartReader],
        first: bool = True,
    ) -> None:
        # store the file from the part inside the given directory
        async def store_file(response: Union[HttpResponse, aiohttp.BodyPartReader], directory: str) -> Tuple[str, str]:
            if (filepath := response.headers.get("file-path")) is not None:
                path = Path(filepath).expanduser().absolute()
                filepath = str(path)
                filename = path.name
            else:  # fall back to content-disposition
                disposition = response.headers.get("Content-Disposition", "")
                match = re.findall('filename="([^"]+)"', disposition)
                filename = parse.unquote(match[0]) if match else "out"
                if "/" in filename:
                    raise ValueError(f"Invalid filename: {filename}")
                filepath = os.path.join(directory, filename)
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "wb+") as fh:
                if isinstance(response, HttpResponse):
                    content = await response.payload_bytes()
                else:
                    content = await response.read()
                fh.write(content)
            return filename, filepath

        content_type = response.headers.get("Content-Type", "text/plain")
        action = response.headers.get(CLIEnvelope.action)
        command = response.headers.get(CLIEnvelope.command)
        line_delimiter = "---"

        # If we get a plain text result, we simply print it to the console.
        if content_type == "text/plain":
            # Received plain text: print it.
            if not first:
                self.stdout(line_delimiter)
            if isinstance(response, HttpResponse):
                async for line in response.async_iter_lines():
                    decoded = line.decode("utf-8")
                    self.stdout(decoded)
            elif isinstance(response, aiohttp.BodyPartReader):
                while line := await response.readline():
                    decoded = line.decode("utf-8")
                    print(decoded)
            else:
                raise ValueError(f"Found not expected response type: {type(response)}")
        # File is sent in order to edit and return it.
        # We expect the command to define what should happen with the edited file.
        elif content_type == "application/octet-stream" and action == "edit" and command:
            with TemporaryDirectory() as tmp:
                if isinstance(response, aiohttp.MultipartReader):
                    raise ValueError(
                        f"Found not expected response type: {type(response)} for content type {content_type}"
                    )
                filename, filepath = await store_file(response, tmp)
                original_shasum = sha256sum(filepath)
                call([os.environ.get("EDITOR", "vi"), filepath])
                new_shasum = sha256sum(filepath)
                log.debug(f"Original config sha256: {original_shasum}," f" new sha256: {new_shasum}")
                if new_shasum != original_shasum:
                    await self.handle_command(
                        command=f"{command} {filename}", additional_headers={}, files={filename: filepath}
                    )
                else:
                    self.stderr("No change made while editing the file. Update aborted.")
        # File is sent: save it to local disk
        elif content_type == "application/octet-stream":
            if isinstance(response, aiohttp.MultipartReader):
                raise ValueError(f"Found not expected response type: {type(response)} for content type {content_type}")

            filename, filepath = await store_file(response, ArgumentParser.args.download_directory)
            self.stdout(f"Received a file {filename}, which is stored to {filepath}")
        # Multipart: handle each part separately
        elif content_type.startswith("multipart"):
            # Received a multipart response: parse the parts
            if isinstance(response, HttpResponse):
                client_response: aiohttp.ClientResponse = response.undrelying
                reader = aiohttp.MultipartReader(client_response.headers, client_response.content)
            elif isinstance(response, aiohttp.MultipartReader):
                reader = response
            else:
                raise ValueError(f"Found not expected response type: {type(response)} for content type {content_type}")

            num = 0
            async for part in reader:
                await self.handle_result(part, num == 0)
                num += 1

    def stdout(self, text: str) -> None:
        print(text)

    def stderr(self, text: Union[str, FormattedText, Markdown, HTML, ANSI]) -> None:
        print_formatted_text(text, file=sys.stderr, color_depth=self.color_depth)
