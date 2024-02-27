import os
from typing import List, Callable
from pathlib import Path

from fixlib.logger import log
from fixworker.config import HomeDirectoryFile


def write_utf8_file(path: Path, content: str) -> None:
    """Write a UTF-8 encoded file to disk"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "wb") as f:
            f.write(content.encode("utf-8"))

    except Exception as e:
        log.warning(f"Failed to write file {path}: {e}")
        return


def write_files_to_home_dir(files: List[HomeDirectoryFile], write_to_disk: Callable[[Path, str], None]) -> None:
    """Write external configuration files to disk"""
    for file in files:
        path = Path(file.path)

        # 1. try to expand '~' to the home directory
        path = path.expanduser()

        # 2. if the path is not absolute, assume it is relative to the home directory
        if not path.is_absolute():
            path = Path.home() / path

        # 3. resolve and normalize the path, e.g. remove /../
        path = path.resolve()

        # 4. make sure the path is not outside the home directory
        if not path.is_relative_to(Path.home()):
            log.warning(f"External configuration file {path} is outside the home directory")
            continue

        # 5. make sure the path is not pointing at a directory
        if path.is_dir():
            log.warning(f"External configuration file {path} points to the existing directory")
            continue

        # 6. write the file
        write_to_disk(path, file.content)
