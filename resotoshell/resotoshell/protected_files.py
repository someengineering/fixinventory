import logging
import os.path
import platform
import re
from re import RegexFlag
from typing import Dict

log = logging.getLogger(__name__)

# OS -> List[regexp_strings]
forbidden = {
    "windows": [".*\\/windows\\/.*", ".*SystemRoot.*"],
    "darwin": ["\\/System.*", "\\/Library.*"],
    "linux": [".*\\/etc\\/.*"],
}


def validate_paths(required: Dict[str, str]) -> Dict[str, str]:
    result = {}
    for name, path_in in required.items():
        path = os.path.abspath(os.path.expanduser(path_in))
        if not os.path.exists(path):
            raise AttributeError(f"Path does not exist: {path}")
        if not os.path.isfile(path):
            raise AttributeError(f"Path is not a file: {path}")
        if is_protected_file(path):
            raise AttributeError(f"Not allowed to upload {path}. This path is protected.")
        result[name] = path
    return result


def is_protected_file(path: str, system: str = platform.system()) -> bool:
    """
    Check if given path points to a file that should not be visible to anybody else.
    :param path: the path to check.
    :param system: only here for testing purposes.
    :return: True if the file is protected, otherwise false.
    """
    path_lower = os.path.abspath(path).lower()
    for check in forbidden.get(system.lower(), []):
        if re.compile(check, RegexFlag.IGNORECASE).fullmatch(path_lower):
            return True
    return False
