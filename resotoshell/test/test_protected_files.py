import os

import pytest

from resotoshell.protected_files import is_protected_file, validate_paths


def test_validate_path() -> None:
    # to test for files, pick one existing in cwd
    cwd_files = [a for a in os.listdir(".") if os.path.isfile(a)]
    if cwd_files:
        first = cwd_files[0]
        validated = validate_paths({"file": f"./{os.path.basename(first)}"})
        assert validated["file"] == os.path.abspath(first)

    with pytest.raises(AttributeError):  # unknown path
        validate_paths({"file": "/this/path/does/not/exist"})
    with pytest.raises(AttributeError):  # not a file
        validate_paths({"file": "/"})


def test_is_protected_file() -> None:
    assert is_protected_file("C:/windows/system32/some/oath", "windows")
    assert is_protected_file("%SystemRoot%/some/path", "windows")
    assert not is_protected_file("D:/application/test", "windows")

    assert is_protected_file("/System/Test/File", "darwin")
    assert is_protected_file("/Library/Test/File", "darwin")
    assert not is_protected_file("/Users/foo/file", "darwin")

    assert is_protected_file("/etc/passwd", "linux")
    assert not is_protected_file("/opt/test/file", "linux")
    assert not is_protected_file("/home/foo/file", "darwin")
