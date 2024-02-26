from fixlib.args import ArgumentParser
from fixworker.__main__ import add_args
from fixlib.core import add_args as core_add_args, fixcore
from fixworker.config import FixWorkerConfig, HomeDirectoryFile


def test_args() -> None:
    arg_parser = ArgumentParser(
        description="fix worker",
        env_args_prefix="FIXWORKER_",
    )
    add_args(arg_parser)
    core_add_args(arg_parser)
    arg_parser.parse_args()
    assert fixcore.http_uri == "https://localhost:8900"


def test_config() -> None:
    cfg = FixWorkerConfig(write_files_to_home_dir=[HomeDirectoryFile(path="a", content="a")])
    assert cfg.all_files_in_home_dir() == [HomeDirectoryFile("a", "a")]
    cfg = FixWorkerConfig(
        write_files_to_home_dir=[HomeDirectoryFile(path="a", content="a")],
        files_in_home_dir={"b": "b"},
    )
    assert cfg.all_files_in_home_dir() == [HomeDirectoryFile("a", "a"), HomeDirectoryFile("b", "b")]
