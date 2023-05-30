from resotolib.args import ArgumentParser
from resotoworker.__main__ import add_args
from resotolib.core import add_args as core_add_args, resotocore
from resotoworker.config import ResotoWorkerConfig, HomeDirectoryFile


def test_args() -> None:
    arg_parser = ArgumentParser(
        description="resoto worker",
        env_args_prefix="RESOTOWORKER_",
    )
    add_args(arg_parser)
    core_add_args(arg_parser)
    arg_parser.parse_args()
    assert resotocore.http_uri == "https://localhost:8900"


def test_config() -> None:
    cfg = ResotoWorkerConfig(write_files_to_home_dir=[HomeDirectoryFile(path="a", content="a")])
    assert cfg.all_files_in_home_dir() == [HomeDirectoryFile("a", "a")]
    cfg = ResotoWorkerConfig(
        write_files_to_home_dir=[HomeDirectoryFile(path="a", content="a")],
        files_in_home_dir={"b": "b"},
    )
    assert cfg.all_files_in_home_dir() == [HomeDirectoryFile("a", "a"), HomeDirectoryFile("b", "b")]
