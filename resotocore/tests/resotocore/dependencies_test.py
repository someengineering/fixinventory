from typing import Tuple, List

from resotocore.dependencies import parse_args
from resotocore.types import JsonElement


def test_parse_override() -> None:
    def parse(args: str) -> List[Tuple[str, JsonElement]]:
        return parse_args(args.split()).config_override  # type: ignore

    assert parse(f"--override a=foo") == [("a", "foo")]
    assert parse(f"--override a=foo,bla") == [("a", ["foo", "bla"])]
    assert parse(f"--override a=foo,bla b=a,b,c") == [("a", ["foo", "bla"]), ("b", ["a", "b", "c"])]
    assert parse(f'--override a="value,with,comma,in,quotes"') == [("a", "value,with,comma,in,quotes")]
    assert parse(f'--override a=some,value,"with,comma"') == [("a", ["some", "value", "with,comma"])]
