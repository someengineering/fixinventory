import re
from argparse import ArgumentParser
from datetime import datetime
from functools import lru_cache
from typing import (
    TypeVar,
    Union,
    Any,
    Callable,
    NoReturn,
    Optional,
    Awaitable,
    Tuple,
    List,
    AsyncIterable,
)

from aiostream import stream
from aiostream.core import Stream
from parsy import Parser, regex, string

from fixcore.model.graph_access import Section
from fixcore.types import JsonElement, Json
from fixcore.util import utc, parse_utc, AnyT
from fixlib.durations import parse_duration, DurationRe
from fixlib.parse_util import (
    make_parser,
    literal_dp,
    equals_dp,
    json_value_dp,
    space_dp,
    double_quote_dp,
    single_quote_dp,
    any_non_whitespace_string,
    comma_p,
    double_quoted_string_part_dp,
    backslash_dp,
    single_quoted_string_part_dp,
    dash_dp,
    equals_p,
    whitespace,
)

T = TypeVar("T")
JsStream = Stream[JsonElement]
JsGen = AsyncIterable[JsonElement]
# A sink function takes a stream and creates a result
Sink = Callable[[JsStream], Awaitable[T]]

list_sink: Callable[[JsGen], Awaitable[Any]] = stream.list  # type: ignore


@make_parser
def key_value_parser() -> Parser:
    key = yield literal_dp
    yield equals_dp
    value = yield json_value_dp
    return key, value


@make_parser
def arg_with_value_parser() -> Parser:
    # parses --foo bla as (foo, bla) and --foo=bla as (foo, bla)
    # translates - to _ in the key --foo-test bla -> (foo_test, bla)
    yield dash_dp
    yield dash_dp
    key = yield literal_dp
    yield equals_p | space_dp.at_least(1)
    value = yield json_value_dp
    return key.replace("-", "_"), value


# for the cli part: unicode and special characters are translated. escaped \\ \' \" are preserved
string_esc_dp = backslash_dp >> (
    backslash_dp.result(r"\\")
    | string("'").result(r"\'")
    | string('"').result(r"\"")
    | string("b").result("\b")
    | string("f").result("\f")
    | string("n").result("\n")
    | string("r").result("\r")
    | string("t").result("\t")
    | regex(r"u[0-9a-fA-F]{4}").map(lambda s: chr(int(s[1:], 16)))
)


double_quoted_string_part_or_esc_dp = (double_quoted_string_part_dp | string_esc_dp | backslash_dp).many().concat()
single_quoted_string_part_or_esc_dp = (single_quoted_string_part_dp | string_esc_dp | backslash_dp).many().concat()


# name=value test=true -> {name: value, test: true}
key_values_parser: Parser = key_value_parser.sep_by(comma_p | space_dp).map(dict)
args_values_parser: Parser = arg_with_value_parser.sep_by(space_dp).map(dict)
# anything that is not: | " ' ; \
cmd_token = regex("[^|\"';\\\\]+")
# single and double-quoted string are maintained with quotes: "foo"->"foo", 'foo'->'foo'
# all characters inside the quoted string are not parsed
double_quoted_string = double_quote_dp + double_quoted_string_part_or_esc_dp + double_quote_dp
single_quoted_string = single_quote_dp + single_quoted_string_part_or_esc_dp + single_quote_dp
# same as above, but the surrounding quotes are not preserved: "foo"->foo, 'foo'->foo
double_quoted_raw_string = double_quote_dp >> double_quoted_string_part_or_esc_dp << double_quote_dp
single_quoted_raw_string = single_quote_dp >> single_quoted_string_part_or_esc_dp << single_quote_dp
# parse \| \" \' \; and unescape it \| -> |
escaped_token = regex("\\\\[|\"';]").map(lambda x: x[1])
# a command are tokens until EOF or pipe (all characters will be preserved)
cmd_with_args_parser = (escaped_token | double_quoted_string | single_quoted_string | cmd_token).at_least(1).concat()

# argument parser which will read the argument list while removing single and double quotes
# command line arguments: foo "bla: 'foo = bla' -> [foo, bla, foo = bla]
args_parts_unquoted_parser = (
    escaped_token | double_quoted_raw_string | single_quoted_raw_string | any_non_whitespace_string
).sep_by(whitespace, min=1)

# argument parser which will read the argument list while removing single quotes
# Example: "--a \"a or b\" --b 'b or c' --c c d" -> ["--a", "\"a or b\"", "--b", "b or c", "--c", "c", "d"]
args_parts_parser = (
    escaped_token | double_quoted_string | single_quoted_raw_string | any_non_whitespace_string
).sep_by(whitespace, min=1)


def strip_quotes(maybe_quoted: str) -> str:
    res = maybe_quoted.strip()
    if res:
        first = res[0]
        if first in "'\"":
            res = res[1 : len(res) - 1] if res.startswith(first) and res.endswith(first) else res  # noqa: E203
    return res


# check if a is a json node element
def get_node(a: Any) -> Optional[Json]:
    return a if isinstance(a, dict) and "id" in a and Section.reported in a else None


def is_node(a: Any) -> bool:
    return "id" in a and Section.reported in a if isinstance(a, dict) else False


# check if given object is a json edge element
def is_edge(a: Any) -> bool:
    return "from" in a and "to" in a if isinstance(a, dict) else False


class NoExitArgumentParser(ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise AttributeError(f"Could not parse arguments: {message}")

    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        msg = message if message else "unknown"
        raise AttributeError(f"Could not parse arguments: {msg}")


path_array_index_parser = re.compile(r"([^[]+)\[([^]]*)]")


@lru_cache(maxsize=8192)
def parse_path_index(path: str) -> Tuple[str, Union[bool, int, None]]:
    mm = path_array_index_parser.match(path)
    if mm:
        if mm.group(2) in ("*", ""):
            return mm.group(1), True
        elif mm.group(2).isdigit():
            return mm.group(1), int(mm.group(2))
        else:
            raise ValueError(f"Invalid path index: {path}")
    else:
        return path, None


# Is able to read iso timestamps: 2020-01-01T00:00:00.000Z, as well as durations like 1d, 3h, 5m, 10s
def parse_time_or_delta(time_or_delta: str) -> datetime:
    return utc() - parse_duration(time_or_delta) if DurationRe.fullmatch(time_or_delta) else parse_utc(time_or_delta)


def js_value_get(element: JsonElement, path_or_name: Union[List[str], str], if_none: AnyT) -> AnyT:
    result = js_value_at(element, path_or_name)
    return result if result and isinstance(result, type(if_none)) else if_none  # type: ignore


def js_value_at(element: JsonElement, path_or_name: Union[List[str], str]) -> Optional[Any]:
    path = path_or_name if isinstance(path_or_name, list) else path_or_name.split(".")
    at = len(path)

    def at_idx(current: JsonElement, idx: int) -> Optional[Any]:
        if at == idx:
            return current
        prop, index = parse_path_index(path[idx])
        if current is None or not isinstance(current, dict) or prop not in current:
            return None
        else:
            child = current[prop]
            if isinstance(child, list):
                if index is None or index is True:
                    return [at_idx(e, idx + 1) for e in child]
                elif index < len(child):
                    return at_idx(child[index], idx + 1)
                else:
                    return None
            else:
                return at_idx(child, idx + 1)

    return at_idx(element, 0)
