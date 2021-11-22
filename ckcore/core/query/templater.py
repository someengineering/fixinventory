import functools
import json
from typing import Any, List, Generator, ByteString, Union

from ustache import default_getter, default_virtuals, render

from core.types import Json
from core.util import identity


def with_index(result: Any) -> Any:
    def item(lst: List[Any], idx: int, i: Any) -> Any:
        itm = i
        if not isinstance(i, dict):
            itm = {"value": i}
        itm["index"] = idx
        if idx == 0:
            itm["first"] = True
        if idx == len(lst) - 1:
            itm["last"] = True
        return itm

    if isinstance(result, list):
        result = [item(result, idx, a) for idx, a in enumerate(result)]
    return result


def json_stringify(data: Any, text: bool = False) -> Generator[Union[bytes, ByteString], None, None]:
    if isinstance(data, ByteString) and not text:
        yield data
    elif isinstance(data, str):
        yield data.encode()
    elif isinstance(data, (list, dict)):
        yield json.dumps(data).encode()
    else:
        yield f"{data}".encode()


def render_template(template: str, props: Json) -> str:
    getter = functools.partial(
        default_getter,
        virtuals={
            **default_virtuals,
            "with_index": with_index,
            "parens": lambda s: f'"{s}"',
        },
    )
    return render(template, props, escape=identity, stringify=json_stringify, getter=getter)  # type: ignore
