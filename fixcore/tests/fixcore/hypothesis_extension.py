import string
from datetime import datetime
from typing import TypeVar, Any, cast, Optional, List, Generator

from hypothesis.strategies import (
    SearchStrategy,
    just,
    text,
    dictionaries,
    booleans,
    integers,
    lists,
    composite,
    sampled_from,
    DrawFn,
)

from fixcore.model.resolve_in_graph import NodePath
from fixcore.types import JsonElement, Json
from fixcore.util import value_in_path, interleave
from fixlib.asynchronous.stream import Stream

T = TypeVar("T")


def optional(st: SearchStrategy[T]) -> SearchStrategy[Optional[T]]:
    return st | just(None)


any_ws_digits_string = text(alphabet=string.ascii_letters + " " + string.digits, min_size=0, max_size=10)
any_string = text(alphabet=string.ascii_letters, min_size=3, max_size=10)
kind_gen = sampled_from(["volume", "instance", "load_balancer", "volume_type"])

any_datetime = integers(min_value=0, max_value=1688108028).map(lambda x: datetime.fromtimestamp(x))


@composite
def json_element_gen(draw: DrawFn) -> JsonElement:
    return cast(JsonElement, draw(json_object_gen | json_simple_element_gen | json_array_gen))


json_simple_element_gen = any_ws_digits_string | booleans() | integers(min_value=0, max_value=100000) | just(None)
json_object_gen = dictionaries(any_string, json_element_gen(), min_size=1, max_size=5)
json_array_gen = lists(json_element_gen(), max_size=5)


@composite
def node_gen(draw: DrawFn) -> Json:
    uid = draw(any_string)
    name = draw(any_string)
    kind = draw(kind_gen)
    reported = draw(json_object_gen)
    metadata = draw(json_object_gen)
    desired = draw(json_object_gen)
    return {
        "id": uid,
        "kinds": [kind],
        "reported": {**reported, "kind": kind, "id": uid, "name": name},
        "metadata": metadata,
        "desired": desired,
        "type": "node",
    }


def graph_stream(node_list: List[Json]) -> Stream[Json]:
    def from_node() -> Generator[Json, Any, None]:
        for node in node_list:
            yield node
        node_ids = [value_in_path(a, NodePath.node_id) for a in node_list]
        for from_n, to_n in interleave(node_ids):
            yield {"type": "edge", "from": from_n, "to": to_n}

    return Stream.iterate(from_node())
