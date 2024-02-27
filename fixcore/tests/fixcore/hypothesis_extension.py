import string
from datetime import datetime
from typing import TypeVar, Callable, Any, cast, Optional, List, Generator

from aiostream import stream
from aiostream.core import Stream
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
)

from fixcore.model.resolve_in_graph import NodePath
from fixcore.types import JsonElement, Json
from fixcore.util import value_in_path, interleave

T = TypeVar("T")
UD = Callable[[SearchStrategy[Any]], Any]


def optional(st: SearchStrategy[T]) -> SearchStrategy[Optional[T]]:
    return st | just(None)


class Drawer:
    """
    Only here for getting a drawer for typed drawings.
    """

    def __init__(self, hypo_drawer: Callable[[SearchStrategy[Any]], Any]):
        self._drawer = hypo_drawer

    def draw(self, st: SearchStrategy[T]) -> T:
        return cast(T, self._drawer(st))

    def optional(self, st: SearchStrategy[T]) -> Optional[T]:
        return self.draw(optional(st))


any_ws_digits_string = text(alphabet=string.ascii_letters + " " + string.digits, min_size=0, max_size=10)
any_string = text(alphabet=string.ascii_letters, min_size=3, max_size=10)
kind_gen = sampled_from(["volume", "instance", "load_balancer", "volume_type"])

any_datetime = integers(min_value=0, max_value=1688108028).map(lambda x: datetime.fromtimestamp(x))


@composite
def json_element_gen(ud: UD) -> JsonElement:
    return cast(JsonElement, ud(json_object_gen | json_simple_element_gen | json_array_gen))


json_simple_element_gen = any_ws_digits_string | booleans() | integers(min_value=0, max_value=100000) | just(None)
json_object_gen = dictionaries(any_string, json_element_gen(), min_size=1, max_size=5)
json_array_gen = lists(json_element_gen(), max_size=5)


@composite
def node_gen(ud: UD) -> Json:
    d = Drawer(ud)
    uid = d.draw(any_string)
    name = d.draw(any_string)
    kind = d.draw(kind_gen)
    reported = d.draw(json_object_gen)
    metadata = d.draw(json_object_gen)
    desired = d.draw(json_object_gen)
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

    return stream.iterate(from_node())
