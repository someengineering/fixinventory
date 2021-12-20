import string
from typing import TypeVar, Callable, Any, cast, Optional

from hypothesis.strategies import SearchStrategy, just, text, dictionaries, booleans, integers, lists, composite

from core.types import JsonElement

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


any_string = text(alphabet=string.ascii_letters, min_size=3, max_size=10)


@composite
def json_element(ud: UD) -> JsonElement:
    return cast(JsonElement, ud(json_simple_element | json_object | json_array))


json_simple_element = any_string | booleans() | integers(min_value=0, max_value=100000) | just(None)
json_object = dictionaries(any_string, json_element(), min_size=1)
json_array = lists(json_element(), max_size=4)
