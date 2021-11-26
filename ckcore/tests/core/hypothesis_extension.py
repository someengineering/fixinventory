from typing import TypeVar, Callable, Any, cast, Optional

from hypothesis.strategies import SearchStrategy, just

T = TypeVar("T")


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
