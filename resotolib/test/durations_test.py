from datetime import timedelta
from itertools import chain
from typing import Callable, Any, cast, Optional, TypeVar

from hypothesis import given
from hypothesis.strategies import sampled_from, tuples, integers, composite, lists, SearchStrategy, just

from resotolib.durations import time_unit_parser, time_units, parse_duration, DurationRe, duration_str

units_gen = sampled_from(list(chain.from_iterable(names for _, names, _ in time_units)))
combines_gen = sampled_from(["", ", ", " and "])
duration_gen = tuples(integers(1000, 1000), units_gen).map(lambda x: f"{x[0]}{x[1]}")

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


@composite
def durations_gen(ud: UD) -> str:
    d = Drawer(ud)
    result = d.draw(sampled_from(["", "+", "-"]))
    first = True
    for duration in d.draw(lists(duration_gen, min_size=1, max_size=4)):
        if first:
            first = False
        else:
            result += d.draw(combines_gen)
        result += duration
    return result


@given(durations_gen())
def test_arbitrary_durations(duration_str: str) -> None:
    assert DurationRe.fullmatch(duration_str)
    parse_duration(duration_str)


def test_parse_duration() -> None:
    for short, names, seconds in time_units:
        for name in names:
            assert time_unit_parser.parse(name) == seconds

    assert parse_duration("1s") == timedelta(seconds=1)
    assert parse_duration("4d") == timedelta(days=4)
    assert parse_duration("1h") == timedelta(hours=1)
    assert parse_duration("32days, 4hours and 3min and 3s") == timedelta(days=32, hours=4, minutes=3, seconds=3)
    assert parse_duration("-32days, 4hours and 3min and 3s") == timedelta(days=-32, hours=-4, minutes=-3, seconds=-3)
    assert parse_duration("3d4h6m5s") == timedelta(days=3, hours=4, minutes=6, seconds=5)


def test_duration_string() -> None:
    duration = timedelta(days=1, hours=2, minutes=3, seconds=4)
    assert duration_str(duration) == "1d2h3min4s"
    # define the most granular unit
    assert duration_str(duration, down_to_unit="min") == "1d2h3min"
    assert duration_str(duration, down_to_unit="h") == "1d2h"
    assert duration_str(duration, down_to_unit="d") == "1d"
    assert duration_str(duration, down_to_unit="min") == "1d2h3min"
    # define the precision
    assert duration_str(duration, precision=1) == "1d"
    assert duration_str(duration, precision=2) == "1d2h"
    assert duration_str(duration, precision=3) == "1d2h3min"
