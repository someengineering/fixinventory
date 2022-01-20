from datetime import timedelta
from itertools import chain

from hypothesis import given
from hypothesis.strategies import sampled_from, tuples, integers, composite, lists

from core.durations import time_units_parser, time_units, parse_duration, DurationRe
from tests.core.hypothesis_extension import UD, Drawer

units_gen = sampled_from(list(chain.from_iterable([short, long, long + "s"] for short, long, _ in time_units)))
combines_gen = sampled_from(["", ", ", " and "])
duration_gen = tuples(integers(1000, 1000), units_gen).map(lambda x: f"{x[0]}{x[1]}")


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
    for short, long, seconds in time_units:
        assert time_units_parser.parse(short) == seconds
        assert time_units_parser.parse(long) == seconds
        assert time_units_parser.parse(f"{long}s") == seconds

    assert parse_duration("4d") == timedelta(days=4)
    assert parse_duration("1h") == timedelta(hours=1)
    assert parse_duration("32days, 4hours and 3min and 3s") == timedelta(days=32, hours=4, minutes=3, seconds=3)
    assert parse_duration("-32days, 4hours and 3min and 3s") == timedelta(days=-32, hours=-4, minutes=-3, seconds=-3)
