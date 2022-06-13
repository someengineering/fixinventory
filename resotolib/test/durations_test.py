from datetime import timedelta
from itertools import chain

from hypothesis import given
from hypothesis.strategies import sampled_from, tuples, integers, composite, lists

from resotolib.durations import time_unit_parser, time_units, parse_duration, DurationRe
from tests.resotocore.hypothesis_extension import UD, Drawer

units_gen = sampled_from(list(chain.from_iterable(names for _, names, _ in time_units)))
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
    for short, names, seconds in time_units:
        for name in names:
            assert time_unit_parser.parse(name) == seconds

    assert parse_duration("4d") == timedelta(days=4)
    assert parse_duration("1h") == timedelta(hours=1)
    assert parse_duration("32days, 4hours and 3min and 3s") == timedelta(days=32, hours=4, minutes=3, seconds=3)
    assert parse_duration("-32days, 4hours and 3min and 3s") == timedelta(days=-32, hours=-4, minutes=-3, seconds=-3)
    assert parse_duration("3d4h6m5s") == timedelta(days=3, hours=4, minutes=6, seconds=5)
