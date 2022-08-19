import operator
from datetime import timedelta
from functools import reduce
import re
from itertools import chain
from typing import Union, List, Optional

import parsy
from parsy import string, Parser

from resotolib.parse_util import lexeme, float_p, integer_p


# See https://en.wikipedia.org/wiki/Unit_of_time for reference
# The order is relevant: from highest to lowest and longest to shortest
# | output | all names | number of seconds |
time_units = [
    ("yr", ["years", "year", "yr", "y"], 365 * 24 * 3600),
    ("mo", ["months", "month", "mo", "M"], 31 * 24 * 3600),
    ("d", ["days", "day", "d"], 24 * 3600),
    (None, ["weeks", "week", "w"], 7 * 24 * 3600),  # output is none, so it will not be used to print
    ("h", ["hours", "hour", "h"], 3600),
    ("min", ["minutes", "minute", "min", "m"], 60),
    ("s", ["seconds", "second", "s"], 1),
]

time_unit_combines = [",", "and"]

# Check if a string is a valid
DurationRe = re.compile(
    "^[+-]?([\\d.]+\\s*("
    + "|".join(chain.from_iterable(names for unit, names, _ in time_units))
    + ")\\s*("
    + "|".join(time_unit_combines)
    + ")?\\s*)+$"
)


def combine_durations(elems: List[Union[int, float]]) -> Union[int, float]:
    result = 0.0
    for d in elems:
        result += abs(d)
    return result if elems[0] >= 0 else -result


time_unit_parser = reduce(
    lambda x, y: x | y, [lexeme(string(name)).result(seconds) for _, names, seconds in time_units for name in names]
)

time_unit_combination: Parser = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in [",", "and"]])
single_duration_parser = parsy.seq((float_p | integer_p), time_unit_parser).combine(operator.mul)
duration_parser = single_duration_parser.sep_by(time_unit_combination.optional(), min=1).map(combine_durations)


def parse_duration(ds: str) -> timedelta:
    return timedelta(seconds=duration_parser.parse(ds))


def duration_str(duration: timedelta, precision: Optional[int] = 0, down_to_unit: Optional[str] = None) -> str:
    """
    Convert a timedelta to a string representing the duration human-readable short unit syntax.
    Examples: 3d2h, 2min42s
    :param duration: the duration to convert
    :param precision: the number of units to use to represent the duration.
    :param down_to_unit: use all units starting from the biggest one until the given unit.
    :return: string representing the duration
    """
    seconds = duration.total_seconds()
    found = False
    count = 0
    result = ""
    for unit, _, factor in time_units:
        if unit:
            if seconds >= factor:
                found = True
                num = int(seconds / factor)
                seconds = seconds - (num * factor)
                result += f"{num}{unit}"
            if found:
                count += 1
            if precision and count >= precision or unit == down_to_unit:
                break

    # in case the duration is less than one second
    return result if result else ("0s" if down_to_unit is None else f"0{down_to_unit}")
