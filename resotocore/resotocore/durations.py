import operator
from datetime import timedelta
from functools import reduce
import re
from itertools import chain
from typing import Union, List

import parsy
from parsy import string, Parser

from resotocore.parse_util import lexeme, float_p, integer_p


# See https://en.wikipedia.org/wiki/Unit_of_time for reference
# The order is relevant: from highest to lowest and longest to shortest
# | output | all names | number of seconds |
time_units = [
    ("yr", ["years", "year", "yr", "y"], 365 * 24 * 3600),
    ("mo", ["month", "mo", "M"], 31 * 24 * 3600),
    ("d", ["days", "day", "d"], 24 * 3600),
    (None, ["weeks", "week", "w"], 7 * 24 * 3600),  # output is none, so it will not be used to print
    ("h", ["hours", "hour", "h"], 3600),
    ("min", ["minutes", "minute", "min", "m"], 60),
    ("s", ["seconds", "second", "s"], 1),
]

time_unit_combines = [",", "and"]

# Check if a string is a valid
DurationRe = re.compile(
    "^[+-]?([\\d.]+("
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
