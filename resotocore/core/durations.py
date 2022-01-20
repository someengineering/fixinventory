import operator
from datetime import timedelta
from functools import reduce
import re
from itertools import chain
from typing import Union, List

import parsy
from parsy import string, Parser

from core.parse_util import lexeme, float_p, integer_p


# See https://en.wikipedia.org/wiki/Unit_of_time for reference
# unit, long name, number of seconds
# The order is relevant: from highest to lowest
time_units = [
    ("yr", "year", 365 * 24 * 3600),
    ("mo", "month", 31 * 24 * 3600),
    ("d", "day", 24 * 3600),
    ("h", "hour", 3600),
    ("min", "minute", 60),
    ("s", "second", 1),
]

time_unit_combines = [",", "and"]

# Check if a string is a valid
DurationRe = re.compile(
    "^[+-]?([\\d.]+("
    + "|".join(chain.from_iterable([short, long, long + "s"] for short, long, _ in time_units))
    + ")\\s*("
    + "|".join(time_unit_combines)
    + ")?\\s*)+$"
)


def combine_durations(elems: List[Union[int, float]]) -> Union[int, float]:
    result = 0.0
    for d in elems:
        result += abs(d)
    return result if elems[0] >= 0 else -result


time_units_parser: Parser = reduce(
    lambda result, tpl: result
    | lexeme(string(tpl[1]) << string("s").optional()).result(tpl[2])
    | lexeme(string(tpl[0])).result(tpl[2]),
    time_units,
    parsy.fail(None),
)
time_unit_combination: Parser = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in [",", "and"]])
single_duration_parser = parsy.seq((float_p | integer_p), time_units_parser).combine(operator.mul)
duration_parser = single_duration_parser.sep_by(time_unit_combination.optional(), min=1).map(combine_durations)


def parse_duration(ds: str) -> timedelta:
    return timedelta(seconds=duration_parser.parse(ds))
