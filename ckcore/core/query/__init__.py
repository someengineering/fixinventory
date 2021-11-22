from abc import ABC, abstractmethod
from dataclasses import dataclass

from parsy import string, Parser, regex, any_char

from core.parse_util import (
    double_quote_dp,
    single_quote_dp,
    double_quoted_string_part_or_esc_dp,
    single_quoted_string_part_or_esc_dp,
    make_parser,
    lparen_p,
    literal_p,
    equals_p,
    json_value_p,
    comma_p,
    colon_p,
    json_object_p,
    rparen_dp,
)
from core.types import Json


@dataclass
class Expandable:
    template: str
    props: Json


class TemplateExpander(ABC):
    @abstractmethod
    async def render(self, maybe_template: str) -> str:
        pass


# double quoted string is maintained with quotes: "foo" -> "foo"
double_quoted_string = double_quote_dp + double_quoted_string_part_or_esc_dp + double_quote_dp
# single quoted string is parsed without surrounding quotes: 'foo' -> 'foo'
single_quoted_string = single_quote_dp + single_quoted_string_part_or_esc_dp + single_quote_dp
expand_fn = string("expand")
not_expand_or_paren = regex("(?:(?!(?:(?:expand\\()|[\"'])).)+")


@make_parser
def key_value_parser() -> Parser:
    key = yield literal_p
    yield equals_p
    value = yield json_value_p
    return key, value


@make_parser
def expand_fn_parser() -> Parser:
    yield expand_fn
    yield lparen_p
    template_name = yield literal_p
    yield (comma_p | colon_p).optional()
    props = yield (json_object_p | key_value_parser.sep_by(comma_p, min=1).map(dict)).optional()
    yield rparen_dp
    return Expandable(template_name, props if props else {})


# a command are tokens until EOF or pipe
string_with_expands = (
    double_quoted_string | single_quoted_string | expand_fn_parser | not_expand_or_paren | any_char
).at_least(1)
