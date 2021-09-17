from typing import Callable

from parsy import Parser, generate, regex, string


def make_parser(fn: Callable[[], Parser]) -> Parser:
    """
    Make typed parser (required for mypy).
    """
    return generate(fn)


whitespace: Parser = regex(r"\s*")


def lexeme(p: Parser) -> Parser:
    """
    Create a whitespace tolerant parser from a given parser.
    """
    return whitespace >> p << whitespace


# region direct parser (not including whitespace)

space_dp = regex(r"\s+")
lparen_dp = string("(")
rparen_dp = string(")")
l_bracket_dp = string("[")
r_bracket_dp = string("]")
l_curly_dp = string("{")
r_curly_dp = string("}")
gt_dp = string(">")
lt_dp = string("<")
colon_dp = string(":")
comma_dp = string(",")
dot_dot_dp = string("..")
equals_dp = string("=")
integer_dp = regex(r"[+-]?[0-9]+").map(int)
float_dp = regex(r"[+-]?[0-9]+\.[0-9]+").map(float)
variable_dp = regex("[A-Za-z][A-Za-z0-9_.*\\[\\]]*")
literal_dp = regex("[A-Za-z0-9][A-Za-z0-9_\\-]*")

string_part_dp = regex(r'[^"\\]+')
string_esc_dp = string("\\") >> (
    string("\\")
    | string("/")
    | string('"')
    | string("b").result("\b")
    | string("f").result("\f")
    | string("n").result("\n")
    | string("r").result("\r")
    | string("t").result("\t")
    | regex(r"u[0-9a-fA-F]{4}").map(lambda s: chr(int(s[1:], 16)))
)
string_part_or_esc_dp = (string_part_dp | string_esc_dp).many().concat()
quoted_string_dp = string('"') >> string_part_or_esc_dp << string('"')
quoted_or_simple_string_dp = quoted_string_dp | literal_dp

true_dp = string("true").result(True)
false_dp = string("false").result(False)
null_dp = string("null").result(None)

# endregion

# region whitespace agnostic parser

lparen_p = lexeme(lparen_dp)
rparen_p = lexeme(rparen_dp)
l_bracket_p = lexeme(l_bracket_dp)
r_bracket_p = lexeme(r_bracket_dp)
l_curly_p = lexeme(l_curly_dp)
r_curly_p = lexeme(r_curly_dp)
gt_p = lexeme(gt_dp)
lt_p = lexeme(lt_dp)
colon_p = lexeme(colon_dp)
comma_p = lexeme(comma_dp)
dot_dot_p = lexeme(dot_dot_dp)
equals_p = lexeme(equals_dp)
true_p = lexeme(true_dp)
false_p = lexeme(false_dp)
null_p = lexeme(null_dp)
float_p = lexeme(float_dp)
integer_p = lexeme(integer_dp)
variable_p = lexeme(variable_dp)
literal_p = lexeme(literal_dp)
quoted_string_p = lexeme(quoted_string_dp)

# endregion


@make_parser
def json_array_parser() -> Parser:
    yield l_bracket_p
    elements = yield json_value_p.sep_by(comma_p)
    yield r_bracket_p
    return elements


@make_parser
def json_object_pair() -> Parser:
    key = yield quoted_string_p | literal_p
    yield colon_p
    val = yield json_value_p
    return key, val


json_object = l_curly_dp >> json_object_pair.sep_by(comma_dp).map(dict) << r_curly_dp
json_value_dp = (
    quoted_string_dp
    | json_array_parser
    | json_object
    | float_dp
    | integer_dp
    | true_dp
    | false_dp
    | null_dp
    | literal_dp
)
json_value_p = lexeme(json_value_dp)
