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
literal_dp = regex("[A-Za-z][A-Za-z0-9_]*")

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
string_dp = (string_part_dp | string_esc_dp).many().concat()
quoted_string_dp = string('"') >> string_dp << string('"')

true_dp = string("true").result(True)
false_dp = string("false").result(False)
null_dp = string("null").result(None)

value_dp = float_dp | integer_dp | true_dp | false_dp | null_dp | literal_dp | quoted_string_dp
