import re
from typing import Callable

import parsy
from parsy import Parser, generate, regex, string


def make_direct_parser(fn: Callable[[str, int], parsy.Result]) -> Parser:
    """
    Make typed parser (required for mypy).
    """
    return Parser(fn)


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
slash = string("/")
colon_dp = string(":")
semicolon_dp = string(";")
comma_dp = string(",")
dot_dp = string(".")
dot_dot_dp = string("..")
equals_dp = string("=")
backtick_dp = string("`")
pipe_dp = string("|")
integer_dp = regex(r"[+-]?[0-9]+").map(int)
float_dp = regex(r"[+-]?[0-9]+\.[0-9]+").map(float)
literal_dp = regex("[A-Za-z0-9][A-Za-z0-9_\\-]*")

# variables:
# - simple props: foo, bla, bar
# - nested props: foo.bla.bar
# - array props: foo[*].bla[0].bar[1]
# - props with non json conform keys: foo.bla.`:-)`.bar
variable_dp_backtick_allowed = regex(r"[^`]+")
variable_dp_backtick = backtick_dp + variable_dp_backtick_allowed + backtick_dp
variable_dp_part_string = regex("[A-Za-z_][A-Za-z0-9_\\-]*")
variable_dp_part_plain = regex("[.]*")
variable_dp_part = variable_dp_part_string | variable_dp_backtick
variable_dp_array_part = variable_dp_part + regex("(\\[[0-9\\*]*\\])*")
optional_slash = slash.at_most(1).concat()
variable_dp = optional_slash + variable_dp_array_part + (dot_dp + variable_dp_array_part).many().map("".join)
variable_no_array_dp = optional_slash + (variable_dp_part + variable_dp_part_plain).at_least(1).map("".join)


unquoted_allowed_characters = re.compile("[A-Za-z0-9_\\-:/.]")
unquoted_end_of_unquoted_str = re.compile("[,\\[\\])(}{\\s]")


def unquoted_string_parser(*stop_words: str) -> Parser:
    @make_direct_parser
    def unquoted_string_direct_parser(stream: str, index: int) -> parsy.Result:
        # read from index until -> end_of_unquoted_str
        # all characters in between have to be allowed characters
        # there has to be at least one non-digit character (to not read numbers as strings)
        start = index
        found_no_number = False
        valid_string_chars = True
        number_found_dot = False

        # valid numbers are: digits or a minus at the start: 123, -321, -123.321
        def is_no_number() -> bool:
            nonlocal number_found_dot
            char = stream[index]
            is_dot = char == "."
            is_num = str.isdigit(char) or (start == index and char == "-") or (is_dot and not number_found_dot)
            if not number_found_dot and is_dot:
                number_found_dot = True
            return not is_num

        # look ahead to next delimiter
        while index < len(stream) and valid_string_chars and not unquoted_end_of_unquoted_str.match(stream[index]):
            found_no_number = is_no_number() if not found_no_number else found_no_number
            valid_string_chars = unquoted_allowed_characters.match(stream[index]) is not None
            index += 1

        result = stream[start:index]
        for stop in stop_words:
            stop_len = len(stop)
            # make sure the result is not a stop word. e.g. foo should match foo, foo-123 but not foobar
            if result.startswith(stop) and (len(result) == stop_len or not str.isalpha(result[stop_len])):
                return parsy.Result.failure(index, "A-Za-z0-9_-:")

        if index <= len(stream) and valid_string_chars and found_no_number:
            return parsy.Result.success(index, result)
        else:
            return parsy.Result.failure(index, "A-Za-z0-9_-:")

    return unquoted_string_direct_parser


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

unquoted_string_dp = unquoted_string_parser()

single_quote_dp = string("'")
single_quoted_string_part_dp = regex(r"[^'\\]+")
single_quoted_string_part_or_esc_dp = (single_quoted_string_part_dp | string_esc_dp).many().concat()
single_quoted_string_dp = single_quote_dp >> single_quoted_string_part_or_esc_dp << single_quote_dp

double_quote_dp = string('"')
double_quoted_string_part_dp = regex(r'[^"\\]+')
double_quoted_string_part_or_esc_dp = (double_quoted_string_part_dp | string_esc_dp).many().concat()
double_quoted_string_dp = double_quote_dp >> double_quoted_string_part_or_esc_dp << double_quote_dp

any_string = parsy.any_char.many().concat()
any_non_white_space_string = parsy.test_char(lambda x: x != " ", "non whitespace").many().concat()
double_quoted_or_simple_string_dp = double_quoted_string_dp | any_string
any_non_whitespace_string = parsy.test_char(lambda c: c != " ", "non whitespace").at_least(1).concat()

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
semicolon_p = lexeme(semicolon_dp)
comma_p = lexeme(comma_dp)
pipe_p = lexeme(pipe_dp)
dot_p = lexeme(dot_dp)
dot_dot_p = lexeme(dot_dot_dp)
equals_p = lexeme(equals_dp)
true_p = lexeme(true_dp)
false_p = lexeme(false_dp)
null_p = lexeme(null_dp)
float_p = lexeme(float_dp)
integer_p = lexeme(integer_dp)
variable_p = lexeme(variable_dp)
variable_no_array_p = lexeme(variable_no_array_dp)
literal_p = lexeme(literal_dp)
quoted_string_p = lexeme(double_quoted_string_dp)
unquoted_string_p = lexeme(unquoted_string_dp)

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


json_object_p = l_curly_dp >> json_object_pair.sep_by(comma_dp).map(dict) << r_curly_dp
simple_json_value_dp = (
    double_quoted_string_dp | true_dp | false_dp | null_dp | unquoted_string_dp | float_dp | integer_dp
)
json_value_dp = json_array_parser | json_object_p | simple_json_value_dp
json_value_p = lexeme(json_value_dp)
