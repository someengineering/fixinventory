from functools import reduce
from typing import Callable

from parsy import string, regex, digit, generate, success, Parser
from core.query.model import Predicate, CombinedTerm, IsInstanceTerm, Part, Navigation, Query, FunctionTerm, IdTerm

whitespace: Parser = regex(r'\s*')


def make_parser(fn: Callable[[], Parser]) -> Parser:
    return generate(fn)


def lexeme(p: Parser) -> Parser:
    return whitespace >> p << whitespace


operationP = reduce(lambda x, y: x | y,
                    [lexeme(string(a)) for a in ["<=", ">=", ">", "<", "==", "!=", "=~", "!~", "in", "not in"]])

functionP = reduce(lambda x, y: x | y, [lexeme(string(a)) for a in ["in_subnet", "has_desired_change"]])

lparenP = lexeme(string('('))
rparenP = lexeme(string(')'))
lbrackP = lexeme(string('['))
rbrackP = lexeme(string(']'))
gtP = lexeme(string('>'))
ltP = lexeme(string('<'))
colonP = lexeme(string(':'))
commaP = lexeme(string(','))
trueP = lexeme(string('true')).result(True)
falseP = lexeme(string('false')).result(False)
nullP = lexeme(string('null')).result(None)
integerP = digit.at_least(1).concat().map(int)
floatP = (digit.many() + string('.').result(['.']) + digit.many()).concat().map(float)
variableP = lexeme(regex("[A-z0-9.*\\[\\]]+"))

string_part = regex(r'[^"\\]+')
string_esc = string('\\') >> (
    string('\\')
    | string('/')
    | string('"')
    | string('b').result('\b')
    | string('f').result('\f')
    | string('n').result('\n')
    | string('r').result('\r')
    | string('t').result('\t')
    | regex(r'u[0-9a-fA-F]{4}').map(lambda s: chr(int(s[1:], 16)))
)
quotedP = lexeme(string('"') >> (string_part | string_esc).many().concat() << string('"'))


@make_parser
def array_parser() -> Parser:
    yield lbrackP
    elements = yield valueP.sep_by(commaP)
    yield rbrackP
    return elements


valueP = quotedP | floatP | integerP | array_parser | trueP | falseP | nullP


@make_parser
def predicate_term() -> Parser:
    name = yield variableP
    op = yield operationP
    value = yield valueP
    return Predicate(name, op, value, {})


@make_parser
def function_term() -> Parser:
    fn = yield functionP
    yield lparenP
    name = yield variableP
    args = yield (commaP >> valueP).many()
    yield rparenP
    return FunctionTerm(fn, name, args)


isinstance_term = lexeme(string("isinstance") >> lparenP >> quotedP << rparenP).map(lambda kind: IsInstanceTerm(kind))
id_term = lexeme(string("id") >> lparenP >> quotedP << rparenP).map(lambda kind: IdTerm(kind))

leafTermP = isinstance_term | id_term | predicate_term | function_term

boolOpP = lexeme(string("and") | string("or"))


@make_parser
def combined_term() -> Parser:
    left = yield simpleTermP
    result = left
    while True:
        op = yield boolOpP | success(None)
        if op is None:
            break
        right = yield simpleTermP
        result = CombinedTerm(result, op, right)
    return result


simpleTermP = (lparenP >> combined_term << rparenP) | leafTermP

# This can parse a complete term
term_parser = combined_term | simpleTermP


@make_parser
def range_parser() -> Parser:
    yield lbrackP
    start = yield integerP
    has_end = yield colonP.optional()
    maybe_end = yield integerP.optional()
    yield rbrackP
    end = start if has_end is None else maybe_end if maybe_end is not None else Navigation.Max
    return [start, end]


direct = (gtP | ltP).result([1, 1])
outP = lexeme(string(">") >> (range_parser | direct) << string(">")).map(lambda nav: Navigation(nav[0], nav[1], "out"))
inP = lexeme(string("<") >> (range_parser | direct) << string("<")).map(lambda nav: Navigation(nav[0], nav[1], "in"))
navigation_parser = outP | inP

pin_parser = lexeme(string("+")).optional().map(lambda x: False if x is None else True)


@make_parser
def part_parser() -> Parser:
    term = yield term_parser
    yield whitespace
    nav = yield navigation_parser | success(None)
    pinned = yield pin_parser
    return Part(term, pinned, nav)


query_parser: Parser = part_parser.many().map(lambda parts: Query(parts[::-1]))


def parse_query(query: str) -> Query:
    return query_parser.parse(query)  # type: ignore
