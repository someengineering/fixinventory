import pytest
from parsy import ParseError

from resotolib.parse_util import (
    integer_dp,
    float_dp,
    json_value_p,
    unquoted_string_dp,
    unquoted_string_p,
    variable_p,
    unquoted_string_parser,
)


def test_variable_p() -> None:
    assert variable_p.parse("foo.bla.bar") == "foo.bla.bar"
    assert variable_p.parse("foo.bla.bar[*]") == "foo.bla.bar[*]"
    assert variable_p.parse("foo.bla.`foo-bar`") == "foo.bla.`foo-bar`"
    assert variable_p.parse("foo.bla.bar[*].`:-)`.bla[1].test") == "foo.bla.bar[*].`:-)`.bla[1].test"


def test_number_parse() -> None:
    assert integer_dp.parse("-123") == -123
    assert integer_dp.parse("123") == 123
    assert integer_dp.parse("+123") == 123
    assert float_dp.parse("-123.321") == -123.321
    assert float_dp.parse("123.321") == 123.321
    assert float_dp.parse("+123.321") == 123.321


def test_unquoted_string_dp() -> None:
    assert unquoted_string_p.parse("a") == "a"
    assert unquoted_string_p.parse("  abc:123  ") == "abc:123"
    assert unquoted_string_dp.parse("2021-09-23T06:42:26Z") == "2021-09-23T06:42:26Z"
    with pytest.raises(ParseError) as ex:
        unquoted_string_dp.parse("2021%")
    assert str(ex.value) == "expected 'A-Za-z0-9_-:' at 0:5"
    # not will not be parsed, but words
    p = unquoted_string_parser("not", "test", "foo")
    assert p.parse("nothing") == "nothing"
    assert p.parse("tester") == "tester"
    assert p.parse("fooo") == "fooo"
    assert p.parse("no") == "no"
    with pytest.raises(ParseError):
        assert p.parse("not")  # stop word
    with pytest.raises(ParseError):
        assert p.parse("not_123")  # stop word
    with pytest.raises(ParseError):
        assert p.parse("test")  # stop word


def test_json_value_p() -> None:
    assert json_value_p.parse("-123") == -123
    assert json_value_p.parse("123") == 123
    assert json_value_p.parse("123.23") == 123.23
    assert json_value_p.parse("-123.23") == -123.23
    assert json_value_p.parse("127.0.0.1") == "127.0.0.1"
    assert json_value_p.parse('"-123"') == "-123"
    assert json_value_p.parse("2021-09-23T06:42:26Z") == "2021-09-23T06:42:26Z"
    assert json_value_p.parse('"2021-09-23T06:42:26Z"') == "2021-09-23T06:42:26Z"
    assert json_value_p.parse("true") is True
    assert json_value_p.parse("false") is False
    assert json_value_p.parse("null") is None
    assert json_value_p.parse('["a", 1, "2", {"test":"a"}]') == ["a", 1, "2", {"test": "a"}]
    assert json_value_p.parse('{"test":{"foo":{"bla":123}}}') == {"test": {"foo": {"bla": 123}}}
    assert json_value_p.parse("test") == "test"
    assert json_value_p.parse("[foo, bla, bar,baz]") == ["foo", "bla", "bar", "baz"]
