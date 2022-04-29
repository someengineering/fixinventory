import os
from typing import List

from resotolib.args import get_arg_parser, ArgumentParser, convert, NoneType
from resotolib.logger import add_args as logging_add_args
from resotolib.jwt import add_args as jwt_add_args


def test_args():
    assert ArgumentParser.args.does_not_exist is None

    os.environ["RESOTO_PSK"] = "changeme"
    arg_parser = get_arg_parser()
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    arg_parser.parse_args()
    assert ArgumentParser.args.verbose is False
    assert ArgumentParser.args.psk == "changeme"

    os.environ["RESOTO_PSK"] = ""
    os.environ["RESOTO_VERBOSE"] = "true"
    os.environ["RESOTO_TEST_INT"] = "123"
    os.environ["RESOTO_TEST_LIST0"] = "foobar"
    arg_parser = get_arg_parser()
    logging_add_args(arg_parser)
    jwt_add_args(arg_parser)
    arg_parser.add_argument(
        "--test-int",
        dest="test_int",
        type=int,
        default=0,
    )
    arg_parser.add_argument(
        "--test-list",
        dest="test_list",
        type=str,
        default=[],
        nargs="+",
    )

    arg_parser.parse_args()
    assert ArgumentParser.args.verbose is True
    assert ArgumentParser.args.psk is None
    assert ArgumentParser.args.test_int == 123
    assert ArgumentParser.args.test_list[0] == "foobar"


def test_convert() -> None:
    def make_a_list(s: str) -> List[str]:
        return s.split(",")

    # coercing works
    assert convert(None, NoneType) is None
    assert convert("3", int) == 3
    assert convert("3.4", float) == 3.4
    assert convert("true", bool) is True
    assert convert("false", bool) is False
    assert convert("123", complex) == complex(123)

    # coercing is not possible
    assert convert("no_int", int) == "no_int"
    assert convert("no_float", float) == "no_float"
    assert convert("no_complex", complex) == "no_complex"

    # does not know how to handle
    assert convert("args", ArgumentParser) == "args"

    # call a function
    assert convert("1,2,3,4", make_a_list) == ["1", "2", "3", "4"]
