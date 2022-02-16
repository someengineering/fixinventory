from resotocore.cli.model import CLIContext


def test_format() -> None:
    context = CLIContext()
    fn = context.formatter("foo={foo} and bla={bla}: {bar}")
    assert fn({}) == "foo=null and bla=null: null"
    assert fn({"foo": 1, "bla": 2, "bar": 3}) == "foo=1 and bla=2: 3"


def test_context_format() -> None:
    context = CLIContext()
    fn, vs = context.formatter_with_variables("foo={foo} and bla={bla}: {bar}")
    assert vs == {"foo", "bla", "bar"}
    assert fn({}) == "foo=null and bla=null: null"
    assert fn({"foo": 1, "bla": 2, "bar": 3}) == "foo=1 and bla=2: 3"
