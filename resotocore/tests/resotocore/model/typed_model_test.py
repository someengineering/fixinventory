import abc
from datetime import datetime

from deepdiff import DeepDiff

from resotocore.model.typed_model import from_js, to_js
from resotocore.query.model import Query, P
from resotocore.query.query_parser import parse_query


class ModelBase(abc.ABC):
    def __init__(self, identity: int):
        self.identity = identity


class ModelFoo(ModelBase):
    def __init__(self, identity: int, a: str, b: int):
        super().__init__(identity)
        self.a = a
        self.b = b


class ModelBar(ModelFoo):
    def __init__(self, identity: int, a: str, b: int, foo: str, bla: datetime):
        super().__init__(identity, a, b)
        self.foo = foo
        self.bla = bla


def test_json_marshalling_works() -> None:
    m = ModelFoo(1, "some foo", 23)
    js = to_js(m)
    js["identity"] = 1
    js["a"] = "some foo"
    js["b"] = 23
    again = from_js(js, ModelFoo)
    d = DeepDiff(m, again, truncate_datetime="second")
    assert len(d) == 0


def test_ignore_private_properties() -> None:
    m = ModelFoo(1, "some foo", 23)
    m.__some_private_prop = 23  # type: ignore
    m.__some_other_dunder = "foo"  # type: ignore
    js = to_js(m)
    assert len(js) == 3


def test_marshal_query() -> None:
    q = Query.by("ec2", P("foo") > 23, P("test") >= "bummer", P("das") < "set")
    again = parse_query(str(q))
    assert str(q) == str(again)
