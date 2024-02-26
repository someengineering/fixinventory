from fixcore.db.arangodb_functions import in_subnet, has_desired_change, has_key
from fixcore.db.model import QueryModel
from fixcore.model.model import Model
from fixcore.query.model import FunctionTerm, Query, IsTerm
from fixcore.types import Json


def test_has_desired_change() -> None:
    result = has_desired_change("crs", FunctionTerm("has_desired_change", "foo.bla", []))
    assert result == "crs.desired.foo.bla!=null && crs.reported.foo.bla!=crs.desired.foo.bla"


def test_ip_range() -> None:
    bind_vars: Json = {}
    model = QueryModel(Query.by(IsTerm(["foo"])).on_section("reported"), Model.empty())
    result = in_subnet("crs", bind_vars, FunctionTerm("in_subnet", "foo.bla", ["192.168.1.0/24"]), model)
    assert result == "BIT_AND(IPV4_TO_NUMBER(crs.foo.bla), 4294967040) == @0"
    assert bind_vars["0"] == 3232235776


def test_has_key() -> None:
    bind_vars: Json = {}
    model = QueryModel(Query.by("foo"), Model.empty())
    result = has_key("crs", bind_vars, FunctionTerm("has_key", "foo.bla", [["a", "b", "c"]]), model)
    assert result == "@fn0 ALL IN ATTRIBUTES(crs.foo.bla, true)"
    assert bind_vars["fn0"] == ["a", "b", "c"]
    bind_vars2: Json = {}
    result = has_key("crs", bind_vars2, FunctionTerm("has_key", "foo.bla", ["a"]), model)
    assert result == "HAS(crs.foo.bla, @fn0)"
    assert bind_vars2["fn0"] == "a"
