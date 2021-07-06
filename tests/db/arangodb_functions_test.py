from core.db.arangodb_functions import in_subnet, has_desired_change
from core.db.model import QueryModel
from core.model.model import Model
from core.query.model import FunctionTerm, Query, IsInstanceTerm


def test_has_desired_change():
    result = has_desired_change("crs", FunctionTerm("has_desired_change", "foo.bla", []))
    assert result == "crs.desired.foo.bla!=null && crs.reported.foo.bla!=crs.desired.foo.bla"


def test_ip_range():
    bind_vars = {}
    model = QueryModel(Query.by(IsInstanceTerm("foo")), Model.empty(), "reported")
    result = in_subnet("crs", bind_vars, FunctionTerm("in_subnet", "foo.bla", ["192.168.1.0/24"]), model)
    assert result == "BIT_AND(IPV4_TO_NUMBER(crs.reported.foo.bla), 4294967040) == @0"
    assert bind_vars["0"] == 3232235776
