import json
from typing import Type, Any, Union, List

import pytest
from deepdiff import DeepDiff

from datetime import datetime
from core.model.typed_model import to_js, from_js
from networkx import DiGraph

from core.model.model import (
    StringKind,
    Kind,
    NumberKind,
    BooleanKind,
    DateKind,
    DateTimeKind,
    Array,
    Property,
    Complex,
    Model,
)


def test_json_marshalling() -> None:
    roundtrip(StringKind("string"), Kind)
    roundtrip(StringKind("string", 5, 13, "foo.*bla"), Kind)
    roundtrip(StringKind("string", enum={"foo", "bla"}), Kind)
    roundtrip(NumberKind("num", "int32", minimum=2, maximum=34), Kind)
    roundtrip(NumberKind("num", "int64", enum={1, 2}), Kind)
    roundtrip(BooleanKind("b"), Kind)
    roundtrip(DateKind("d"), Kind)
    roundtrip(DateTimeKind("d"), Kind)
    roundtrip(Array(StringKind("string")), Kind)
    roundtrip(Property("foo", "foo"), Property)
    roundtrip(
        Complex(
            "Test",
            ["Base"],
            [
                Property("array", "string[]"),
                Property("s", "float"),
                Property("i", "int32"),
                Property("other", "SomeComposite"),
            ],
        ),
        Kind,
    )


def test_string() -> None:
    a = StringKind("string", 5, 13, "foo.*bla")
    assert expect_error(a, "foo") == ">foo< does not conform to regex: foo.*bla"
    assert expect_error(a, "fooooo") == ">fooooo< does not conform to regex: foo.*bla"
    assert a.check_valid("fooooobla") is None
    assert expect_error(a, "fooooooooooobla") == ">fooooooooooobla< is too long! Allowed: 13"
    b = StringKind("string", enum={"foo", "bla", "bar"})
    assert b.check_valid("foo") is None
    assert expect_error(b, "baz").startswith(">baz< should be one of")


def test_number() -> None:
    a = NumberKind("cores", "int32", 1, 8)
    assert a.check_valid(1) is None
    assert a.check_valid(8) is None
    assert expect_error(a, 0) == ">0< should be greater or equals than: 1"
    assert expect_error(a, 9) == ">9< should be smaller or equals than: 8"
    b = NumberKind("bin", "int32", enum={1, 2, 4})
    assert b.check_valid(1) is None
    assert expect_error(b, 3) == ">3< should be one of: {1, 2, 4}"


def test_boolean() -> None:
    a = BooleanKind("question")
    assert a.check_valid(True) is None
    assert a.check_valid(False) is None
    assert expect_error(a, "test").startswith("Expected type boolean but got")


def test_datetime() -> None:
    a = DateTimeKind("dt")
    assert a.check_valid("2021-06-08T08:56:15Z") is None
    assert a.check_valid("2021-06-08T08:56:15+00:00") == "2021-06-08T08:56:15Z"
    assert expect_error(a, True) == "Expected type datetime but got bool"
    assert a.coerce("2021-06-08T08:56:15Z") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000+00:00") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000+0000") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08 08:56:15").startswith("2021-06-08T")
    assert a.coerce("2021-06-08 08:56:15").endswith(":56:15Z")  # ignore the hours, time zone dependant
    today = datetime.today().replace(hour=6, minute=56, second=15).strftime(DateTimeKind.Format)
    assert a.coerce("08:56:15").startswith(today[0:11])
    assert a.coerce("08:56:15").endswith(":56:15Z")  # ignore the hours, time zone dependant
    assert a.coerce("-12d").startswith("20")
    assert a.coerce("12w").startswith("20")
    with pytest.raises(AttributeError) as no_date:
        a.coerce("simply no date")
    assert str(no_date.value) == f"Expected datetime but got: >simply no date<"


def test_date() -> None:
    a = DateKind("d")
    assert a.check_valid("2021-06-08") is None
    assert expect_error(a, True) == "Expected type date but got bool"
    assert a.coerce("2021-06-08") == "2021-06-08"
    assert a.coerce("2021 06 08") == "2021-06-08"
    assert a.coerce("-12d").startswith("20")
    assert a.coerce("12w").startswith("20")
    with pytest.raises(AttributeError) as no_date:
        a.coerce("simply no date")
    assert str(no_date.value) == f"Expected date but got: >simply no date<"


def test_dictionary() -> None:
    address = Complex("Foo", [], [Property("tags", "dictionary"), Property("kind", "string")])
    model = Model.from_kinds([address])
    assert model.check_valid({"kind": "Foo", "tags": {"a": "b", "b": "c"}}) is None
    expected = 'Kind:Foo Property:tags is not valid: dictionary allows for simple key/value strings, but got a:1: {"kind": "Foo", "tags": {"a": 1, "b": "c"}}'
    assert expect_error(model, {"kind": "Foo", "tags": {"a": 1, "b": "c"}}) == expected


def test_array() -> None:
    foo = Complex("Foo", [], [Property("tags", "dictionary"), Property("kind", "string")])
    complex_kind = Complex(
        "TestArray",
        [],
        [
            Property("kind", "string"),
            Property("los", "string[]"),
            Property("lod", "dictionary[]"),
            Property("foos", "Foo[]"),
            Property("los_los", "string[][]"),
            Property("los_los_los", "string[][][]"),
        ],
    )
    model = Model.from_kinds([foo, complex_kind])
    assert (
        model.check_valid(
            {
                "kind": "TestArray",
                "los": ["a", "b", "c"],
                "lod": [{"a": "b"}, {"b": "c"}],
                "foos": [{"kind": "Foo", "tags": {"a": "b"}}, {"kind": "Foo", "tags": {"b": "c"}}],
                "los_los": [["a", "b"], ["c"], ["d", "e"]],
                "los_los_los": [[["a", "b"], ["c"]], [["d", "e"], ["f"]]],
            }
        )
        is None
    )


def test_model_checking(person_model: Model) -> None:
    assert person_model.check_valid({"kind": "Base", "id": "32"}) is None
    assert person_model.check_valid({"kind": "Base", "id": "32", "tags": ["one", "two"]}) is None
    expected = 'Kind:Base Property:tags is not valid: Expected type string but got int: {"kind": "Base", "id": "32", "tags": [1, 2]}'
    assert expect_error(person_model, {"kind": "Base", "id": "32", "tags": [1, 2]}) == expected
    expected = 'Kind:Base Property:tags is not valid: Expected property is not an array!: {"kind": "Base", "id": "32", "tags": "not iterable"}'
    assert expect_error(person_model, {"kind": "Base", "id": "32", "tags": "not iterable"}) == expected
    expected = 'Kind:Base Property:id is not valid: Expected type string but got int: {"kind": "Base", "id": 32}'
    assert expect_error(person_model, {"kind": "Base", "id": 32}) == expected
    expected = 'Kind:Base Property:id is required and missing in {"kind": "Base"}'
    assert expect_error(person_model, {"kind": "Base"}) == expected
    expected = "Kind:Base Property:unknown is not defined in model!"
    assert expect_error(person_model, {"kind": "Base", "id": "bla", "unknown": 1}) == expected
    expected = (
        'Kind:Address Property:id is required and missing in {"kind": "Address", "zip": "12345", "city": "gotham"}'
    )
    assert expect_error(person_model, {"kind": "Address", "zip": "12345", "city": "gotham"}) == expected
    nested = {
        "id": "batman",
        "kind": "Person",
        "name": "batman",
        "address": {"kind": "Address", "id": "foo", "city": "gotham"},
    }
    assert person_model.check_valid(nested) is None
    nested = {"id": "batman", "kind": "Person", "name": "batman", "address": {"kind": "Address", "city": "gotham"}}
    expected = 'Kind:Person Property:address is not valid: Kind:Address Property:id is required and missing in {"kind": "Address", "city": "gotham"}: {"id": "batman", "kind": "Person", "name": "batman", "address": {"kind": "Address", "city": "gotham"}}'
    assert expect_error(person_model, nested) == expected
    assert person_model.check_valid({"kind": "Base", "id": "32", "mtime": "2008-09-03T20:56:35+20:00"})["mtime"] == "2008-09-03T00:56:35Z"  # type: ignore


def test_property_path(person_model: Model) -> None:
    # complex based property path
    person_path = person_model["Person"].property_kind_by_path()  # type: ignore
    assert len(person_path) == 7
    assert person_path["name"] == person_model["string"]
    assert person_path["tags[]"] == person_model["string"]
    assert person_path["address.zip"] == person_model["zip"]

    # model based property path
    assert len(person_model.property_kind_by_path) == 10
    assert person_model.property_kind_by_path["name"] == person_model["string"]
    assert person_model.property_kind_by_path["tags[]"] == person_model["string"]
    assert person_model.property_kind_by_path["address.zip"] == person_model["zip"]


def test_update(person_model: Model) -> None:
    with pytest.raises(AttributeError) as not_allowed:  # update city is removed
        person_model.update_kinds([Complex("Address", ["Base"], [])])
    assert str(not_allowed.value) == "Update Address existing required property city cannot be removed!"
    with pytest.raises(AttributeError) as not_allowed:  # update city as not required
        person_model.update_kinds(
            [
                Complex(
                    "Address",
                    ["Base"],
                    [
                        Property("city", "string"),
                    ],
                )
            ]
        )
    assert str(not_allowed.value) == "Update Address existing required property city marked as not required!"
    with pytest.raises(AttributeError) as not_allowed:  # update city with different type
        person_model.update_kinds(
            [
                Complex(
                    "Address",
                    ["Base"],
                    [
                        Property("city", "int32", required=True),
                    ],
                )
            ]
        )
    assert (
        str(not_allowed.value)
        == "Update not possible. Following properties would be non unique having the same path but different type: city"
    )

    updated = person_model.update_kinds([StringKind("Foo")])
    assert updated["Foo"].fqn == "Foo"
    with pytest.raises(AttributeError) as simple:
        updated.update_kinds([Complex("Foo", [], [])])
    assert str(simple.value) == "Update Foo changes an existing property type Foo"
    with pytest.raises(AttributeError) as duplicate:
        updated.update_kinds([Complex("Bla", [], [Property("id", "int32")])])
    assert (
        str(duplicate.value)
        == "Update not possible. Following properties would be non unique having the same path but different type: id"
    )


def test_load(model_json: str) -> None:
    kinds: List[Kind] = [from_js(a, Kind) for a in json.loads(model_json)]  # type: ignore
    model = Model.from_kinds(kinds)
    assert model.check_valid({"kind": "test.EC2", "id": "e1", "name": "e1", "cores": 1, "mem": 32, "tags": {}}) is None
    assert model["test.EC2"].kind_hierarchy() == {"test.Compound", "test.BaseResource", "test.Base", "test.EC2"}


def test_graph(person_model: Model) -> None:
    graph: DiGraph = person_model.graph()
    assert len(graph.nodes()) == 4
    assert len(graph.edges()) == 2


def roundtrip(obj: Any, clazz: Type[object]) -> None:
    js = to_js(obj)
    again = from_js(js, clazz)
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"


def expect_error(kind: Union[Kind, Model], obj: Any) -> str:
    try:
        kind.check_valid(obj)
        raise Exception("Expected an error but got a result!")
    except AttributeError as a:
        return str(a)


@pytest.fixture
def person_model() -> Model:
    zip = StringKind("zip")
    base = Complex(
        "Base",
        [],
        [
            Property("id", "string", required=True),
            Property("kind", "string", required=True),
            Property("tags", "string[]"),
            Property("mtime", "datetime"),
        ],
    )
    address = Complex(
        "Address",
        ["Base"],
        [
            Property("zip", "zip"),
            Property("city", "string", required=True),
        ],
    )
    person = Complex(
        "Person",
        ["Base"],
        [
            Property("name", "string"),
            Property("address", "Address"),
        ],
    )
    return Model.from_kinds([zip, person, address, base])


@pytest.fixture
def model_json() -> str:
    return """
    [
      {
        "fqn": "test.Compound",
        "properties": [
          { "name": "kind", "kind": "string", "required": true, "description": "The kind of this compound type." }
        ]
      },
      {
        "fqn": "test.Base",
        "properties": [
          { "name": "tags", "kind": "dictionary", "description": "Tags that describe the resource.", "required": false }
        ]
      },
      { "fqn" :  "test.BaseResource",
        "bases": ["test.Compound", "test.Base"],
        "properties": [
          { "name": "id", "kind": "string", "description": "The identifier of this resource", "required": true },
          { "name": "name", "kind": "string", "description": "The name of the resource.", "required": true }
        ]
      },
      { "fqn" :  "test.EC2",
        "bases": ["test.BaseResource"],
        "properties": [
          { "name": "mem", "kind": "int32", "description": "The amount of bytes", "required": true },
          { "name": "cores", "kind": "int32", "description": "The amount of cores", "required": true }
        ]
      }
    ]
    """
