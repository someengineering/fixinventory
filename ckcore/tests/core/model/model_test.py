import json
from typing import Type, Any, Union, cast

import pytest
from deepdiff import DeepDiff

from datetime import datetime, timedelta
from core.model.typed_model import to_js, from_js
from networkx import DiGraph

from core.model.model import (
    StringKind,
    Kind,
    NumberKind,
    BooleanKind,
    DateKind,
    DateTimeKind,
    ArrayKind,
    Property,
    ComplexKind,
    Model,
    DictionaryKind,
    predefined_kinds,
    PropertyPath,
    TransformKind,
    DurationKind,
)
from core.util import from_utc, utc


def test_json_marshalling() -> None:
    roundtrip(StringKind("string"), Kind)
    roundtrip(StringKind("string", 5, 13, "foo.*bla"), Kind)
    roundtrip(StringKind("string", enum={"foo", "bla"}), Kind)
    roundtrip(NumberKind("num", "int32", minimum=2, maximum=34), Kind)
    roundtrip(NumberKind("num", "int64", enum={1, 2}), Kind)
    roundtrip(BooleanKind("b"), Kind)
    roundtrip(DateKind("d"), Kind)
    roundtrip(DateTimeKind("d"), Kind)
    roundtrip(DurationKind("duration"), Kind)
    roundtrip(TransformKind("synth", "duration", "datetime", "duration_to_datetime", True), Kind)
    roundtrip(ArrayKind(StringKind("string")), Kind)
    roundtrip(Property("foo", "foo"), Property)
    roundtrip(
        ComplexKind(
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


def test_duration() -> None:
    a = DurationKind("dt")
    assert a.check_valid("2w3d5h6m3s") is None
    assert expect_error(a, True) == "Expected type duration but got bool"
    assert expect_error(a, "23df") == "Wrong format for duration: 23df. Examples: 2w, 4h3m, 2weeks, 1second"
    assert a.coerce("12w") == "7257600s"
    with pytest.raises(AttributeError) as no_date:
        a.coerce("simply no duration")
    assert str(no_date.value) == f"Expected duration but got: >simply no duration<"


def test_transform() -> None:
    age = TransformKind("dt", "duration", "datetime", "duration_to_datetime", True)
    age.resolve({"duration": DurationKind("duration"), "datetime": DateTimeKind("datetime")})
    with pytest.raises(AttributeError):
        age.check_valid("3s")  # check valid is not allowed on synthetic values (they do not get imported!)
    # age transforms a duration into a timestamp before now
    one_day_old = from_utc(age.coerce("1d"))
    # difference between 1d and computed utc-24h should be less than 2 seconds (depending on test env less)
    assert (one_day_old - (utc() - timedelta(hours=24))).total_seconds() <= 2


def test_datetime() -> None:
    a = DateTimeKind("dt")
    assert a.check_valid("2021-06-08T08:56:15Z") is None
    assert a.check_valid("2021-06-08T08:56:15+00:00") == "2021-06-08T08:56:15Z"
    assert expect_error(a, True) == "Expected type datetime but got bool"
    assert a.coerce("2021-06-08T08:56:15Z") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000+00:00") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000+02:00") == "2021-06-08T06:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000-02:00") == "2021-06-08T10:56:15Z"
    assert a.coerce("2021-06-08T08:56:15.0000+0000") == "2021-06-08T08:56:15Z"
    assert a.coerce("2021-06-08 08:56:15").startswith("2021-06-08T")  # type: ignore
    assert a.coerce("2021-06-08 08:56:15").endswith(":56:15Z")  # type: ignore # ignore the hours, time zone dependant
    today = datetime.today().replace(hour=6, minute=56, second=15).strftime(DateTimeKind.Format)
    assert a.coerce("08:56:15").startswith(today[0:11])  # type: ignore
    assert a.coerce("08:56:15").endswith(":56:15Z")  # type: ignore# ignore the hours, time zone dependant
    assert a.coerce("-12d").startswith("20")  # type: ignore
    assert a.coerce("12w").startswith("20")  # type: ignore
    with pytest.raises(AttributeError) as no_date:
        a.coerce("simply no date")
    assert str(no_date.value) == f"Expected datetime but got: >simply no date<"


def test_date() -> None:
    a = DateKind("d")
    assert a.check_valid("2021-06-08") is None
    assert expect_error(a, True) == "Expected type date but got bool"
    assert a.coerce("2021-06-08") == "2021-06-08"
    assert a.coerce("2021 06 08") == "2021-06-08"
    assert a.coerce("-12d").startswith("20")  # type: ignore
    assert a.coerce("12w").startswith("20")  # type: ignore
    with pytest.raises(AttributeError) as no_date:
        a.coerce("simply no date")
    assert str(no_date.value) == f"Expected date but got: >simply no date<"


def test_dictionary() -> None:
    model = {k.fqn: k for k in predefined_kinds}
    result = Property.parse_kind("dictionary[string, string]", model)
    assert isinstance(result, DictionaryKind)
    assert result.key_kind is model["string"]
    assert result.value_kind is model["string"]
    result = Property.parse_kind("dictionary[string, dictionary[string, float]]", model)
    assert isinstance(result, DictionaryKind)
    assert result.key_kind is model["string"]
    assert result.value_kind == DictionaryKind(model["string"], model["float"])
    address = ComplexKind(
        "Foo", [], [Property("tags", "dictionary[string, string]"), Property("anything", "dictionary[string, any]")]
    )
    address_model = Model.from_kinds([address])
    assert address_model.check_valid({"kind": "Foo", "tags": {"a": "b", "b": "c"}}) is None
    expected = 'Kind:Foo Property:tags is not valid: value of dictionary[string, string] is not valid: Expected type string but got int: {"kind": "Foo", "tags": {"a": 1, "b": "c"}}'
    assert expect_error(address_model, {"kind": "Foo", "tags": {"a": 1, "b": "c"}}) == expected
    assert address_model.check_valid({"kind": "Foo", "anything": {"a": 1, "b": "c", "c": True}}) is None
    expected = 'Kind:Foo Property:anything is not valid: dictionary requires a json object, but got this: 1: {"kind": "Foo", "anything": 1}'
    assert expect_error(address_model, {"kind": "Foo", "anything": 1}) == expected


def test_any() -> None:
    model = Model.from_kinds(predefined_kinds)
    assert model.check_valid({"kind": "any", "a": True, "b": 12, "c": [], "d": {"a": "b"}}) is None


def test_array() -> None:
    foo = ComplexKind("Foo", [], [Property("tags", "dictionary[string, string]"), Property("kind", "string")])
    complex_kind = ComplexKind(
        "TestArray",
        [],
        [
            Property("kind", "string"),
            Property("los", "string[]"),
            Property("lod", "dictionary[string, string][]"),
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
    assert person_model.check_valid({"kind": "Base", "id": "32", "list": ["one", "two"]}) is None
    expected = 'Kind:Base Property:list is not valid: Expected type string but got int: {"kind": "Base", "id": "32", "list": [1, 2]}'
    assert expect_error(person_model, {"kind": "Base", "id": "32", "list": [1, 2]}) == expected
    expected = 'Kind:Base Property:list is not valid: Expected property is not an array!: {"kind": "Base", "id": "32", "list": "not iterable"}'
    assert expect_error(person_model, {"kind": "Base", "id": "32", "list": "not iterable"}) == expected
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
    anything = {"kind": "any", "some": [1, 2, 3], "not": "defined", "props": True}
    assert person_model.check_valid(anything) is None
    any_foo = {"kind": "any_foo", "id": "foo", "foo": {"a": [1, 2, 3]}, "test": "hallo"}
    assert person_model.check_valid(any_foo) is None


def test_property_path() -> None:
    p1 = PropertyPath(["a", None, "c", None])
    p2 = PropertyPath(["a", "b", "c", "d"])
    p3 = PropertyPath(["a", "b"])
    p4 = p3.child("c").child("d")
    assert p1 == p2
    assert hash(p1) == hash(p2)
    assert p2 == p1
    assert p1 != p3
    assert p2 == p4


def test_property_path_on_model(person_model: Model) -> None:
    # complex based property path
    person: ComplexKind = cast(ComplexKind, person_model["Person"])
    person_path = person.property_by_path()
    assert len(person_path) == 11
    assert person_path[PropertyPath(["name"])].kind == person_model["string"]
    assert person_path[PropertyPath(["name"])].prop.name == "name"
    assert person_path[PropertyPath(["list[]"])].kind == person_model["string"]
    assert person_path[PropertyPath(["list[]"])].prop.name == "list"
    assert person_path[PropertyPath(["tags", None])].kind == person_model["string"]
    assert person_path[PropertyPath(["address", "zip"])].kind == person_model["zip"]
    assert person_path[PropertyPath(["address", "zip"])].prop.name == "zip"
    with pytest.raises(KeyError):
        _ = person_path[PropertyPath(["anything"])]

    # model based property path
    assert person_model.kind_by_path("name") == person_model["string"]
    assert person_model.kind_by_path("list[]") == person_model["string"]
    assert person_model.kind_by_path("tags.foo") == person_model["string"]
    assert person_model.kind_by_path("tags.bla") == person_model["string"]
    assert person_model.kind_by_path("other_addresses.bla.zip") == person_model["zip"]
    assert person_model.kind_by_path("address.zip") == person_model["zip"]


def test_update(person_model: Model) -> None:
    with pytest.raises(AttributeError) as not_allowed:  # update city with different type
        person_model.update_kinds(
            [
                ComplexKind(
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
        == "Update not possible. Address: following properties would be non unique having the same path but different type: city (string -> int32)"
    )

    updated = person_model.update_kinds([StringKind("Foo")])
    assert updated["Foo"].fqn == "Foo"
    with pytest.raises(AttributeError) as simple:
        updated.update_kinds([ComplexKind("Foo", [], [])])
    assert str(simple.value) == "Update Foo changes an existing property type Foo"
    with pytest.raises(AttributeError) as duplicate:
        updated.update_kinds([ComplexKind("Bla", [], [Property("id", "int32")])])
    assert (
        str(duplicate.value)
        == "Update not possible. Bla: following properties would be non unique having the same path but different type: id (string -> int32)"
    )


def test_load(model_json: str) -> None:
    kinds: List[Kind] = [from_js(a, Kind) for a in json.loads(model_json)]  # type: ignore
    model = Model.from_kinds(kinds)
    assert model.check_valid({"kind": "test.EC2", "id": "e1", "name": "e1", "cores": 1, "mem": 32, "tags": {}}) is None

    base: ComplexKind = model["test.Base"]  # type: ignore
    ec2: ComplexKind = model["test.EC2"]  # type: ignore
    assert ec2.kind_hierarchy() == {"test.Compound", "test.BaseResource", "test.Base", "test.EC2"}
    assert ec2.allow_unknown_props is True
    assert base.allow_unknown_props is False


def test_graph(person_model: Model) -> None:
    graph: DiGraph = person_model.graph()
    assert len(graph.nodes()) == 6
    assert len(graph.edges()) == 3


def roundtrip(obj: Any, clazz: Type[object]) -> None:
    js = to_js(obj)
    again = from_js(js, clazz)
    assert type(obj) == type(again)
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
    base = ComplexKind(
        "Base",
        [],
        [
            Property("id", "string", required=True),
            Property("kind", "string", required=True),
            Property("list", "string[]"),
            Property("tags", "dictionary[string, string]"),
            Property("mtime", "datetime"),
        ],
    )
    address = ComplexKind(
        "Address",
        ["Base"],
        [
            Property("zip", "zip"),
            Property("city", "string", required=True),
        ],
    )
    person = ComplexKind(
        "Person",
        ["Base"],
        [
            Property("name", "string"),
            Property("address", "Address"),
            Property("other_addresses", "dictionary[string, Address]"),
            Property("any", "any"),
        ],
    )
    any_foo = ComplexKind(
        "any_foo",
        ["Base"],
        [
            Property("foo", "any"),
            Property("test", "string"),
        ],
    )
    return Model.from_kinds([zip, person, address, base, any_foo])


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
          { "name": "tags", "kind": "dictionary[string, string]", "description": "Tags that describe the resource.", "required": false }
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
        "allow_unknown_props": true,
        "properties": [
          { "name": "mem", "kind": "int32", "description": "The amount of bytes", "required": true },
          { "name": "cores", "kind": "int32", "description": "The amount of cores", "required": true }
        ]
      }
    ]
    """
