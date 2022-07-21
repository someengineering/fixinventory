import json
from datetime import datetime, timedelta
from textwrap import dedent
from typing import Type, Any, Union, cast, List

import pytest
import yaml
from attr import evolve
from deepdiff import DeepDiff
from hypothesis import HealthCheck, settings, given
from networkx import DiGraph

from resotocore.cli.model import CLIContext
from resotocore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from resotocore.model.graph_access import EdgeTypes
from resotocore.model.model import (
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
    SyntheticProperty,
    string_kind,
)
from resotocore.model.typed_model import to_json, from_js
from resotocore.types import Json
from resotocore.util import from_utc, utc, utc_str
from tests.resotocore.hypothesis_extension import json_object_gen


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
    roundtrip(Property("age", "trafo.duration_to_datetime", False, SyntheticProperty(["ctime"])), Property)
    props = [
        Property("array", "string[]"),
        Property("s", "float"),
        Property("i", "int32"),
        Property("other", "SomeComposite"),
    ]
    successor_kinds = {EdgeTypes.default: ["Base", "Test"], EdgeTypes.delete: ["Base"]}
    roundtrip(ComplexKind("Test", ["Base"], props), Kind)
    roundtrip(ComplexKind("Test", [], props, True), Kind)
    roundtrip(ComplexKind("Test", [], props, True, successor_kinds), Kind)


def test_json_sort(person_model: Model) -> None:
    ps = person_model["Person"].sort_json(
        {
            "name": "a",
            "tags": {"c": 2, "a": 1},
            "address": {"name": "a", "id": "a", "city": "gotham", "zip": "123"},
            "mtime": "2020-01-01T00:00:00Z",
            "list": ["b", "a"],
            "id": "a",
        }
    )
    # this is the order of the properties in the model
    assert list(ps.keys()) == ["id", "list", "tags", "mtime", "name", "address"]
    assert list(ps["address"].keys()) == ["id", "zip", "city", "name"]
    # tags do not have a related complex kind: expect natural sort order
    assert list(ps["tags"].keys()) == ["a", "c"]


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
    int32 = NumberKind("cores", "int32", 1, 8)
    flot = NumberKind("test", "float", 1, 8)
    assert int32.coerce_if_required(1) is None
    assert int32.coerce_if_required(None) is None
    assert int32.coerce_if_required("no number") is None
    assert int32.check_valid(1) is None
    assert int32.check_valid(8) is None
    assert int32.check_valid("8") is 8
    assert expect_error(int32, "7.123") == "Expected type int32 but got str"
    assert flot.check_valid("7.123") == 7.123
    assert expect_error(int32, 0) == ">0< should be greater or equals than: 1"
    assert expect_error(int32, 9) == ">9< should be smaller or equals than: 8"
    assert expect_error(int32, "9") == ">9< should be smaller or equals than: 8"
    b = NumberKind("bin", "int32", enum={1, 2, 4})
    assert b.check_valid(1) is None
    assert expect_error(b, 3) == ">3< should be one of: {1, 2, 4}"


def test_boolean() -> None:
    a = BooleanKind("question")
    assert a.coerce_if_required(True) is None
    assert a.coerce_if_required(None) is None
    assert a.coerce_if_required("no bool") is None
    assert a.check_valid(True) is None
    assert a.check_valid(False) is None
    assert a.check_valid("true") is True
    assert a.check_valid("false") is False
    assert a.check_valid("FALSE") is False
    assert expect_error(a, "test").startswith("Expected type boolean but got")


def test_duration() -> None:
    a = DurationKind("dt")
    assert a.check_valid("3d5h6min3s") is None
    assert expect_error(a, True) == "Expected type duration but got bool"
    assert (
        expect_error(a, "23df") == "Wrong format for duration: 23df. Examples: 1yr, 3mo, 3d4h3min1s, 3days and 2hours"
    )
    assert a.coerce("12d") == "1036800s"
    assert a.coerce("12d", normalize=False) == "12d"
    with pytest.raises(AttributeError) as no_date:
        a.check_valid("simply no duration")
    assert (
        str(no_date.value)
        == "Wrong format for duration: simply no duration. Examples: 1yr, 3mo, 3d4h3min1s, 3days and 2hours"
    )


def test_transform() -> None:
    age = TransformKind("dt", "duration", "datetime", "duration_to_datetime", True)
    age.resolve({"duration": DurationKind("duration"), "datetime": DateTimeKind("datetime")})
    with pytest.raises(AttributeError):
        age.check_valid("3s")  # check valid is not allowed on synthetic values (they do not get imported!)
    # age transforms a duration into a timestamp before now
    one_day_old = from_utc(age.coerce_if_required("1d"))  # type: ignore
    # difference between 1d and computed utc-24h should be less than 2 seconds (depending on test env less)
    assert (one_day_old - (utc() - timedelta(hours=24))).total_seconds() <= 2

    # transform back from underlying timestamp to timedelta
    assert age.transform(utc_str(utc() - timedelta(seconds=123))) == "2min3s"
    assert age.transform(utc_str(utc() - timedelta(seconds=123456))) == "1d10h"
    assert age.transform(utc_str(utc() - timedelta(seconds=1234567))) == "14d6h"
    assert age.transform(utc_str(utc() - timedelta(seconds=123456789))) == "3yr10mo"


def test_datetime() -> None:
    a = DateTimeKind("dt")
    assert a.check_valid("2021-06-08T08:56:15Z") is None
    assert a.check_valid("2021-06-08T08:56:15+00:00") == "2021-06-08T08:56:15Z"
    assert expect_error(a, True) == "Expected type datetime but got bool"
    assert a.coerce_if_required(None) is None
    assert a.coerce_if_required("no datetime") is None
    assert a.coerce_if_required("2021-06-08T08") is not None
    assert a.coerce_if_required("2021-06-08T08:56:15Z") is None
    assert a.coerce_if_required("2021-06-08T08:56:15.0000+00:00") == "2021-06-08T08:56:15Z"
    assert a.coerce_if_required("2021-06-08T08:56:15.0000+02:00") == "2021-06-08T06:56:15Z"
    assert a.coerce_if_required("2021-06-08T08:56:15.0000-02:00") == "2021-06-08T10:56:15Z"
    assert a.coerce_if_required("2021-06-08T08:56:15.0000+0000") == "2021-06-08T08:56:15Z"
    assert a.coerce_if_required("2021-06-08 08:56:15").startswith("2021-06-08T")  # type: ignore
    assert a.coerce_if_required("2021-06-08 08:56:15").endswith(":56:15Z")  # type: ignore # ignore the hours, time zone dependant
    today = datetime.today().replace(hour=6, minute=56, second=15).strftime(DateTimeKind.Format)
    assert a.coerce_if_required("08:56:15").startswith(today[0:11])  # type: ignore
    assert a.coerce_if_required("08:56:15").endswith(":56:15Z")  # type: ignore# ignore the hours, time zone dependant
    assert a.coerce_if_required("-12d").startswith("20")  # type: ignore
    assert a.coerce_if_required("12mo").startswith("20")  # type: ignore
    with pytest.raises(Exception) as no_date:
        a.check_valid("simply no date")
    assert str(no_date.value) == f"Invalid isoformat string: 'simply no date'"


def test_date() -> None:
    a = DateKind("d")
    assert a.check_valid("2021-06-08") is None
    assert expect_error(a, True) == "Expected type date but got bool"
    assert a.coerce_if_required("2021-06-08") == "2021-06-08"
    assert a.coerce_if_required("2021 06 08") == "2021-06-08"
    assert a.coerce_if_required("-12d").startswith("20")  # type: ignore
    assert a.coerce_if_required("12mo").startswith("20")  # type: ignore
    with pytest.raises(Exception) as no_date:
        a.check_valid("simply no date")
    assert str(no_date.value) == f"Invalid isoformat string: 'simply no date'"


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
    assert address_model.check_valid({"kind": "Foo", "tags": {"a": 1, "b": "c"}}) is not None
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
    assert person_model.check_valid({"kind": "Base", "id": "32", "list": [1, 2]})["list"] == ["1", "2"]  # type: ignore

    expected = 'Kind:Base Property:list is not valid: Expected property is a json object not an array!: {"kind": "Base", "id": "32", "list": {"not": "an array"}}'
    assert expect_error(person_model, {"kind": "Base", "id": "32", "list": {"not": "an array"}}) == expected
    assert person_model.check_valid({"kind": "Base", "id": 32}) == {"kind": "Base", "id": "32"}
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
    assert p1.same_as(p2)
    assert p2.same_as(p1)
    assert not p1.same_as(p3)
    assert p2.same_as(p4)


def test_property_path_on_model(person_model: Model) -> None:
    # complex based property path
    person: ComplexKind = cast(ComplexKind, person_model["Person"])
    person_path = {p.path: p for p in person.resolved_properties()}
    assert len(person_path) == 20
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

    # access complex types (user.addresses)
    assert person_model.kind_by_path("addresses") == ArrayKind(person_model["Address"])
    assert person_model.kind_by_path("addresses[23]") == person_model["Address"]
    assert person_model.kind_by_path("addresses[23].zip") == person_model["zip"]
    assert person_model.kind_by_path("other_addresses") == DictionaryKind(string_kind, person_model["Address"])
    assert person_model.kind_by_path("other_addresses.test") == person_model["Address"]


def test_update(person_model: Model) -> None:
    with pytest.raises(AttributeError) as not_allowed:  # update city with different type
        person_model.update_kinds([ComplexKind("Address", ["Base"], [Property("city", "int32", required=True)])])
    assert (
        str(not_allowed.value)
        == "Update not possible: following properties would be non unique having the same path but different type: "
        "Address.city (string -> int32)"
    )

    updated = person_model.update_kinds([StringKind("Foo")])
    assert updated["Foo"].fqn == "Foo"
    # update simple type Foo as Complex is forbidden
    with pytest.raises(AttributeError) as simple:
        updated.update_kinds([ComplexKind("Foo", [], [])])
    assert str(simple.value) == "Update Foo changes an existing property type Foo"
    with pytest.raises(AttributeError) as duplicate:
        updated.update_kinds([ComplexKind("Bla", [], [Property("id", "int32")])])
    assert (
        str(duplicate.value)
        == "Update not possible: following properties would be non unique having the same path but different type: "
        "Bla.id (string -> int32)"
    )

    # update the test property of any_foo from string to an enumeration
    prop = Property("test", "string", description="Some test value.")
    updated.update_kinds(
        [
            StringKind("test_enum", enum={"a", "b", "c"}),
            ComplexKind("any_foo", ["Base"], [evolve(prop, kind="test_enum")]),
        ]
    )
    # allowed to change string to duration, any or date
    for kind in ["duration", "any", "date"]:
        updated.update_kinds([ComplexKind("any_foo", ["Base"], [evolve(prop, kind=kind)])])
    # not allowed and should fail
    for kind in ["int32", "int64", "double"]:
        with pytest.raises(AttributeError):
            updated.update_kinds([ComplexKind("any_foo", ["Base"], [evolve(prop, kind=kind)])])


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
    assert len(graph.nodes()) == 11
    assert len(graph.edges()) == 9


def roundtrip(obj: Any, clazz: Type[object]) -> None:
    js = to_json(obj)
    again = from_js(js, clazz)
    assert type(obj) == type(again)
    assert DeepDiff(obj, again) == {}, f"Json: {js} serialized as {again}"


def expect_error(kind: Union[Kind, Model], obj: Any) -> str:
    try:
        kind.check_valid(obj)
        raise Exception("Expected an error but got a result!")
    except Exception as a:
        return str(a)


@pytest.fixture
def person_model() -> Model:
    zip = StringKind("zip")
    base = ComplexKind(
        "Base",
        [],
        [
            Property("id", "string", required=True, description="Some identifier"),
            Property("kind", "string", required=True, description="Kind if this node."),
            Property("list", "string[]", description="A list of strings."),
            Property("tags", "dictionary[string, string]", description="Key/value pairs."),
            Property("mtime", "datetime", description="Modification time of this node."),
        ],
    )
    address = ComplexKind(
        "Address",
        ["Base"],
        [
            Property("zip", "zip", description="The zip code."),
            Property("city", "string", required=True, description="The name of the city.\nAnd another line."),
        ],
    )
    person = ComplexKind(
        "Person",
        ["Base"],
        [
            Property("name", "string", description="The name of the person."),
            Property("address", "Address", description="The address of the person."),
            Property("other_addresses", "dictionary[string, Address]", description="Other addresses."),
            Property("addresses", "Address[]", description="The list of addresses."),
            Property("any", "any", description="Some arbitrary value."),
        ],
    )
    any_foo = ComplexKind(
        "any_foo",
        ["Base"],
        [
            Property("foo", "any", description="Some foo value."),
            Property("test", "string", description="Some test value."),
        ],
    )
    cloud = ComplexKind("cloud", ["Base"], [])
    account = ComplexKind("account", ["Base"], [])
    region = ComplexKind("region", ["Base"], [])
    parent = ComplexKind("parent", ["Base"], [])
    child = ComplexKind("child", ["Base"], [])

    return Model.from_kinds([zip, person, address, base, any_foo, cloud, account, region, parent, child])


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


def test_markup() -> None:
    ctx = CLIContext(console_renderer=ConsoleRenderer(color_system=ConsoleColorSystem.monochrome))
    md = dedent(
        """
        - b1 test
        - b2 fox
        - test
        """
    )
    result = ctx.render_console(md)
    assert len(result) > len(md)
    assert "• b1 test" in result


def test_yaml(person_model: Model) -> None:
    person_kind: ComplexKind = person_model["Person"]  # type: ignore
    address = {"zip": "134", "city": "gotham", "number": 123, "float": 1.2345}
    person = {
        "name": "batman",
        "address": address,
        "addresses": [address, address],
        "other_addresses": {"home": address, "work": address},
        "simple": [1, 2, 3, 4, 5, True, False, None],
    }
    assert person_kind.create_yaml(person) == dedent(
        """
        # The name of the person.
        name: 'batman'
        # The address of the person.
        address:
          # The zip code.
          zip: '134'
          # The name of the city.
          # And another line.
          city: 'gotham'
          number: 123
          float: 1.2345
        # The list of addresses.
        addresses:
          - # The zip code.
            zip: '134'
            # The name of the city.
            # And another line.
            city: 'gotham'
            number: 123
            float: 1.2345
          - # The zip code.
            zip: '134'
            # The name of the city.
            # And another line.
            city: 'gotham'
            number: 123
            float: 1.2345
        # Other addresses.
        other_addresses:
          home:
            # The zip code.
            zip: '134'
            # The name of the city.
            # And another line.
            city: 'gotham'
            number: 123
            float: 1.2345
          work:
            # The zip code.
            zip: '134'
            # The name of the city.
            # And another line.
            city: 'gotham'
            number: 123
            float: 1.2345
        simple:
          - 1
          - 2
          - 3
          - 4
          - 5
          - true
          - false
          - null
          """.rstrip()
    )

    assert person == yaml.safe_load(person_kind.create_yaml(person))


@given(json_object_gen)
@settings(max_examples=50, suppress_health_check=HealthCheck.all())
def test_yaml_generation(js: Json) -> None:
    kind = ComplexKind("test", [], [])
    assert js == yaml.safe_load(kind.create_yaml(js))
