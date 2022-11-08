from attrs import define, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Union, ClassVar, Literal

from resotolib.core.model_export import (
    is_collection,
    type_arg,
    is_dict,
    dict_types,
    transitive_classes,
    dataclasses_to_resotocore_model,
    model_name,
    dynamic_object_to_resotocore_model,
    is_primitive_or_primitive_union,
)
from resotolib.baseresources import ModelReference


class ExampleEnum(Enum):
    Moon = "moon"
    Sun = "sun"
    Earth = "earth"


@define(slots=False)
class DataClassBase:
    kind: ClassVar[str] = "base"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {"default": [], "delete": []}

    tags: Dict[str, str] = field(metadata={"description": "Description of tags"})
    _private_prop: dict
    __dunder_prop: list
    ctime: Optional[datetime] = field(metadata={"synthetic": {"age": "trafo.duration_to_datetime"}})


@define
class DataClassProp:
    kind: ClassVar[str] = "prop"
    key: Optional[str]
    value: Union[str, int, float]


@define(slots=False)
class DataClassExample(DataClassBase):
    kind: ClassVar[str] = "example"
    successor_kinds: ClassVar[Dict[str, List[str]]] = {
        "default": ["example"],
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["base"]},
        "predecessors": {"delete": ["other"]},
    }
    list_of_string: List[str]
    optional_list_of_props: Optional[List[DataClassProp]]
    props: List[DataClassProp]
    values: dict
    simple_list: list
    weird_list: List[Dict[str, Dict[str, Dict[str, Dict[str, DataClassProp]]]]]
    weird_dict: Dict[str, Dict[str, Dict[str, Dict[str, DataClassProp]]]]
    optionally_weird_dict: Optional[Optional[Dict[str, Dict[str, Dict[str, Dict[Union[str, int], DataClassProp]]]]]]
    some_enum: ExampleEnum
    optional_enum: Optional[ExampleEnum]


@define(slots=False)
class DataClassOther(DataClassBase):
    kind: ClassVar[str] = "other"
    something: str


def test_collection() -> None:
    assert is_collection(Optional[List[str]]) is True
    assert is_collection(List[str]) is True
    assert is_collection(list) is True
    assert is_collection(dict) is False

    assert type_arg(Optional[List[int]]) == int
    assert type_arg(List[datetime]) == datetime


def test_dictionary() -> None:
    assert is_dict(Optional[Dict[str, str]]) is True
    assert is_dict(Dict[str, str]) is True
    assert is_dict(dict) is True
    assert is_dict(list) is False

    assert dict_types(Dict[str, int]) == (str, int)
    assert dict_types(dict) == (object, object)


def test_transitive() -> None:
    assert transitive_classes({DataClassExample}) == {
        DataClassExample,
        DataClassProp,
        DataClassBase,
        DataClassOther,
        ExampleEnum,
    }


def test_model_name() -> None:
    assert model_name(str) == "string"
    assert model_name(int) == "int64"
    assert model_name(Dict[str, str]) == "dictionary[string, string]"
    assert model_name(Optional[Dict[str, int]]) == "dictionary[string, int64]"
    assert model_name(list) == "any[]"
    assert model_name(dict) == "dictionary[any, any]"
    assert model_name(List[DataClassProp]) == "prop[]"
    assert model_name(Optional[List[DataClassProp]]) == "prop[]"
    assert (
        model_name(Optional[Dict[str, List[Dict[str, DataClassProp]]]])
        == "dictionary[string, dictionary[string, prop][]]"
    )


def test_enum_to_model() -> None:
    assert dataclasses_to_resotocore_model({ExampleEnum}) == [
        {
            "fqn": "example_enum",
            "runtime_kind": "string",
            "enum": ["moon", "sun", "earth"],
        }
    ]


def test_dataclasses_to_resotocore_model() -> None:
    result = dataclasses_to_resotocore_model({DataClassExample})
    assert len(result) == 5
    for r in result:
        props = {p["name"]: p for p in r.get("properties", [])}
        if r["fqn"] == "base":
            assert len(r["properties"]) == 3
            assert r["successor_kinds"] == {"default": [], "delete": []}
            assert props["tags"]["kind"] == "dictionary[string, string]"
            assert props["tags"]["description"] == "Description of tags"
            assert props["ctime"]["kind"] == "datetime"
            assert props["age"]["kind"] == "trafo.duration_to_datetime"
            assert props["age"]["synthetic"]["path"] == ["ctime"]
        elif r["fqn"] == "prop":
            assert r["successor_kinds"] is None
            assert len(r["properties"]) == 2
            assert props["key"]["kind"] == "string"
            assert props["value"]["kind"] == "any"
        elif r["fqn"] == "other":
            assert r["successor_kinds"] == {"default": [], "delete": ["example"]}
        elif r["fqn"] == "example":
            assert set(r["successor_kinds"]["default"]) == {"base", "example"}
            assert len(r["properties"]) == 10
            assert props["list_of_string"]["kind"] == "string[]"
            assert props["optional_list_of_props"]["kind"] == "prop[]"
            assert props["props"]["kind"] == "prop[]"
            assert props["values"]["kind"] == "dictionary[any, any]"
            assert props["simple_list"]["kind"] == "any[]"
            assert (
                props["weird_list"]["kind"]
                == "dictionary[string, dictionary[string, dictionary[string, dictionary[string, prop]]]][]"
            )
            assert (
                props["weird_dict"]["kind"]
                == "dictionary[string, dictionary[string, dictionary[string, dictionary[string, prop]]]]"
            )
            assert (
                props["optionally_weird_dict"]["kind"]
                == "dictionary[string, dictionary[string, dictionary[string, dictionary[any, prop]]]]"
            )
            assert props["some_enum"]["kind"] == "example_enum"
            assert props["optional_enum"]["kind"] == "example_enum"
        elif r["fqn"] == "example_enum":
            assert r["runtime_kind"] == "string"
            assert r["enum"] == [e.value for e in ExampleEnum]


@define
class AwsTestConfig:
    kind: ClassVar[str] = "aws_config"
    access_key: str = field(metadata={"description": "The AWS access key."})
    secret_key: str = field(metadata={"description": "The secret part of the key."})


@define
class GcpTestConfigConfig:
    kind: ClassVar[str] = "gcp_config"
    foo: int = field(metadata={"description": "Some foo value."})


def test_config_export():
    # Let's assume a dynamic top level object of name Config
    # The properties are defined by name and related type.
    result = dynamic_object_to_resotocore_model("config", {"aws": AwsTestConfig, "gcp": GcpTestConfigConfig})
    result_dict = {a["fqn"]: a for a in result}
    assert len(result_dict["gcp_config"]["properties"]) == 1
    assert len(result_dict["aws_config"]["properties"]) == 2
    # Aws properties are rendered with description
    aws = {a["name"]: a["description"] for a in result_dict["aws_config"]["properties"]}
    assert aws == {
        "access_key": "The AWS access key.",
        "secret_key": "The secret part of the key.",
    }
    # Gcp properties are rendered with description
    gcp = {a["name"]: a["description"] for a in result_dict["gcp_config"]["properties"]}
    assert gcp == {"foo": "Some foo value."}
    # All global config properties are defined
    config = {a["name"] for a in result_dict["config"]["properties"]}
    assert config == {"aws", "gcp"}


def test_primitive_union() -> None:
    # simple types
    assert is_primitive_or_primitive_union(str) is True
    assert is_primitive_or_primitive_union(int) is True
    assert is_primitive_or_primitive_union(bool) is True
    assert is_primitive_or_primitive_union(int) is True
    assert is_primitive_or_primitive_union(float) is True
    assert is_primitive_or_primitive_union(type(None)) is True
    assert is_primitive_or_primitive_union(GcpTestConfigConfig) is False
    # literal types
    assert is_primitive_or_primitive_union(Literal["test"]) is True
    # union types
    assert is_primitive_or_primitive_union(Union[str, int, None]) is True
    assert is_primitive_or_primitive_union(Union[str, int, GcpTestConfigConfig]) is False
    assert is_primitive_or_primitive_union(Union[float]) is True
    assert is_primitive_or_primitive_union(Optional[str]) is True
    assert is_primitive_or_primitive_union(Optional[int]) is True
    assert is_primitive_or_primitive_union(Optional[GcpTestConfigConfig]) is False
