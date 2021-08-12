from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Union, ClassVar

from cloudkeeper_plugin_keepercore.datamodel_export import (
    is_collection,
    type_arg,
    is_dict,
    dict_types,
    transitive_dataclasses,
    export_dataclasses,
    model_name,
)


@dataclass
class DataClassBase:
    resource_type: ClassVar[str] = "base"
    tags: Dict[str, str]


@dataclass
class DataClassProp:
    resource_type: ClassVar[str] = "prop"
    key: Optional[str]
    value: Union[str, int, float]


@dataclass
class DataClassExample(DataClassBase):
    resource_type: ClassVar[str] = "example"
    list_of_string: List[str]
    optional_list_of_props: Optional[List[DataClassProp]]
    props: List[DataClassProp]
    values: dict
    simple_list: list
    weird_list: List[Dict[str, Dict[str, Dict[str, Dict[str, DataClassProp]]]]]
    weird_dict: Dict[str, Dict[str, Dict[str, Dict[str, DataClassProp]]]]
    optionally_weird_dict: Optional[
        Optional[Dict[str, Dict[str, Dict[str, Dict[Union[str, int], DataClassProp]]]]]
    ]


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
    assert transitive_dataclasses([DataClassExample]) == {
        DataClassExample,
        DataClassProp,
        DataClassBase,
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


def test_export_dataclasses() -> None:
    result = export_dataclasses([DataClassExample])
    assert len(result) == 3
    for r in result:
        props = {p["name"]: p for p in r["properties"]}
        if r["fqn"] == "base":
            assert len(r["properties"]) == 1
            assert props["tags"]["kind"] == "dictionary[string, string]"
        elif r["fqn"] == "prop":
            assert len(r["properties"]) == 2
            assert props["key"]["kind"] == "string"
            assert props["value"]["kind"] == "any"
        elif r["fqn"] == "example":
            assert len(r["properties"]) == 8
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
