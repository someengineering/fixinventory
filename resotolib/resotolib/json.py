import json
from datetime import timedelta
from typing import TypeVar, Any, Type, Optional, Dict, Union, List

import attrs
import cattrs
import jsons
from cattrs import override
from cattrs.gen import make_dict_unstructure_fn
from jsons import set_deserializer

from resotolib.durations import parse_duration
from resotolib.logger import log
from resotolib.types import Json, JsonElement

AnyT = TypeVar("AnyT")


converter = cattrs.Converter()
converter.register_unstructure_hook_factory(
    attrs.has,
    lambda cls: make_dict_unstructure_fn(
        cls, converter, **{a.name: override(omit=True) for a in attrs.fields(cls) if a.name.startswith("_")}
    ),
)


def to_json(node: Any, **kwargs: Any) -> Json:
    """
    Use this method, if the given node is known as complex object,
    so the result will be a json object.
    """
    unstructured = converter.unstructure(node)
    if strip_attr := kwargs.get("strip_attr"):
        if isinstance(strip_attr, str):
            if unstructured.get(strip_attr):
                del unstructured[strip_attr]
        elif isinstance(strip_attr, (list, tuple)):
            for field in strip_attr:
                if unstructured.get(field):
                    del unstructured[field]
        else:
            raise ValueError(f"Don't know how to handle type of strip_attr: {strip_attr}")
    result: Json = jsons.dump(  # type: ignore
        unstructured,
        strip_microseconds=True,
        strip_nulls=True,
        # class variables have to stripped manually via strip_attr=
        # see: https://github.com/ramonhagenaars/jsons/issues/177
        # strip_class_variables=True,
        **kwargs,
    )
    return result


def to_json_str(node: Any, json_kwargs: Optional[Dict[str, object]] = None, **kwargs: Any) -> str:
    """
    Json string representation of the given object.
    """
    return json.dumps(to_json(node, **kwargs), **(json_kwargs or {}))


def from_json(json: JsonElement, clazz: Type[AnyT], **kwargs: Any) -> AnyT:
    """
    Loads a json object into a python object.
    :param json: the json object to load.
    :param clazz: the type of the python object.
    :return: the loaded python object.
    """
    try:
        return jsons.load(json, clazz, **kwargs) if clazz != dict else json  # type: ignore
    except Exception as e:
        log.debug(f"Can not deserialize json into class {clazz.__name__}: {json}. Error: {e}")
        raise


def value_in_path(element: JsonElement, path_or_name: Union[List[str], str]) -> Optional[Any]:
    """
    Access a value in a json object by a defined path.
    {"a": {"b": {"c": 1}}} -> value_in_path({"a": {"b": {"c": 1}}}, ["a", "b", "c"]) -> 1
    The path can be defined as a list of strings or as a string with dots as separator.
    """
    path = path_or_name if isinstance(path_or_name, list) else path_or_name.split(".")
    at = len(path)

    def at_idx(current: JsonElement, idx: int) -> Optional[Any]:
        if at == idx:
            return current
        elif current is None or not isinstance(current, dict) or path[idx] not in current:
            return None
        else:
            return at_idx(current[path[idx]], idx + 1)

    return at_idx(element, 0)


# allow timedelta either as number of seconds or as duration string
def timedelta_from_json(js: Any, _: type = object, **__: Any) -> timedelta:
    if isinstance(js, str):
        return parse_duration(js)
    elif isinstance(js, (int, float)):
        return timedelta(seconds=js)
    else:
        raise ValueError(f"Cannot convert {js} to timedelta")


set_deserializer(timedelta_from_json, timedelta)
