import json

import jsons
from typing import TypeVar, Any, Type, Optional, Dict

from resotolib.types import Json, JsonElement

AnyT = TypeVar("AnyT")


def to_json(node: Any, **kwargs: Any) -> Json:
    """
    Use this method, if the given node is known as complex object,
    so the result will be a json object.
    """
    return jsons.dump(  # type: ignore
        node,
        strip_privates=True,
        strip_microseconds=True,
        strip_nulls=True,
        # class variables have to stripped manually via strip_attr=
        # see: https://github.com/ramonhagenaars/jsons/issues/177
        # strip_class_variables=True,
        **kwargs,
    )


def to_json_str(node: Any, json_kwargs: Optional[Dict[str, object]] = None, **kwargs: Any) -> str:
    """
    Json string representation of the given object.
    """
    return json.dumps(to_json(node, **kwargs), **(json_kwargs or {}))


def from_json(json: JsonElement, clazz: Type[AnyT]) -> AnyT:
    """
    Loads a json object into a python object.
    :param json: the json object to load.
    :param clazz: the type of the python object.
    :return: the loaded python object.
    """
    return jsons.load(json, cls=clazz) if clazz != dict else json  # type: ignore
