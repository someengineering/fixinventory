import functools
from pydoc import locate
from typing import Type, Any

import jsons
from frozendict import frozendict  # type: ignore
from jsons import set_deserializer, set_serializer

from resotocore.types import JsonElement, Json
from resotocore.util import AnyT


@functools.lru_cache(maxsize=1024)
def class_by_name(class_name: str) -> type:
    clazz = locate(class_name)
    return clazz if clazz is not None else dict  # type: ignore


def class_fqn(obj: Any) -> str:
    return type_fqn(obj.__class__)


def type_fqn(tpe: type) -> str:
    module = tpe.__module__
    return tpe.__name__ if module is None or module == str.__class__.__module__ else module + "." + tpe.__name__


def from_js(json: JsonElement, clazz: Type[AnyT]) -> AnyT:
    return jsons.load(json, cls=clazz) if clazz != dict else json  # type: ignore


def to_js(node: Any, **kwargs: Any) -> Json:
    """
    Use this method, if the given node is known as complex object,
    so the result will be a json object.
    Otherwise: use to_json directly.
    """
    return to_json(node, **kwargs)  # type: ignore


def to_json(node: Any, **kwargs: Any) -> JsonElement:
    # shortcut: assume a dict is already a json value
    if isinstance(node, dict):
        return node
    return jsons.dump(node, strip_privates=True, strip_microseconds=True, **kwargs)  # type: ignore


def to_js_str(node: Any) -> str:
    return jsons.dumps(node, strip_privates=True)  # type: ignore


# Define serializers for external types ===============


def __unfreeze(f: frozendict, **_: Any) -> Json:
    return dict(f)


def __freeze(json: Json, _: type, **__: Any) -> frozendict:
    return frozendict(json)


set_deserializer(__freeze, frozendict)
set_serializer(__unfreeze, frozendict)
