import json
import sys
from datetime import timedelta, datetime, date, timezone
from typing import TypeVar, Any, Type, Optional, Union, List, get_args, Literal, get_origin, Callable, Iterable

if sys.version_info >= (3, 10):
    from types import UnionType, NoneType
else:
    UnionType = Union
    NoneType = type(None)

import attrs
import cattrs
from cattrs import override
from cattrs.gen import make_dict_unstructure_fn

from resotolib.durations import parse_duration, duration_str
from resotolib.logger import log
from resotolib.types import Json, JsonElement
from resotolib.utils import utc_str, parse_utc, str2timezone

AnyT = TypeVar("AnyT")


def is_primitive_or_primitive_union(t: Any) -> bool:
    if t in (str, bytes, int, float, bool, NoneType):
        return True
    origin = get_origin(t)
    if origin is Literal:
        return True
    if (base := cattrs._compat.get_newtype_base(t)) is not None:
        return is_primitive_or_primitive_union(base)
    if origin in (UnionType, Union):
        return all(is_primitive_or_primitive_union(ty) for ty in get_args(t))
    return False


converter = cattrs.Converter()

# structure hooks
converter.register_structure_hook(datetime, lambda x, _: parse_utc(x))
converter.register_structure_hook(date, lambda obj, typ: date.fromisoformat(obj))
converter.register_structure_hook(timedelta, lambda obj, typ: parse_duration(obj))
converter.register_structure_hook(timezone, lambda obj, typ: str2timezone(obj))
# work around until this is solved: https://github.com/python-attrs/cattrs/issues/278
converter.register_structure_hook_func(is_primitive_or_primitive_union, lambda v, ty: v)  # type: ignore

# unstructure hooks
converter.register_unstructure_hook(datetime, utc_str)
converter.register_unstructure_hook(date, lambda obj: obj.isoformat())
converter.register_unstructure_hook(timedelta, lambda obj: duration_str(obj))
converter.register_unstructure_hook(timezone, lambda obj: str(obj))
converter.register_unstructure_hook_factory(
    attrs.has,
    lambda cls: make_dict_unstructure_fn(
        cls, converter, **{a.name: override(omit=True) for a in attrs.fields(cls) if a.name.startswith("_")}
    ),
)


def to_json_str(node: Any, strip_attr: Union[None, str, Iterable[str]] = None, strip_nulls: bool = False) -> str:
    try:
        return json.dumps(to_json(node, strip_attr, strip_nulls))
    except Exception as e:
        log.debug(f"Can not serialize object {node} to json. Error: {e}")
        raise


def to_json(node: Any, strip_attr: Union[None, str, Iterable[str]] = None, strip_nulls: bool = False) -> Json:
    """
    Use this method, if the given node is known as complex object,
    so the result will be a json object.
    """

    def walk_js_object(js: Json, filter_fn: Optional[Callable[[str, Any], bool]] = None) -> Json:
        result: Json = {}
        for k, v in js.items():
            if filter_fn and not filter_fn(k, v):
                continue
            if isinstance(v, dict):
                v = walk_js_object(v, filter_fn)
            elif isinstance(v, (list, tuple)):
                v = [walk_js_object(e, filter_fn) if isinstance(e, dict) else e for e in v]
            result[k] = v
        return result

    unstructured = converter.unstructure(node)
    if strip_attr:
        remove_keys = {strip_attr} if isinstance(strip_attr, str) else set(strip_attr)
        unstructured = walk_js_object(unstructured, lambda k, v: k not in remove_keys)

    if strip_nulls:
        unstructured = walk_js_object(unstructured, lambda k, v: v is not None)

    return unstructured


def from_json(json: JsonElement, clazz: Type[AnyT]) -> AnyT:
    """
    Loads a json object into a python object.
    :param json: the json object to load.
    :param clazz: the type of the python object.
    :return: the loaded python object.
    """
    try:
        return converter.structure(json, clazz) if clazz != dict else json
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


def set_value_in_path(element: JsonElement, path_or_name: Union[List[str], str], js: Optional[Json] = None) -> Json:
    path = path_or_name if isinstance(path_or_name, list) else path_or_name.split(".")
    at = len(path) - 1

    def at_idx(current: Json, idx: int) -> None:
        if at == idx:
            current[path[-1]] = element
        else:
            value = current.get(path[idx])
            if not isinstance(value, dict):
                value = {}
                current[path[idx]] = value
            at_idx(value, idx + 1)

    js = js if js is not None else {}
    at_idx(js, 0)
    return js


# allow timedelta either as number of seconds or as duration string
def timedelta_from_json(js: Any, _: type = object, **__: Any) -> timedelta:
    if isinstance(js, str):
        return parse_duration(js)
    elif isinstance(js, (int, float)):
        return timedelta(seconds=js)
    else:
        raise ValueError(f"Cannot convert {js} to timedelta")


def is_empty(js: JsonElement) -> bool:
    if js is None:
        return True
    elif isinstance(js, dict):
        return all(is_empty(v) for v in js.values())
    elif isinstance(js, list):
        return all(is_empty(v) for v in js)
    else:
        return False
