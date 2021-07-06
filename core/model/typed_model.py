import functools
from pydoc import locate
from typing import Type, Any, Optional

import jsons

from core.types import Json


@functools.lru_cache(maxsize=1024)
def class_by_name(class_name: str) -> type:
    clazz = locate(class_name)
    return clazz if clazz is not None else dict  # type: ignore


def class_fqn(obj: Any) -> str:
    return type_fqn(obj.__class__)


@functools.lru_cache(maxsize=1024)
def type_fqn(tpe: type) -> str:
    module = tpe.__module__
    return tpe.__name__ if module is None or module == str.__class__.__module__ else module + '.' + tpe.__name__


def from_js(json: Optional[Any], clazz: Type[object]) -> object:
    result = jsons.load(json, cls=clazz) if clazz != dict else json
    # TODO: filter data that is not allowed to view
    # try:
    #     security_manager = SecurityManager.get()
    #     for prop in properties(clazz).values():
    #         if not security_manager.allowed_to_view(clazz, prop):
    #             delattr(result, prop.name)
    # except AttributeError:
    #     pass
    return result


def to_js(node: object) -> Json:
    # shortcut: assume a dict is already a json value
    if isinstance(node, dict):
        return node
    return jsons.dump(node, strip_privates=True)  # type: ignore
