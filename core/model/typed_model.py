import functools
from pydoc import locate
from typing import Type, Any, Optional, Dict

import jsons


@functools.lru_cache(maxsize=1024)
def class_by_name(class_name: str):
    clazz = locate(class_name)
    return clazz if clazz is not None else dict


def class_fqn(obj: Any):
    return type_fqn(obj.__class__)


@functools.lru_cache(maxsize=1024)
def type_fqn(tpe: type):
    module = tpe.__module__
    return tpe.__name__ if module is None or module == str.__class__.__module__ else module + '.' + tpe.__name__


def from_js(json: Optional[Dict[str, Any]], clazz: Type[object]):
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


def to_js(node):
    # shortcut: assume a dict is already a json value
    if isinstance(node, dict) or isinstance(node, str) or isinstance(node, bool) or \
       isinstance(node, int) or isinstance(node, float) or node is None:
        return node
    return jsons.dump(node, strip_privates=True)
