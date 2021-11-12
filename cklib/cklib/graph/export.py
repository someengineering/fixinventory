import sys
from dataclasses import is_dataclass, fields, Field
from datetime import datetime, date, timedelta, timezone
from functools import lru_cache, reduce
from pydoc import locate
from typing import List, MutableSet, Union, Tuple, Dict, Set, Any, TypeVar
from cklib.baseresources import BaseResource
from cklib.utils import type_str, str2timedelta, str2timezone
from cklib.logging import log

# load the correct function depending on the version
if sys.version_info >= (3, 8):
    from typing import get_args, get_origin
else:
    from typing_compat import get_args, get_origin


Json = Dict[str, Any]


# List[X] -> list, list -> list
def optional_origin(clazz: type) -> type:
    maybe_optional = get_args(clazz)[0] if is_optional(clazz) else clazz
    origin = get_origin(maybe_optional)
    return origin if origin else maybe_optional


# Optional[x] -> true
def is_optional(clazz: type) -> bool:
    args = get_args(clazz)
    return get_origin(clazz) is Union and type(None) in args and len(args) == 2


# List[x] -> true, list -> true
def is_collection(clazz: type) -> bool:
    return optional_origin(clazz) in [list, set, tuple]


# Dict[x,y] -> true, dict -> true
def is_dict(clazz: type) -> bool:
    return optional_origin(clazz) in [dict]


# List[X] -> X, list -> object
def type_arg(clazz: type) -> type:
    maybe_optional = get_args(clazz)[0] if is_optional(clazz) else clazz
    args = get_args(maybe_optional)
    return args[0] if args and len(args) == 1 else object


# Dict[X,Y] -> (X,Y), dict -> (object, object)
def dict_types(clazz: type) -> Tuple[type, type]:
    maybe_optional = get_args(clazz)[0] if is_optional(clazz) else clazz
    args = get_args(maybe_optional)
    return (args[0], args[1]) if args and len(args) == 2 else (object, object)


# walk class hierarchy, as well as all properties to find transitive data classes
def transitive_dataclasses(classes: Set[type]) -> Set[type]:
    all_classes: MutableSet[type] = set()

    def check(to_check: type) -> None:
        clazz = optional_origin(to_check)
        if is_dict(clazz):
            key_type, value_type = dict_types(to_check)
            check(key_type)
            check(value_type)
        elif is_collection(clazz):
            check(type_arg(to_check))
        elif clazz not in all_classes and is_dataclass(clazz):
            all_classes.add(clazz)
            for mro_clazz in clazz.mro()[1:]:
                check(mro_clazz)
            for subclass in clazz.__subclasses__():
                check(subclass)
            for field in fields(clazz):
                check(field.type)

    for c in classes:
        check(c)

    return set(all_classes)


lookup: Dict[type, str] = {
    str: "string",
    int: "int64",
    bool: "boolean",
    float: "double",
    datetime: "datetime",
    date: "date",
    timedelta: "string",
}
simple_type = tuple(lookup.keys())


# Model name from the internal python class name
def model_name(clazz: type) -> str:
    to_check = get_args(clazz)[0] if is_optional(clazz) else clazz
    if is_collection(to_check):
        return f"{model_name(type_arg(to_check))}[]"
    elif is_dict(to_check):
        key_type, value_type = dict_types(to_check)
        return f"dictionary[{model_name(key_type)}, {model_name(value_type)}]"
    elif get_origin(to_check) == Union:
        # this is a union of different types other than none.
        # since union types are not supported, we fallback to any here
        return "any"
    elif isinstance(to_check, TypeVar):
        return model_name(get_args(to_check))
    elif isinstance(to_check, type) and issubclass(to_check, simple_type):
        return lookup[to_check]
    elif is_dataclass(to_check):
        name = getattr(to_check, "kind", None)
        if not name:
            raise AttributeError(
                f"dataclass {to_check} need to define a ClassVar kind!"
            )
        return name
    else:
        return "any"


# define if a field should be exported or not.
# Use python default: hide props starting with underscore.
def should_export(field: Field) -> bool:
    return not field.name.startswith("_")


def dataclasses_to_ckcore_model(classes: Set[type]) -> List[Json]:
    """
    Analyze all transitive dataclasses and create the model
    definition as understood by ckcore.
    A plain python dataclass defines the model structure and
    should be used to create json in the same format.

    :param classes: all dataclasses to analyze.
    :return: the model definition in the ckcore json format.
    """

    def prop(field: Field) -> List[Json]:
        # the field itself can define the type via a type hint
        # this is useful for int and float in python where the representation can not be
        # detected by the type itself. Example: int32/int64 or float/double
        # If not defined, we fallback to the largest container: int64 and double
        name = field.name
        kind = field.metadata.get("type_hint", model_name(field.type))
        desc = field.metadata.get("description", "")
        required = field.metadata.get("required", False)
        synthetic = field.metadata.get("synthetic")
        synthetic = synthetic if synthetic else {}

        def json(
            name: str, kind_str: str, required: bool, description: str, **kwargs: Any
        ) -> Json:
            return {
                "name": name,
                "kind": kind_str,
                "required": required,
                "description": description,
                **kwargs,
            }

        synthetics = [
            json(
                synth_prop,
                synth_trafo,
                False,
                f"Synthetic prop {synth_trafo} on {name}",
                synthetic={"path": [name]},
            )
            for synth_prop, synth_trafo in synthetic.items()
        ]

        # required = not is_optional(field.type)
        return [json(name, kind, required, desc)] + synthetics

    model: List[Json] = []
    for clazz in transitive_dataclasses(classes):
        bases = [base for base in clazz.__bases__ if is_dataclass(base)]
        base_names = [model_name(base) for base in bases]
        base_props: Set[Field] = reduce(
            lambda result, base: result | set(fields(base)), bases, set()
        )
        props = [
            p
            for field in fields(clazz)
            if field not in base_props and should_export(field)
            for p in prop(field)
        ]
        model.append(
            {"fqn": model_name(clazz), "bases": base_names, "properties": props}
        )
    return model


def format_value_for_export(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    elif isinstance(value, (timedelta, timezone)):
        return str(value)
    return value


def get_node_attributes(node: BaseResource) -> Dict:
    attributes: Dict = {"kind": node.kind}
    if not is_dataclass(node):
        raise ValueError(f"Node {node.rtdname} is no dataclass")
    for field in fields(node):
        if field.name.startswith("_"):
            continue
        value = getattr(node, field.name, None)
        if value is None:
            continue
        value = format_value_for_export(value)
        attributes.update({field.name: value})
    return attributes


def node_to_dict(
    node: BaseResource, changes_only: bool = False, include_revision: bool = False
) -> Dict:
    node_dict = {"id": node._ckcore_id if node._ckcore_id else node.chksum}
    if changes_only:
        node_dict.update(node.changes.get())
    else:
        node_dict.update(
            {
                "reported": get_node_attributes(node),
                "metadata": {
                    "python_type": type_str(node),
                    "cleaned": node.cleaned,
                    "phantom": node.phantom,
                    "protected": node.protected,
                },
            }
        )
        if node.clean:
            node_dict.update(
                {
                    "desired": {
                        "clean": node.clean,
                    }
                }
            )
    if include_revision and node._ckcore_revision:
        node_dict.update(
            {
                "revision": node._ckcore_revision,
            }
        )
    return node_dict


@lru_cache(maxsize=None)
def locate_python_type(python_type: str) -> Any:
    return locate(python_type)


def node_from_dict(node_data: Dict) -> BaseResource:
    """Create a resource from ckcore graph node data"""
    log.debug(f"Making node from {node_data}")
    node_data_reported = node_data.get("reported", {})
    if node_data_reported is None:
        node_data_reported = {}
    node_data_desired = node_data.get("desired", {})
    if node_data_desired is None:
        node_data_desired = {}
    node_data_metadata = node_data.get("metadata", {})
    if node_data_metadata is None:
        node_data_metadata = {}

    new_node_data = dict(node_data_reported)
    if "kind" in new_node_data:
        del new_node_data["kind"]

    python_type = node_data_metadata.get("python_type", "NoneExisting")
    node_type = locate_python_type(python_type)
    if node_type is None:
        raise ValueError(f"Do not know how to handle {node_data_reported}")

    restore_node_field_types(node_type, new_node_data)
    cleanup_node_field_types(node_type, new_node_data)

    ancestors = {}
    for ancestor in ("cloud", "account", "region", "zone"):
        if node_data_reported.get(ancestor) and node_data_metadata.get(ancestor):
            ancestors[f"_{ancestor}"] = node_from_dict(
                {
                    "reported": node_data_reported[ancestor],
                    "metadata": node_data_metadata[ancestor],
                }
            )
    new_node_data.update(ancestors)
    new_node_data.update(
        {
            "_ckcore_id": node_data.get("id"),
            "_ckcore_revision": node_data.get("revision"),
        }
    )

    node = node_type(**new_node_data)
    node._raise_tags_exceptions = True
    node._protected = node_data_metadata.get("protected", False)
    node._cleaned = node_data_metadata.get("cleaned", False)
    node._clean = node_data_desired.get("clean", False)
    return node


def cleanup_node_field_types(node_type: BaseResource, node_data_reported: Dict):
    valid_fields = set(field.name for field in fields(node_type))
    for field_name in list(node_data_reported.keys()):
        if field_name not in valid_fields:
            log.debug(
                f"Removing extra field {field_name} from new node of type {node_type}"
            )
            del node_data_reported[field_name]


def restore_node_field_types(node_type: BaseResource, node_data_reported: Dict):
    for field in fields(node_type):
        if field.name not in node_data_reported:
            continue
        field_type = optional_origin(field.type)

        if field_type == datetime:
            datetime_str = str(node_data_reported[field.name])
            if datetime_str.endswith("Z"):
                datetime_str = datetime_str[:-1] + "+00:00"
            node_data_reported[field.name] = datetime.fromisoformat(datetime_str)
        elif field_type == date:
            node_data_reported[field.name] = date.fromisoformat(
                node_data_reported[field.name]
            )
        elif field_type == timedelta:
            node_data_reported[field.name] = str2timedelta(
                node_data_reported[field.name]
            )
        elif field_type == timezone:
            node_data_reported[field.name] = str2timezone(
                node_data_reported[field.name]
            )
