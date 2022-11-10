import re
import sys
from collections import defaultdict
from datetime import datetime, date, timedelta, timezone
from enum import Enum
from functools import lru_cache, reduce
from pydoc import locate
from typing import List, MutableSet, Union, Tuple, Dict, Set, Any, TypeVar, Type, Optional, Literal
from typing import get_args, get_origin

import attrs
import cattrs
from attr import resolve_types
from attrs import Attribute

from resotolib.baseresources import BaseResource
from resotolib.durations import duration_str
from resotolib.types import Json
from resotolib.utils import type_str, str2timedelta, str2timezone, utc_str

if sys.version_info >= (3, 10):
    from types import UnionType, NoneType
else:
    UnionType = Union
    NoneType = type(None)


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


# either enum or optional enum
def is_enum(clazz: type) -> bool:
    origin = optional_origin(clazz)
    return isinstance(origin, type) and issubclass(origin, Enum)


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
def transitive_classes(classes: Set[type], walk_subclasses: bool = True) -> Set[type]:
    all_classes: MutableSet[type] = set()

    def check(to_check: type) -> None:
        clazz = optional_origin(to_check)
        if clazz in all_classes:
            pass
        elif is_dict(clazz):
            key_type, value_type = dict_types(to_check)
            check(key_type)
            check(value_type)
        elif is_collection(clazz):
            check(type_arg(to_check))
        elif attrs.has(clazz):
            all_classes.add(clazz)
            for mro_clazz in clazz.mro()[1:]:
                check(mro_clazz)
            if walk_subclasses:
                for subclass in clazz.__subclasses__():
                    check(subclass)
            for field in attrs.fields(clazz):
                check(field.type)
        elif is_enum(clazz):
            all_classes.add(clazz)

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
    timedelta: "duration",
}
simple_type = tuple(lookup.keys())


# Model name from the internal python class name
def model_name(clazz: Union[type, Tuple[Any]]) -> str:
    to_check = get_args(clazz)[0] if is_optional(clazz) else clazz
    if is_collection(to_check):
        return f"{model_name(type_arg(to_check))}[]"
    elif is_dict(to_check):
        key_type, value_type = dict_types(to_check)
        return f"dictionary[{model_name(key_type)}, {model_name(value_type)}]"
    elif is_enum(to_check):
        # camel case to snake case
        return re.sub(r"(?<!^)(?=[A-Z])", "_", to_check.__name__).lower()
    elif get_origin(to_check) == Union:
        # this is a union of different types other than none.
        # since union types are not supported, we fallback to any here
        return "any"
    elif isinstance(to_check, TypeVar):
        return model_name(get_args(to_check))
    elif isinstance(to_check, type) and issubclass(to_check, simple_type):
        return lookup[to_check]
    elif attrs.has(to_check):
        name = getattr(to_check, "kind", None)
        if not name:
            raise AttributeError(f"dataclass {to_check} need to define a ClassVar kind!")
        return name
    else:
        return "any"


# define if a field should be exported or not.
# Use python default: hide props starting with underscore.
def should_export(field: Attribute) -> bool:
    return not field.name.startswith("_")


def dataclasses_to_resotocore_model(
    classes: Set[type],
    allow_unknown_props: bool = False,
    aggregate_root: Optional[type] = None,
    walk_subclasses: bool = True,
) -> List[Json]:
    """
    Analyze all transitive dataclasses and create the model
    definition as understood by resotocore.
    A plain python dataclass defines the model structure and
    should be used to create json in the same format.

    :param classes: all dataclasses to analyze.
    :param allow_unknown_props: allow properties in json that are not defined in the model.
    :param aggregate_root: if a type is a subtype of this type, it will be considered an aggregate root.
    :param walk_subclasses: if true, all subclasses of the given classes will be analyzed as well.
    :return: the model definition in the resotocore json format.
    """

    def prop(field: Attribute) -> List[Json]:
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

        def json(name: str, kind_str: str, required: bool, description: str, **kwargs: Any) -> Json:
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
    all_classes = transitive_classes(classes, walk_subclasses)

    # type edge_type -> list of types
    successors: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    for clazz in all_classes:
        if name := getattr(clazz, "kind", None):
            # backwards compatibility: still look for successor kinds variable. deprecated.
            if succs := getattr(clazz, "successor_kinds", None):
                for edge_type, values in succs.items():
                    successors[name][edge_type].extend(values)
            if refs := getattr(clazz, "reference_kinds", None):
                if succs := refs.get("successors", None):
                    for edge_type, values in succs.items():
                        successors[name][edge_type].extend(values)
                if preds := refs.get("predecessors", None):
                    for edge_type, values in preds.items():
                        for value in values:
                            successors[value][edge_type].append(name)
    successors = {k: {ik: list(set(iv)) for ik, iv in v.items()} for k, v in successors.items()}

    def export_data_class(clazz: type) -> None:
        bases = [base for base in clazz.__bases__ if attrs.has(base)]
        base_names = [model_name(base) for base in bases]
        base_props: Set[Attribute] = reduce(lambda result, base: result | set(attrs.fields(base)), bases, set())
        props = [
            p for field in attrs.fields(clazz) if field not in base_props and should_export(field) for p in prop(field)
        ]
        root = any(sup == aggregate_root for sup in clazz.mro()) if aggregate_root else True
        kind = model_name(clazz)
        model.append(
            {
                "fqn": kind,
                "bases": base_names,
                "properties": props,
                "allow_unknown_props": allow_unknown_props,
                "successor_kinds": successors.get(kind, None),
                "aggregate_root": root,
            }
        )

    def export_enum(clazz: Type[Enum]) -> None:
        # Only allow string based enumerations.
        def literal_name(en: Enum) -> str:
            if isinstance(en.value, str):
                return en.value
            else:
                raise AttributeError(f"Enumeration {clazz} does not use string as values!")

        enum_values = [literal_name(literal) for literal in clazz]
        model.append({"fqn": model_name(clazz), "runtime_kind": "string", "enum": enum_values})

    for cls in all_classes:
        if attrs.has(cls):
            resolve_types(cls)  # make sure all string based types are resolved correctly
            export_data_class(cls)
        elif is_enum(cls):
            export_enum(cls)  # type: ignore
        else:
            raise AttributeError(f"Don't know how to handle: {cls}")
    return model


# Use this model exporter, if a dynamic object is exported
# with given name and properties.
def dynamic_object_to_resotocore_model(name: str, properties: Dict[str, type]) -> List[Json]:
    dependant = dataclasses_to_resotocore_model(set(properties.values()))
    # append definition for top level object
    dependant.append(
        {
            "fqn": name,
            "bases": [],
            "properties": [
                {"name": prop_name, "kind": model_name(prop_type), "required": False}
                for prop_name, prop_type in properties.items()
            ],
        }
    )
    return dependant


def format_value_for_export(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return utc_str(value)
    elif isinstance(value, (timedelta, timezone)):
        return duration_str(value)
    elif isinstance(value, Enum):
        return value.value
    return value


def get_node_attributes(node: BaseResource) -> Dict:
    def create_dict() -> Json:
        attributes: Dict = {"kind": node.kind}
        for field in attrs.fields(type(node)):
            if field.name.startswith("_"):
                continue
            value = getattr(node, field.name, None)
            if value is None:
                continue
            value = format_value_for_export(value)
            attributes.update({field.name: value})
        return attributes

    if hasattr(node, "to_json"):
        result = node.to_json()
        result["kind"] = node.kind
        return result
    elif attrs.has(node):
        return create_dict()
    else:
        raise ValueError(f"Node {node.rtdname} is neither a dataclass nor has a to_json method")


def node_to_dict(node: BaseResource, changes_only: bool = False, include_revision: bool = False) -> Json:
    node_dict = {"id": node._resotocore_id if node._resotocore_id else node.chksum}
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
    if include_revision and node._resotocore_revision:
        node_dict.update(
            {
                "revision": node._resotocore_revision,
            }
        )
    return node_dict


@lru_cache(maxsize=None)
def locate_python_type(python_type: str) -> Any:
    cls = locate(python_type)
    if attrs.has(cls):
        attrs.resolve_types(cls)
    return cls


converter = cattrs.Converter()


def convert_datetime(value: datetime) -> datetime:
    datetime_str = str(value)
    if datetime_str.endswith("Z"):
        datetime_str = datetime_str[:-1] + "+00:00"
    return datetime.fromisoformat(datetime_str)


def is_primitive_or_primitive_union(t: Any) -> bool:
    if t in (str, bytes, int, float, bool, NoneType):
        return True
    origin = get_origin(t)
    if origin is Literal:
        return True
    if (basetype := cattrs._compat.get_newtype_base(t)) is not None:
        return is_primitive_or_primitive_union(basetype)
    if origin in (UnionType, Union):
        return all(is_primitive_or_primitive_union(ty) for ty in get_args(t))
    return False


converter.register_structure_hook(datetime, lambda obj, typ: convert_datetime(obj))
converter.register_structure_hook(date, lambda obj, typ: date.fromisoformat(obj))
converter.register_structure_hook(timedelta, lambda obj, typ: str2timedelta(obj))
converter.register_structure_hook(timezone, lambda obj, typ: str2timezone(obj))
# work around until this is solved: https://github.com/python-attrs/cattrs/issues/278
converter.register_structure_hook_func(is_primitive_or_primitive_union, lambda v, ty: v)


def node_from_dict(node_data: Dict, include_select_ancestors: bool = False) -> BaseResource:
    """Create a resource from resotocore graph node data

    If include_select_ancestors is True, the resource will be created with
    ancestors cloud, account, region and zone passed directly to the constructor.
    This is useful for when the node is being created for standalone use instead
    of in the context of a graph. E.g. during tagging of an individual resource
    where the tagger needs to know which cloud and account a resource came from.
    """
    node_data_reported = node_data.get("reported", {})
    if node_data_reported is None:
        node_data_reported = {}
    node_data_desired = node_data.get("desired", {})
    if node_data_desired is None:
        node_data_desired = {}
    node_data_metadata = node_data.get("metadata", {})
    if node_data_metadata is None:
        node_data_metadata = {}
    node_data_ancestors = node_data.get("ancestors", {})
    if node_data_ancestors is None:
        node_data_ancestors = {}

    new_node_data = dict(node_data_reported)
    if "kind" in new_node_data:
        del new_node_data["kind"]

    python_type = node_data_metadata.get("python_type", "NoneExisting")
    node_type = locate_python_type(python_type)
    if node_type is None:
        raise ValueError(f"Do not know how to handle {node_data_reported}")

    cleanup_node_field_types(node_type, new_node_data)
    ancestors = {}
    if include_select_ancestors:
        for ancestor in ("cloud", "account", "region", "zone"):
            if node_data_ancestors.get(ancestor):
                ancestors[f"_{ancestor}"] = node_from_dict(
                    {
                        "reported": node_data_ancestors[ancestor].get("reported", {}),
                        "metadata": node_data_ancestors[ancestor].get("metadata", {}),
                    }
                )
    new_node_data.update(
        {
            "_resotocore_id": node_data.get("id"),
            "_resotocore_revision": node_data.get("revision"),
            "_resotocore_query_tag": node_data_metadata.get("query_tag"),
        }
    )

    node = converter.structure_attrs_fromdict(new_node_data, node_type)
    for field_name, value in ancestors.items():
        setattr(node, field_name, value)
    node._raise_tags_exceptions = True
    node._protected = node_data_metadata.get("protected", False)
    node._cleaned = node_data_metadata.get("cleaned", False)
    node._clean = node_data_desired.get("clean", False)
    return node


def cleanup_node_field_types(node_type: BaseResource, node_data_reported: Dict):
    valid_fields = set(field.name for field in attrs.fields(node_type))
    for field_name in list(node_data_reported.keys()):
        if field_name not in valid_fields:
            del node_data_reported[field_name]
