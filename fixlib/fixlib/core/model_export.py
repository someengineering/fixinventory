import re
from collections import defaultdict
from datetime import datetime, date, timedelta
from enum import Enum
from functools import lru_cache, reduce
from pydoc import locate
from typing import List, MutableSet, Union, Tuple, Dict, Set, Any, TypeVar, Type, Optional
from typing import get_args, get_origin

import attrs
from attr import resolve_types
from attrs import Attribute

from fixlib.baseresources import BaseResource
from fixlib.json import from_json
from fixlib.types import Json
from fixlib.utils import type_str

property_metadata_to_strip = ["restart_required", "description", "required", "kind"]


# List[X] -> list, list -> list
def optional_origin(clazz: Type[Any]) -> Type[Any]:
    maybe_optional = get_args(clazz)[0] if is_optional(clazz) else clazz
    origin = get_origin(maybe_optional)
    return origin if origin else maybe_optional  # type: ignore


# Optional[x] -> true
def is_optional(clazz: Union[type, Tuple[Any]]) -> bool:
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
    return args[0] if args and len(args) == 1 else object  # type: ignore


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
            resolve_types(clazz)
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
def model_name(clazz: Union[type, Tuple[Any], None]) -> str:
    if clazz is None:
        return "any"
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
        return name  # type: ignore
    else:
        return "any"


# define if a field should be exported or not.
# Use python default: hide props starting with underscore.
def should_export(field: Attribute) -> bool:  # type: ignore
    return not field.name.startswith("_")


def dataclasses_to_fixcore_model(
    classes: Set[Type[Any]],
    *,
    allow_unknown_props: bool = False,
    aggregate_root: Optional[Type[Any]] = None,
    walk_subclasses: bool = True,
    use_optional_as_required: bool = False,
    with_description: bool = True,
) -> List[Json]:
    """
    Analyze all transitive dataclasses and create the model
    definition as understood by fixcore.
    A plain python dataclass defines the model structure and
    should be used to create json in the same format.

    :param classes: all dataclasses to analyze.
    :param allow_unknown_props: allow properties in json that are not defined in the model.
    :param aggregate_root: if a type is a subtype of this type, it will be considered an aggregate root.
    :param walk_subclasses: if true, all subclasses of the given classes will be analyzed as well.
    :param use_optional_as_required: if true, all non-optional fields will be considered required.
    :param with_description: if true, include the description for classes and properties.
    :return: the model definition in the fixcore json format.
    """

    def prop(field: Attribute) -> List[Json]:  # type: ignore
        # the field itself can define the type via a type hint
        # this is useful for int and float in python where the representation can not be
        # detected by the type itself. Example: int32/int64 or float/double
        # If not defined, we fall back to the largest container: int64 and double
        name = field.name
        meta = field.metadata.copy()
        kind = meta.pop("type_hint", model_name(field.type))
        desc = meta.pop("description", None)
        desc = desc if with_description else None
        required = meta.pop("required", use_optional_as_required and not is_optional(field.type))  # type: ignore
        synthetic = meta.pop("synthetic", None)
        synthetic = synthetic if synthetic else {}
        for ps in property_metadata_to_strip:
            meta.pop(ps, None)

        def json(
            name: str,
            kind_str: str,
            required: bool,
            description: Optional[str],
            meta: Optional[Dict[str, str]],
            **kwargs: Any,
        ) -> Json:
            js = {"name": name, "kind": kind_str, "required": required, "description": description, **kwargs}
            if meta:
                js["metadata"] = meta
            return js

        synthetics = [
            json(
                synth_prop,
                synth_trafo,
                False,
                None,
                None,
                synthetic={"path": [name]},
            )
            for synth_prop, synth_trafo in synthetic.items()
        ]

        return [json(name, kind, required, desc, meta)] + synthetics

    for cls in classes:
        if attrs.has(cls):
            resolve_types(cls)
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
        base_props: Set[Attribute] = reduce(lambda result, base: result | set(attrs.fields(base)), bases, set())  # type: ignore # noqa: E501
        props = [
            p for field in attrs.fields(clazz) if field not in base_props and should_export(field) for p in prop(field)
        ]
        root = any(sup == aggregate_root for sup in clazz.mro()) if aggregate_root else True
        kind = model_name(clazz)
        metadata: Json = {}
        if (m := getattr(clazz, "metadata", None)) and isinstance(m, dict):
            metadata = m.copy()
        if (s := clazz.__dict__.get("kind_display", None)) and isinstance(s, str):
            metadata["name"] = s
        if with_description and (s := clazz.__dict__.get("kind_description", None)) and isinstance(s, str):
            metadata["description"] = s

        model.append(
            {
                "fqn": kind,
                "bases": base_names,
                "properties": props,
                "allow_unknown_props": allow_unknown_props,
                "successor_kinds": successors.get(kind, None),
                "aggregate_root": root,
                "metadata": metadata or None,
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
            resolve_types(cls)
            export_data_class(cls)
        elif is_enum(cls):
            export_enum(cls)
        else:
            raise AttributeError(f"Don't know how to handle: {cls}")
    return model


# Use this model exporter, if a dynamic object is exported
# with given name and properties.
def dynamic_object_to_fixcore_model(
    name: str, properties: Dict[str, type], aggregate_root: bool = True, traverse_dependant: bool = True
) -> List[Json]:
    dependant = dataclasses_to_fixcore_model(set(properties.values())) if traverse_dependant else []
    # append definition for top level object
    dependant.append(
        {
            "fqn": name,
            "bases": [],
            "aggregate_root": aggregate_root,
            "properties": [
                {"name": prop_name, "kind": model_name(prop_type), "required": False}
                for prop_name, prop_type in properties.items()
            ],
            "metadata": {"dynamic": True},
        }
    )
    return dependant


def get_node_attributes(node: BaseResource) -> Json:
    if not hasattr(node, "to_json"):
        raise ValueError(f"Node {node} has no to_json() method!")
    result = node.to_json()
    result["kind"] = node.kind
    return result


def node_to_dict(node: BaseResource, changes_only: bool = False, include_revision: bool = False) -> Json:
    node_dict: Json = {"id": node._fixcore_id if node._fixcore_id else node.chksum}
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
                    **node._metadata,
                },
                "usage": node._resource_usage,
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
    if include_revision and node._fixcore_revision:
        node_dict.update(
            {
                "revision": node._fixcore_revision,
            }
        )
    return node_dict


@lru_cache(maxsize=None)
def locate_python_type(python_type: str) -> Any:
    cls: Type[Any] = locate(python_type)  # type: ignore
    if attrs.has(cls):
        attrs.resolve_types(cls)
    return cls


def node_from_dict(node_data: Json, include_select_ancestors: bool = False) -> BaseResource:
    """Create a resource from fixcore graph node data

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
            "_fixcore_id": node_data.get("id"),
            "_fixcore_revision": node_data.get("revision"),
            "_fixcore_query_tag": node_data_metadata.get("query_tag"),
        }
    )

    node: BaseResource = from_json(new_node_data, node_type)
    for field_name, value in ancestors.items():
        setattr(node, field_name, value)
    node._raise_tags_exceptions = True
    node._protected = node_data_metadata.get("protected", False)
    node._cleaned = node_data_metadata.get("cleaned", False)
    node._clean = node_data_desired.get("clean", False)
    return node


def cleanup_node_field_types(node_type: BaseResource, node_data_reported: Json) -> None:
    valid_fields = set(field.name for field in attrs.fields(node_type))  # type: ignore
    for field_name in list(node_data_reported.keys()):
        if field_name not in valid_fields:
            del node_data_reported[field_name]
