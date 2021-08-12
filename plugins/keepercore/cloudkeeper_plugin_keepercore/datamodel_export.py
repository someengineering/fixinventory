from dataclasses import is_dataclass, fields, Field
from datetime import datetime, date, timedelta
from functools import reduce
from typing import List, MutableSet, get_args, get_origin, Union, Tuple, Dict, Set, Any

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
def transitive_dataclasses(classes: List[type]) -> Set[type]:
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
    elif issubclass(to_check, simple_type):
        return lookup[to_check]
    elif is_dataclass(to_check):
        name = getattr(to_check, "resource_type", None)
        if not name:
            raise AttributeError(
                f"dataclass {to_check} need to define a ClassVar resource_type!"
            )
        return name
    else:
        return "any"


# define if a field should be exported or not. Use python default: hide props starting with underscore.
def should_export(field: Field) -> bool:
    return not field.name.startswith("_")


def export_dataclasses(classes: List[type]) -> List[Json]:
    """
    Analyze all transitive dataclasses and create the model definition as understood by keepercore.
    A plain python dataclass defines the model structure and should be used to create json in the same format.

    :param classes: all dataclasses to analyze.
    :return: the model definition in the keepercore json format.
    """

    def prop(field: Field) -> Json:
        # the field itself can define the type via a type hint
        # this is useful for int and float in python where the representation can not be
        # detected by the type itself. Example: int32/int64 or float/double
        # If not defined, we fallback to the largest container: int64 and double
        kind = field.metadata.get("type_hint", model_name(field.type))
        return {
            "name": field.name,
            "kind": kind,
            "required": not is_optional(field.type),
            "description": field.metadata.get("description", ""),
        }

    model: List[Json] = []
    for clazz in transitive_dataclasses(classes):
        bases = [base for base in clazz.__bases__ if is_dataclass(base)]
        base_names = [model_name(base) for base in bases]
        base_props: Set[Field] = reduce(
            lambda result, base: result | set(fields(base)), bases, set()
        )
        props = [
            prop(field)
            for field in fields(clazz)
            if field not in base_props and should_export(field)
        ]
        model.append(
            {"fqn": model_name(clazz), "bases": base_names, "properties": props}
        )
    return model
