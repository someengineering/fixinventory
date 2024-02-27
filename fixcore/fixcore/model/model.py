from __future__ import annotations

import copy
import json
import re
import sys
import textwrap
from abc import ABC, abstractmethod
from datetime import datetime, timezone, date
from functools import lru_cache
from json import JSONDecodeError
from typing import (
    Union,
    Any,
    Optional,
    Callable,
    Type,
    Sequence,
    Dict,
    List,
    Set,
    cast,
    Tuple,
    Iterable,
    TypeVar,
    Iterator,
)

import yaml
from attrs import define, frozen
from dateutil.parser import parse
from jsons import set_deserializer, set_serializer
from networkx import MultiDiGraph
from parsy import regex, string, Parser

from fixcore.compat import remove_suffix
from fixcore.model.transform_kind_convert import converters
from fixcore.model.typed_model import from_js, to_js
from fixcore.types import Json, JsonElement, ValidationResult, ValidationFn, EdgeType
from fixcore.util import if_set, utc, duration, first
from fixlib.core.model_check import check_overlap_for
from fixlib.durations import duration_parser, DurationRe
from fixlib.parse_util import make_parser, variable_dp_backtick, dot_dp, l_bracket_p, r_bracket_p
from fixlib.utils import is_env_var_string

T = TypeVar("T")
AvailableEdgeTypes: List[EdgeType] = ["default", "delete"]


def check_type_fn(t: type, type_name: str) -> ValidationFn:
    def check_type(x: Any) -> ValidationResult:
        if isinstance(x, t):
            return None
        else:
            raise AttributeError(f"Expected type {type_name} but got {type(x).__name__}")

    return check_type


def check_fn(x: Optional[Any], func: Callable[[Any, Any], Optional[Any]], message: str) -> Optional[ValidationFn]:
    def check_single(value: Any) -> ValidationResult:
        if func(x, value):
            return None
        else:
            raise AttributeError(f">{value}< {message}")

    return None if x is None else check_single


def validate_fn(*fns: Optional[ValidationFn]) -> ValidationFn:
    defined = list(filter(lambda x: x is not None, fns))

    def always_valid(_: Any) -> ValidationResult:
        return None

    def check_defined(value: Any) -> ValidationResult:
        for fn in defined:
            res = fn(value)  # type: ignore
            if res is not None:
                return res
        return None

    return check_defined if defined else always_valid


@define(order=True, hash=True, frozen=True)
class SyntheticProperty:
    path: List[str]
    """
    A synthetic property does not exist in the underlying data model.
    It is defined by a function on an existing other property.
    Example: age is a duration defined on ctime which is a datetime.
             the function is age=now-ctime.
    """


@define(order=True, hash=True, eq=True)
class Property:
    name: str
    kind: str
    required: bool = False
    synthetic: Optional[SyntheticProperty] = None
    description: Optional[str] = None
    metadata: Optional[Json] = None

    def __attrs_post_init__(self) -> None:
        assert self.synthetic is None or not self.required, "Synthetic properties can not be required!"

    def resolve(self, model: Dict[str, Kind]) -> Kind:
        return Property.parse_kind(self.kind, model)

    def meta(self, name: str, clazz: Type[T]) -> Optional[T]:
        meta = self.metadata
        # noinspection PyUnboundLocalVariable
        return v if meta is not None and (v := meta.get(name)) is not None and isinstance(v, clazz) else None

    def meta_get(self, name: str, clazz: Type[T], default: T) -> T:
        return self.meta(name, clazz) or default

    @staticmethod
    def parse_kind(name: str, model: Dict[str, Kind]) -> Kind:
        def kind_by_name(kind_name: str) -> Kind:
            if kind_name not in model:
                raise AttributeError(f"Property kind is not known: {kind_name}. Have you registered it?")
            return model[kind_name]

        simple_kind_parser = regex("[A-Za-z][A-Za-z0-9_.]*").map(kind_by_name)
        bracket_parser = string("[]")
        dict_string_parser = string("dictionary[")
        comma_parser = regex("\\s*,\\s*")
        bracket_r = string("]")

        @make_parser
        def array_parser() -> Parser:
            inner = yield dictionary_parser | simple_kind_parser
            brackets = yield bracket_parser.times(1, cast(int, float("inf")))
            return ArrayKind.mk_array(inner, len(brackets))

        @make_parser
        def dictionary_parser() -> Parser:
            yield dict_string_parser
            key_kind = cast(Kind, (yield simple_kind_parser))
            yield comma_parser
            value_kind = yield array_parser | dictionary_parser | simple_kind_parser
            yield bracket_r
            return DictionaryKind(key_kind, value_kind)

        return (array_parser | dictionary_parser | simple_kind_parser).parse(name)  # type: ignore

    @staticmethod
    def any_prop() -> Property:
        return Property("any", "any")


# Split a variable path into its path parts.
# foo.bla -> [foo, bla]
# foo.`bla.bar` -> [foo, bla.bar]
prop_path_parser = (regex("[^`.]+") | (variable_dp_backtick + (l_bracket_p + r_bracket_p).optional(""))).sep_by(dot_dp)
array_index_re = re.compile(r"\[(\d+|\*)]")


class PropertyPath:
    @staticmethod
    def from_list(path: List[str]) -> PropertyPath:
        # remove index accesses from the path (e.g. [23] -> "[]", [*] -> "[]")
        no_index = ".".join(array_index_re.sub("[]", a) for a in path)
        return PropertyPath(path, no_index)

    @staticmethod
    def from_string(path: str) -> PropertyPath:
        # remove index accesses from the path (e.g. [23] -> "[]", [*] -> "[]")
        no_index = array_index_re.sub("[]", path)
        return PropertyPath(prop_path_parser.parse(no_index), no_index)

    def __init__(self, path: Sequence[Optional[str]], str_rep: Optional[str] = None):
        self.path = path
        self.path_str = str_rep if str_rep else ".".join(a if a else "" for a in self.path)

    @property
    def root(self) -> bool:
        return not bool(self.path)

    def child(self, part: Optional[str]) -> PropertyPath:
        update = list(self.path)
        update.append(part)
        return PropertyPath(update)

    def unescaped_parts(self) -> List[str]:
        return [p.rstrip("[]").strip("`") for p in self.path if p is not None]

    @property
    def last_part(self) -> Optional[str]:
        return self.path[-1] if self.path else None

    def same_as(self, other: PropertyPath) -> bool:
        """
        Checks if the given path is the same this path.
        Note: the path may include "holes" marked as None.
              The holes mean positions that have to be ignored.
              [A,B,C] same_as [A,None,C] same_as [A,None,None] same_as [None,None,None]
        """
        if len(other.path) == len(self.path):
            for left, right in zip(self.path, other.path):
                if left is not None and right is not None and left != right:
                    return False
            return True
        else:
            return False

    def value_in(self, js: JsonElement) -> JsonElement:
        at = len(self.path)

        def at_idx(current: JsonElement, idx: int) -> Optional[Any]:
            if at == idx:
                return current
            path = self.path[idx]
            is_array = False
            if path and path.endswith("[]"):
                path = path[:-2]
                is_array = True
            if current is None or not isinstance(current, dict) or path not in current:
                return None
            if is_array:
                elem = current[path]
                if isinstance(elem, list):
                    return [at_idx(a, idx + 1) for a in elem]
                else:
                    return None
            else:
                return at_idx(current[path], idx + 1)

        return at_idx(js, 0)

    def __repr__(self) -> str:
        return self.path_str

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, PropertyPath) and other.path_str == self.path_str

    def __hash__(self) -> int:
        return hash(self.path_str)


EmptyPath = PropertyPath([], "")


@define(order=True, hash=True, frozen=True)
class ResolvedPropertyPath:
    # The path of the resolved property in a complex kind
    path: PropertyPath
    # The metadata of the property (name etc.)
    prop: Property
    # the resolved kind of this property
    kind: Kind

    @property
    def simple_kind(self) -> SimpleKind:
        return self.kind if isinstance(self.kind, SimpleKind) else AnyKind()


class Kind(ABC):
    def __init__(self, fqn: str):
        self.fqn = fqn

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Kind) else False

    def __hash__(self) -> int:
        return hash(self.fqn)

    def coerce(self, value: JsonElement, **kwargs: bool) -> JsonElement:
        coerced = self.coerce_if_required(value, **kwargs)
        return coerced or value

    @abstractmethod
    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[JsonElement]:
        """
        Coerces the given value to this kind.
        - if obj is already correct: return None
        - if obj can not be coerced: return None
        - if obj can be coerced: return the value
        """

    @abstractmethod
    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        """
        Validate given object against definition:
        - if obj is valid: return None
        - if obj is not valid and can be coerced: return the coerced value.
        - if obj is not valid and can not be coerced: raise an exception
        """

    @staticmethod
    def to_json(obj: Kind, **kwargs: Any) -> Json:
        return obj.as_json(**kwargs)

    @abstractmethod
    def as_json(self, **kwargs: bool) -> Json:
        pass

    def resolve(self, model: Dict[str, Kind]) -> None:
        pass

    def kind_hierarchy(self) -> Set[str]:
        return {self.fqn}

    def package(self) -> Optional[str]:
        return self.fqn.rsplit(".", 1)[0] if "." in self.fqn else None

    def meta_get(self, name: str, clazz: Type[T], default: T) -> T:
        return default

    # noinspection PyUnusedLocal
    @staticmethod
    def from_json(js: Json, _: type = object, **kwargs: object) -> Kind:
        if "inner" in js:
            inner = Kind.from_json(js["inner"])
            return ArrayKind(inner)
        elif "fqn" in js and "runtime_kind" in js and js["runtime_kind"] in simple_kind_to_type:
            fqn = js["fqn"]
            rk = js["runtime_kind"]
            if "source_fqn" in js and "converter" in js and "reverse_order" in js:
                return TransformKind(fqn, rk, js["source_fqn"], js["converter"], js["reverse_order"])
            elif rk == "string":
                minimum = js.get("min_length")
                maximum = js.get("max_length")
                p = js.get("pattern")
                e = js.get("enum")
                return StringKind(fqn, minimum, maximum, p, e)
            elif rk in ("int32", "int64", "float", "double"):
                minimum = js.get("minimum")
                maximum = js.get("maximum")
                e = js.get("enum")
                return NumberKind(fqn, rk, minimum, maximum, e)
            elif rk == "datetime":
                return DateTimeKind(fqn)
            elif rk == "date":
                return DateKind(fqn)
            elif rk == "duration":
                return DurationKind(fqn)
            elif rk == "boolean":
                return BooleanKind(fqn)
            else:
                raise TypeError(f"Unhandled runtime kind: {rk}")
        elif js.get("fqn") == "any" and js.get("runtime_kind") == "any":
            return AnyKind()
        elif "fqn" in js and ("properties" in js or "bases" in js):
            props = list(map(lambda p: from_js(p, Property), js.get("properties", [])))
            bases: List[str] = js.get("bases", [])
            allow_unknown_props = js.get("allow_unknown_props", False)
            successor_kinds = js.get("successor_kinds")
            aggregate_root = js.get("aggregate_root", True)
            metadata = js.get("metadata")
            return ComplexKind(
                fqn=js["fqn"],
                bases=bases,
                properties=props,
                allow_unknown_props=allow_unknown_props,
                successor_kinds=successor_kinds,
                aggregate_root=aggregate_root,
                metadata=metadata,
            )
        else:
            raise JSONDecodeError("Given type can not be read.", json.dumps(js), 0)

    def sort_json(self, js: Json) -> Json:
        """
        Sort the given json element according to the kind definition.
        A model which define properties in a specific order, the json object also uses the same order.
        This will walk the complete json structure.
        """
        if isinstance(js, dict) and isinstance(self, ComplexKind):
            prop_order = {rp.name: idx for idx, rp in enumerate(self.all_props())}
            sub = {
                k: self.property_kind_of(k, AnyKind()).sort_json(v) if isinstance(v, dict) else v for k, v in js.items()
            }
            # a property which is unknown is moved to the end with no specific order
            return dict(sorted(sub.items(), key=lambda k: prop_order.get(k[0], sys.maxsize)))
        elif isinstance(js, dict):
            # noinspection PyTypeChecker
            return dict(sorted(js.items()))
        else:
            return js

    def nested_complex_kinds(self) -> List[ComplexKind]:
        if isinstance(self, ComplexKind):
            return [self]
        elif isinstance(self, ArrayKind):
            return self.inner.nested_complex_kinds()
        elif isinstance(self, DictionaryKind):
            return self.key_kind.nested_complex_kinds() + self.value_kind.nested_complex_kinds()
        else:
            return []


def should_skip_env_var_str(obj: Any, kwargs: Dict[str, bool]) -> bool:
    return kwargs.get("config_context", False) and is_env_var_string(obj)


simple_kind_to_type: Dict[str, Type[Union[str, int, float, bool]]] = {
    "string": str,
    "int32": int,
    "int64": int,
    "float": float,
    "double": float,
    "boolean": bool,
    "date": str,
    "datetime": str,
    "duration": str,
}


class SimpleKind(Kind, ABC):
    def __init__(self, fqn: str, runtime_kind: str, reverse_order: bool = False):
        super().__init__(fqn)
        self.runtime_kind = runtime_kind
        self.reverse_order = reverse_order

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[JsonElement]:
        """
        Take a user defined value and transform it into a machine queryable value.
        Example:
            - "10s" as string -> "10s"
            - "10s" as boolean -> false
            - "10s" as duration -> "10s"
            - "10s" as date -> now + 10 seconds (depending on local time)
        :param value: the value from the user
        :return: the coerced value from the system
        """
        return None

    def as_json(self, **kwargs: bool) -> Json:
        return {"fqn": self.fqn, "runtime_kind": self.runtime_kind}


class AnyKind(SimpleKind):
    def __init__(self) -> None:
        super().__init__("any", "any")

    def __new__(cls) -> AnyKind:
        if cls.__singleton is None:
            cls.__singleton = super(AnyKind, cls).__new__(cls)
        return cls.__singleton

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        return None

    __singleton: Optional[AnyKind] = None


class StringKind(SimpleKind):
    def __init__(
        self,
        fqn: str,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        enum: Optional[Set[str]] = None,
    ):
        super().__init__(fqn, "string")
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.pattern_compiled = if_set(pattern, re.compile)
        self.enum = enum
        self.valid_fn = validate_fn(
            check_type_fn(str, "string"),
            check_fn(
                self.pattern_compiled,
                lambda p, obj: p.fullmatch(obj) is not None,
                f"does not conform to regex: {self.pattern}",
            ),
            check_fn(self.enum, lambda x, obj: obj in x, f"should be one of: {self.enum}"),
            check_fn(self.min_length, lambda x, obj: len(obj) >= x, f"does not have minimal length: {self.min_length}"),
            check_fn(self.max_length, lambda x, obj: len(obj) <= x, f"is too long! Allowed: {self.max_length}"),
        )

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if obj is None:
            return None
        elif should_skip_env_var_str(obj, kwargs):
            return None
        elif isinstance(obj, str):
            return self.valid_fn(obj)
        coerced = self.coerce_if_required(obj, **kwargs)
        if coerced is not None:
            self.valid_fn(coerced)
            return coerced
        else:
            raise AttributeError(f"Expected type {self.runtime_kind} but got {type(obj).__name__}")

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[str]:
        if value is None:
            return value
        if isinstance(value, str):
            return None
        else:
            return json.dumps(value)

    def as_json(self, **kwargs: bool) -> Json:
        js = super().as_json(**kwargs)
        if self.pattern:
            js["pattern"] = self.pattern
        if self.enum:
            js["enum"] = self.enum
        if self.min_length:
            js["min_length"] = self.min_length
        if self.max_length:
            js["max_length"] = self.max_length
        return js


class NumberKind(SimpleKind):
    def __init__(
        self,
        fqn: str,
        runtime_kind: str,
        minimum: Union[None, float, int] = None,
        maximum: Union[None, float, int] = None,
        enum: Optional[Set[Union[float, int]]] = None,
    ):
        super().__init__(fqn, runtime_kind)
        self.minimum = minimum
        self.maximum = maximum
        self.enum = enum
        self.valid_fn = validate_fn(
            check_type_fn(int, "int") if runtime_kind == "int" else self.check_float,
            check_fn(self.enum, lambda x, obj: obj in x, f"should be one of: {self.enum}"),
            check_fn(self.minimum, lambda x, obj: obj >= x, f"should be greater or equals than: {self.minimum}"),
            check_fn(self.maximum, lambda x, obj: obj <= x, f"should be smaller or equals than: {self.maximum}"),
        )

    @staticmethod
    def check_float(obj: Any) -> ValidationResult:
        if isinstance(obj, (int, float)):
            return None
        else:
            raise AttributeError(f"Expected number but got {obj}")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if obj is None:
            return None
        elif should_skip_env_var_str(obj, kwargs):
            return None
        elif isinstance(obj, (int, float)):
            return self.valid_fn(obj)
        coerced = self.coerce_if_required(obj, **kwargs)
        if coerced is not None:
            self.valid_fn(coerced)
            return coerced
        else:
            raise AttributeError(f"Expected type {self.runtime_kind} but got {type(obj).__name__}")

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[Union[int, float]]:
        if value is None:
            return value
        elif isinstance(value, (int, float)):
            return None
        else:
            try:
                return int(value) if self.runtime_kind in ("int32", "int64") else float(value)  # type: ignore
            except ValueError:
                return None

    def as_json(self, **kwargs: bool) -> Json:
        js = super().as_json(**kwargs)
        if self.enum:
            js["enum"] = self.enum
        if self.minimum:
            js["minimum"] = self.minimum
        if self.maximum:
            js["maximum"] = self.maximum
        return js


class BooleanKind(SimpleKind):
    def __init__(self, fqn: str):
        super().__init__(fqn, "boolean")
        self.valid_fn = check_type_fn(bool, "boolean")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if obj is True or obj is False or obj is None:
            return None
        elif should_skip_env_var_str(obj, kwargs):
            return None
        coerced = self.coerce_if_required(obj, **kwargs)
        if coerced is not None:
            return coerced
        else:
            raise AttributeError(f"Expected type boolean but got {type(obj).__name__}")

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[bool]:
        if value is None:
            return value
        elif isinstance(value, bool):
            return None
        elif isinstance(value, str) and value.lower() in ("true", "yes", "on"):
            return True
        elif isinstance(value, str) and value.lower() in ("false", "no", "off"):
            return False
        else:
            return None


class DurationKind(SimpleKind):
    def __init__(self, fqn: str):
        super().__init__(fqn, "duration")
        self.valid_fn = validate_fn(check_type_fn(str, "duration"), self.check_duration)

    def check_duration(self, v: Any) -> None:
        if not DurationRe.fullmatch(v):
            raise AttributeError(f"Wrong format for duration: {v}. Examples: 1yr, 3mo, 3d4h3min1s, 3days and 2hours")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if should_skip_env_var_str(obj, kwargs):
            return None
        return self.valid_fn(obj)

    def coerce_if_required(self, value: Any, **kwargs: bool) -> Optional[str]:
        try:
            return f"{int(duration_parser.parse(value))}s" if kwargs.get("normalize", True) else None
        except Exception:
            return None


class DateTimeKind(SimpleKind):
    Format = "%Y-%m-%dT%H:%M:%SZ"
    DateTimeRe = re.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z")

    def __init__(self, fqn: str):
        super().__init__(fqn, "datetime")
        self.valid_fn = validate_fn(check_type_fn(str, "datetime"), self.check_datetime)

    @staticmethod
    def parse_datetime(date_string: str) -> Optional[datetime]:
        try:
            return datetime.strptime(date_string, DateTimeKind.Format)
        except ValueError:
            return None

    @staticmethod
    def check_datetime(obj: Any) -> ValidationResult:
        def parse_datetime() -> str:
            parsed = datetime.fromisoformat(str(obj))
            utc_parsed = datetime.fromtimestamp(parsed.timestamp(), tz=timezone.utc)
            return utc_parsed.strftime(DateTimeKind.Format)

        return None if DateTimeKind.DateTimeRe.fullmatch(obj) else parse_datetime()

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if should_skip_env_var_str(obj, kwargs):
            return None
        return self.valid_fn(obj)

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[str]:
        try:
            if value is None:
                return value
            elif not isinstance(value, str):
                return None
            elif self.DateTimeRe.fullmatch(value):
                return None
            elif DurationRe.fullmatch(value):
                return self.from_duration(value)
            else:
                return self.from_datetime(value)
        except Exception:
            return None

    @staticmethod
    def from_datetime(value: str) -> str:
        try:
            dt = datetime.fromisoformat(value)
        except Exception:
            dt = parse(value)
        if (
            not dt.tzinfo
            or dt.tzinfo.utcoffset(None) is None
            or dt.tzinfo.utcoffset(None).total_seconds() != 0  # type: ignore
        ):
            dt = dt.astimezone(timezone.utc)
        return dt.strftime(DateTimeKind.Format)

    @staticmethod
    def from_duration(value: str, now: datetime = utc()) -> str:
        # in case of duration, compute the timestamp as: now + duration
        delta = duration(value)
        instant = now + delta
        return instant.strftime(DateTimeKind.Format)


class DateKind(SimpleKind):
    Format = "%Y-%m-%d"
    DateRe = re.compile("\\d{4}-\\d{2}-\\d{2}")

    def __init__(self, fqn: str):
        super().__init__(fqn, "date")
        self.valid_fn = validate_fn(check_type_fn(str, "date"), self.check_date)

    @staticmethod
    def check_date(obj: Any) -> ValidationResult:
        return None if DateKind.DateRe.fullmatch(obj) else date.fromisoformat(obj)

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if should_skip_env_var_str(obj, kwargs):
            return None
        return self.valid_fn(obj)

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[str]:
        try:
            if value is None:
                return value
            elif not isinstance(value, str):
                return None
            elif DurationRe.fullmatch(value):
                # in case of duration, compute the timestamp as: today + duration
                delta = duration(value)
                at = date.today() + delta
                return at.isoformat()
            else:
                return parse(value).date().strftime(DateKind.Format)
        except Exception:
            return None


class TransformKind(SimpleKind):
    """
    Transform kinds can be used to derive attributes in a complex kind from other attributes.
    It is important, that the transformed attribute does not exist in the original complex kind!
    It is a SimpleKind, since it can be queried directly as if it would be available as part of the json.

    A transformed kind takes a source value of kind source_kind and transforms it using a function
    into the destination kind.

    :param fqn: the fully qualified name of this kind.
    :param source_fqn: the underlying runtime kind.
    :param destination_fqn: the destination kind that is used in the data store.
    :param converter: name of converter. See transform_kind_convert.py for a dict of possible converter names.
    """

    def __init__(self, fqn: str, source_fqn: str, destination_fqn: str, converter: str, reverse_order: bool):
        # note: source_fqn and runtime_kind are considered the same.
        # the synthetic property does not introduce a new type, but translates types.
        super().__init__(fqn, source_fqn, reverse_order)
        self.destination_fqn: str = destination_fqn
        self.source_kind: Optional[SimpleKind] = None
        self.destination_kind: Optional[SimpleKind] = None
        self.converter = converter
        self.source_to_destination, self.destination_to_source = converters[converter]

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[JsonElement]:
        if value is None:
            return None
        elif self.source_kind:
            coerced_source = self.source_kind.coerce(value)
            real = self.source_to_destination(coerced_source)  # type: ignore
            return real
        else:
            return None

    def transform(self, value: Any) -> Any:
        if value is None:
            return None
        elif self.destination_kind:
            real_coerced = self.destination_kind.coerce(value)
            synth = self.destination_to_source(real_coerced)  # type: ignore
            return synth
        else:
            raise AttributeError(f"Synthetic kind is not resolved: {self.fqn}")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        # this function is called during import for supplied values.
        # synthetic values are never supplied
        raise AttributeError(f"TransformKind {self.fqn} is not allowed to be supplied.")

    def resolve(self, model: Dict[str, Kind]) -> None:
        source = model.get(self.runtime_kind)
        destination = model.get(self.destination_fqn)
        if source and destination and isinstance(source, SimpleKind) and isinstance(destination, SimpleKind):
            source.resolve(model)
            destination.resolve(model)
            self.source_kind = source
            self.destination_kind = destination
        else:
            raise AttributeError(f"Underlying kind not known: {self.destination_fqn}")

    def as_json(self, **kwargs: bool) -> Json:
        return {
            "fqn": self.fqn,
            "runtime_kind": self.runtime_kind,
            "source_fqn": self.destination_fqn,
            "converter": self.converter,
            "reverse_order": self.reverse_order,
        }


class ArrayKind(Kind):
    def __init__(self, inner: Kind):
        super().__init__(f"{inner.fqn}[]")
        self.inner = inner

    def as_json(self, **kwargs: bool) -> Json:
        return {"fqn": self.fqn, "inner": self.inner.as_json(**kwargs)}

    def resolve(self, model: Dict[str, Kind]) -> None:
        self.inner.resolve(model)

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            # list is expected, but object found
            raise AttributeError("Expected property is a json object not an array!")

        coerced = self.coerce_if_required(obj, **kwargs)
        for elem in coerced or obj:  # type: ignore
            self.inner.check_valid(elem, **kwargs)
        return coerced

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[JsonElement]:
        has_coerced = False
        mapped: Optional[JsonElement] = None  # noqa

        def check(item: Any) -> ValidationResult:
            nonlocal has_coerced
            res = self.inner.coerce_if_required(item, **kwargs)
            if res is None:
                return item
            else:
                has_coerced = True
                return res

        if value is None:
            return None
        elif isinstance(value, dict):
            return None
        elif not isinstance(value, list):
            value = check(value)
            if kwargs.get("array_creation", True):
                mapped = [value]
                has_coerced = True
            else:  # in case only the inner kind should be coerced (see arango_query)
                mapped = value
        else:
            mapped = [check(elem) for elem in value]
        return mapped if has_coerced else None

    @staticmethod
    def mk_array(kind: Kind, depth: int) -> Kind:
        return kind if depth == 0 else ArrayKind(ArrayKind.mk_array(kind, depth - 1))


class DictionaryKind(Kind):
    def __init__(self, key_kind: Kind, value_kind: Kind):
        super().__init__(f"dictionary[{key_kind.fqn}, {value_kind.fqn}]")
        self.key_kind = key_kind
        self.value_kind = value_kind

    def as_json(self, **kwargs: bool) -> Json:
        return {
            "fqn": self.fqn,
            "key_kind": self.key_kind.as_json(**kwargs),
            "value_kind": self.value_kind.as_json(**kwargs),
        }

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            coerced = self.coerce_if_required(obj, **kwargs)
            for prop, value in (coerced or obj).items():
                part = "key"
                try:
                    self.key_kind.check_valid(prop, **kwargs)
                    part = "value"
                    self.value_kind.check_valid(value, **kwargs)
                except Exception as at:
                    raise AttributeError(f"{part} of {self.fqn} is not valid: {at}") from at
            return coerced
        else:
            raise AttributeError(f"dictionary requires a json object, but got this: {obj}")

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[Json]:
        if isinstance(value, dict):
            coerced: Json = {}
            has_coerced = False
            for p, v in value.items():
                ck = self.key_kind.coerce_if_required(p, **kwargs)
                cv = self.value_kind.coerce_if_required(v, **kwargs)
                coerced[ck or p] = cv or v  # type: ignore
                if ck is not None or cv is not None:
                    has_coerced = True
            return coerced if has_coerced else None
        else:
            return None

    def resolve(self, model: Dict[str, Kind]) -> None:
        self.key_kind.resolve(model)
        self.value_kind.resolve(model)


class ComplexKind(Kind):
    def __init__(
        self,
        fqn: str,
        bases: List[str],
        properties: List[Property],
        allow_unknown_props: bool = False,
        # EdgeType -> possible list of successor kinds
        successor_kinds: Optional[Dict[EdgeType, List[str]]] = None,
        aggregate_root: bool = True,
        metadata: Optional[Json] = None,
    ):
        super().__init__(fqn)
        self.bases = bases
        self.properties = properties
        self.allow_unknown_props = allow_unknown_props
        self.successor_kinds = successor_kinds or {}
        self.aggregate_root = aggregate_root
        self.metadata = metadata or {}
        self._predecessor_kinds: Dict[EdgeType, List[str]] = {}
        self.__prop_by_name = {prop.name: prop for prop in properties}
        self.__resolved = False
        self.__resolved_props: Dict[str, Tuple[Property, Kind]] = {}
        self.__resolved_direct_props: Dict[str, Tuple[Property, Kind]] = {}
        self.__resolved_bases: Dict[str, ComplexKind] = {}
        self.__all_props: List[Property] = list(self.properties)
        self.__resolved_hierarchy: Set[str] = {fqn}
        self.__property_by_path: List[ResolvedPropertyPath] = []
        self.__synthetic_props: List[ResolvedPropertyPath] = []

    def as_json(self, **kwargs: bool) -> Json:
        result: Json = {"fqn": self.fqn, "aggregate_root": self.aggregate_root}
        if kwargs.get("with_metadata", True):
            result["metadata"] = self.metadata
        if kwargs.get("with_properties", True):
            result["allow_unknown_props"] = self.allow_unknown_props
            result["properties"] = [to_js(prop) for prop in self.properties]
        if kwargs.get("with_relatives", True):
            result["bases"] = self.bases
            result["successor_kinds"] = self.successor_kinds
        return result

    def copy(
        self,
        *,
        bases: Optional[List[str]] = None,
        properties: Optional[List[Property]] = None,
        successor_kinds: Optional[Dict[EdgeType, List[str]]] = None,
        predecessor_kinds: Optional[Dict[EdgeType, List[str]]] = None,
        metadata: Optional[Json] = None,
    ) -> ComplexKind:
        result = copy.copy(self)
        result.bases = bases or self.bases
        result.properties = properties or self.properties
        result.successor_kinds = successor_kinds or self.successor_kinds
        result._predecessor_kinds = predecessor_kinds or self._predecessor_kinds
        result.metadata = metadata or self.metadata
        return result

    def resolve(self, model: Dict[str, Kind]) -> None:
        if not self.__resolved:
            self.__resolved = True
            kinds = []
            # resolve properties
            for prop in sorted(self.properties, key=lambda p: p.name):
                kind = prop.resolve(model)
                self.__resolved_direct_props[prop.name] = (prop, kind)
                self.__resolved_props[prop.name] = (prop, kind)
                kinds.append(kind)

            # resolve property kinds
            for kind in kinds:
                kind.resolve(model)

            # make sure all successor kinds can be resolved
            for names in self.successor_kinds.values():
                for name in names or []:
                    if name not in model:
                        raise AttributeError(f"{name} is not a known kind")

            # resolve the hierarchy
            if not self.is_root():
                for base_name in self.bases:
                    base: Kind = model[base_name]
                    base.resolve(model)
                    if isinstance(base, ComplexKind):
                        self.__resolved_bases[base_name] = base
                        self.__resolved_props.update(base.__resolved_props)
                        self.__all_props = base.__all_props + self.__all_props
                        self.__prop_by_name = {prop.name: prop for prop in self.__all_props}
                        self.__resolved_hierarchy.update(base.__resolved_hierarchy)

            # property path -> kind
            self.__property_by_path = ComplexKind.resolve_properties(self, model)
            self.__synthetic_props = [p for p in self.__property_by_path if p.prop.synthetic]

            # resolve predecessor kinds
            self._predecessor_kinds = {
                edge_type: [
                    kind.fqn
                    for kind in model.values()
                    if isinstance(kind, ComplexKind) and self.fqn in kind.successor_kinds.get(edge_type, [])
                ]
                for edge_type in AvailableEdgeTypes
            }

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ComplexKind):
            return (
                self.fqn == other.fqn
                and self.properties == other.properties
                and self.bases == other.bases
                and self.allow_unknown_props == other.allow_unknown_props
                and self.successor_kinds == other.successor_kinds
                and self.aggregate_root == other.aggregate_root
                and self.metadata == other.metadata
            )
        else:
            return False

    def __contains__(self, name: str) -> bool:
        return name in self.__prop_by_name

    def __getitem__(self, name: str) -> Property:
        return self.__prop_by_name[name]

    def meta_get(self, name: str, clazz: Type[T], default: T) -> T:
        return md if isinstance(md := self.metadata.get(name), clazz) else default

    def property_kind_of(self, name: str, or_else: Kind) -> Kind:
        maybe = self.__resolved_props.get(name)
        return maybe[1] if maybe else or_else

    def property_with_kind_of(self, name: str) -> Optional[Tuple[Property, Kind]]:
        return self.__resolved_props.get(name)

    # All properties in hierarchy
    def property_with_kinds(self) -> Iterable[Tuple[Property, Kind]]:
        return self.__resolved_props.values()

    # All properties directly defined for this complex kind
    def direct_property_with_kinds(self) -> Iterable[Tuple[Property, Kind]]:
        return self.__resolved_direct_props.values()

    def is_root(self) -> bool:
        return not self.bases or (len(self.bases) == 1 and self.bases[0] == self.fqn)

    def kind_hierarchy(self) -> Set[str]:
        return self.__resolved_hierarchy

    def is_a(self, kind: str) -> bool:
        return kind in self.__resolved_hierarchy

    def resolved_property_paths(self) -> List[ResolvedPropertyPath]:
        return self.__property_by_path

    def resolved_bases(self) -> Dict[str, ComplexKind]:
        return self.__resolved_bases

    def all_props(self) -> List[Property]:
        return self.__all_props

    def all_props_with_kind(self) -> List[Tuple[Property, Kind]]:
        return [(a, self.property_kind_of(a.name, any_kind)) for a in self.__all_props]

    def synthetic_props(self) -> List[ResolvedPropertyPath]:
        return self.__synthetic_props

    def predecessor_kinds(self) -> Dict[EdgeType, List[str]]:
        return self._predecessor_kinds

    def transitive_complex_types(self, with_bases: bool = True, with_properties: bool = True) -> List[ComplexKind]:
        result: Dict[str, ComplexKind] = {}
        visited: Set[str] = set()

        def add_bases(ck: ComplexKind) -> None:
            for fqn, base in ck.resolved_bases().items():
                result[fqn] = base

        def add_props(ck: ComplexKind) -> None:
            for prop in ck.resolved_property_paths():
                if isinstance(prop.kind, ComplexKind):
                    result[prop.kind.fqn] = prop.kind
                    in_hierarchy(prop.kind)

        def in_hierarchy(ck: ComplexKind) -> None:
            if ck.fqn in visited:
                return
            visited.add(ck.fqn)
            result[ck.fqn] = ck
            if with_bases:
                add_bases(ck)
            if with_properties:
                add_props(ck)
            for base in ck.resolved_bases().values():
                if not base.is_root():
                    in_hierarchy(base)

        in_hierarchy(self)
        return list(result.values())

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            coerced = self.coerce_if_required(obj, **kwargs)
            for name, value in (coerced or obj).items():
                known = self.__resolved_props.get(name, None)
                if known:
                    prop, kind = known
                    if prop.synthetic:
                        # synthetic properties are computed and will not be maintained. Ignore.
                        pass
                    elif value is None:
                        if prop.required:
                            raise AttributeError(f"Required property {prop.name} is undefined!")
                    else:
                        try:
                            kind.check_valid(value, **kwargs)
                        except AttributeError as at:
                            raise AttributeError(
                                f"Kind:{self.fqn} Property:{name} is not valid: {at}: {json.dumps(obj)}"
                            ) from at
                elif name == "kind":
                    pass
                elif not self.allow_unknown_props:
                    raise AttributeError(f"Kind:{self.fqn} Property:{name} is not defined in model!")
            if not kwargs.get("ignore_missing"):
                for prop in self.__all_props:
                    if prop.required and prop.name not in obj:
                        raise AttributeError(
                            f"Kind:{self.fqn} Property:{prop.name} is required and missing in {json.dumps(obj)}"
                        )
            return coerced
        else:
            raise AttributeError(f"Kind:{self.fqn} expected a complex type but got this: {obj}")

    def coerce_if_required(self, value: JsonElement, **kwargs: bool) -> Optional[Json]:
        if isinstance(value, dict):
            result: Json = {}
            has_coerced = False
            for n, v in value.items():
                known = self.__resolved_props.get(n, None)
                if known:
                    prop, kind = known
                    if prop.synthetic:
                        # synthetic properties are computed and will not be maintained. Ignore.
                        pass
                    elif v is None:
                        result[n] = None
                    else:
                        coerced = kind.coerce_if_required(v, **kwargs)
                        has_coerced |= coerced is not None
                        result[n] = coerced if coerced is not None else v
                else:
                    result[n] = v
            return result if has_coerced else None
        else:
            return None

    def create_yaml(self, elem: JsonElement, initial_level: int = 0, overrides: Optional[Json] = None) -> str:
        def safe_string(s: str, indent: int, default_style: Optional[str] = None) -> str:
            # 2 spaces per indent
            yml = yaml.dump(s, indent=0, allow_unicode=True, width=sys.maxsize, default_style=default_style)
            yml = remove_suffix(yml, "\n...\n")
            if default_style == "|":
                yml = textwrap.indent(yml, " " * (max(0, indent - 1) * 2)).lstrip()
            else:
                yml = yml.strip()
            return yml

        def override_note(overrides: Optional[Json], prop_name: str) -> Optional[str]:
            if overrides:
                override = overrides.get(prop_name)
                # leaf node of the override tree
                if isinstance(override, (str, list, int, float, bool)):
                    note = (
                        "Warning: the current value is being ignored because there "
                        "is an active override in place. "
                        f"The override value is: {override}"
                    )
                    return note

            return None

        def walk_element(
            e: JsonElement, kind: Kind, indent: int, cr_on_object: bool = True, overrides: Optional[Json] = None
        ) -> str:
            if isinstance(e, dict):
                result = "\n" if cr_on_object else ""
                prepend = "  " * indent
                for prop, value in e.items():
                    description = None
                    sub: Kind = AnyKind()
                    if isinstance(kind, ComplexKind):
                        maybe_prop = kind.property_with_kind_of(prop)
                        if maybe_prop:
                            description = maybe_prop[0].description
                            sub = maybe_prop[1]
                            # if we're in a complex kind, add the override note
                            if note := override_note(overrides, maybe_prop[0].name):
                                description = f"{description}\n{note}" if description else note
                    elif isinstance(kind, DictionaryKind):
                        sub = kind.value_kind
                        # if we're in a dict, add the override note
                        if note := override_note(overrides, prop):
                            description = f"{description}\n{note}" if description else note

                    override_child = None
                    # check if there are overrides to be passed down the tree
                    if overrides:
                        override_child = overrides.get(prop) or {}
                        if not isinstance(override_child, dict):
                            # overrides can't be traversed further
                            override_child = None
                    str_value = walk_element(value, sub, indent + 1, overrides=override_child)
                    if description:
                        for line in description.splitlines():
                            result += f"{prepend}# {line}\n"
                    maybe_space = "" if str_value.startswith("\n") else " "
                    safe_prop = safe_string(prop, indent)
                    result += f"{prepend}{safe_prop}:{maybe_space}{str_value}\n"
                return remove_suffix(result, "\n")
            elif isinstance(e, list) and e:
                prepend = "  " * indent + "-"
                sub = kind.inner if isinstance(kind, ArrayKind) else kind
                result = "\n"
                for item in e:
                    item_str = walk_element(item, sub, indent + 1, False).lstrip()
                    result += f"{prepend} {item_str}\n"
                return remove_suffix(result, "\n")
            elif isinstance(e, list):
                return "[]"
            elif is_env_var_string(e):
                return str(e)
            elif isinstance(e, str):
                # if the string contains a newline, try a literal block, else a quoted string
                return safe_string(e, indent, "|" if ("\n" in e and len(e) > 1) else "'")
            elif e is None:
                return "null"
            elif e is True:
                return "true"
            elif e is False:
                return "false"
            else:
                return str(e)

        return walk_element(elem, self, initial_level, overrides=overrides)

    @staticmethod
    def resolve_properties(
        complex_kind: ComplexKind,
        model: Dict[str, Kind],
        from_path: PropertyPath = EmptyPath,
        maybe_visited: Optional[Dict[str, PropertyPath]] = None,
    ) -> List[ResolvedPropertyPath]:
        visited = maybe_visited or {}
        result: List[ResolvedPropertyPath] = []

        def path_for(
            prop: Property, kind: Kind, path: PropertyPath, array: bool = False, add_prop_to_path: bool = True
        ) -> None:
            prop_name = f"{prop.name}[]" if array else prop.name
            # Detect object cycles: remember the path when we have visited this property.
            # More complex cycles can be detected that way - leave it simple for now.
            key = f"{prop_name}:{prop.kind}"
            if key in visited and prop_name in visited[key].path:
                return
            visited[key] = path
            relative = path.child(prop_name) if add_prop_to_path else path
            # make sure the kind is resolved
            kind.resolve(model)
            if isinstance(kind, SimpleKind):
                result.append(ResolvedPropertyPath(relative, prop, kind))
            elif isinstance(kind, ArrayKind):
                if name := relative.last_part:
                    result.append(ResolvedPropertyPath(relative, Property(name, kind.fqn), kind))
                path_for(prop, kind.inner, path, True)
            elif isinstance(kind, DictionaryKind):
                child = relative.child(None)
                if name := relative.last_part:
                    result.append(ResolvedPropertyPath(relative, Property(name, kind.fqn), kind))
                    # Any child path accessing this dictionary will get a property of value kind.
                    value = kind.value_kind
                    result.append(ResolvedPropertyPath(child, Property("any", value.fqn), value))
                path_for(prop, kind.value_kind, child, add_prop_to_path=False)
            elif isinstance(kind, ComplexKind):
                if name := relative.last_part:
                    result.append(ResolvedPropertyPath(relative, Property(name, kind.fqn), kind))
                result.extend(ComplexKind.resolve_properties(kind, model, relative, visited))

        for x in complex_kind.all_props():
            path_for(x, complex_kind.__resolved_props[x.name][1], from_path)

        return result


string_kind = StringKind("string")
int32_kind = NumberKind("int32", "int32")
int64_kind = NumberKind("int64", "int64")
float_kind = NumberKind("float", "float")
double_kind = NumberKind("double", "double")
any_kind = AnyKind()
boolean_kind = BooleanKind("boolean")
date_kind = DateKind("date")
datetime_kind = DateTimeKind("datetime")
duration_kind = DurationKind("duration")
empty_complex_kind = ComplexKind("empty", [], [], allow_unknown_props=True)

# Define synthetic properties in the metadata section (not defined in the model)
# The predefined_properties kind is used to define the properties there.
synthetic_metadata_kinds = tuple(["exported_age"])

predefined_kinds = [
    string_kind,
    int32_kind,
    int64_kind,
    float_kind,
    double_kind,
    any_kind,
    boolean_kind,
    date_kind,
    datetime_kind,
    duration_kind,
    TransformKind("trafo.duration_to_datetime", "duration", "datetime", "duration_to_datetime", reverse_order=True),
    ComplexKind(
        "graph_root",
        [],
        [
            Property("id", "string", False, None, "The id of this node."),
            Property("name", "string", False, None, "The name of this node."),
            Property("tags", "dictionary[string, string]", False, None, "All attached tags of this node."),
        ],
        allow_unknown_props=True,
    ),
    ComplexKind(
        "predefined_properties",
        [],
        [
            Property("kind", "string", False, None, "The kind property of every node."),
            Property("ctime", "datetime", False, None, "datetime when the node has been created."),
            Property("age", "trafo.duration_to_datetime", False, SyntheticProperty(["ctime"])),
            Property("last_update", "trafo.duration_to_datetime", False, SyntheticProperty(["mtime"])),
            Property("last_access", "trafo.duration_to_datetime", False, SyntheticProperty(["atime"])),
            # Resource tags might define expiration time. Translate durations to absolute times.
            Property("expires", "datetime", False, None, "datetime when the node expires."),
            # Account defines the time when the data was collected in the metadata section
            Property("exported_at", "datetime", False, None, "datetime when the account was exported."),
            Property("exported_age", "trafo.duration_to_datetime", False, SyntheticProperty(["exported_at"])),
            Property("provider_link", "string", False, None, "Link to the provider of this resource."),
        ],
        metadata={"dynamic": True},
    ),
]
predefined_kinds_by_name = {k.fqn: k for k in predefined_kinds}

allowed_simple_type_changes: List[Tuple[Optional[str], Optional[str]]] = [
    ("string", "duration"),
    ("string", "date"),
    ("duration", "string"),
    ("date", "string"),
    ("any", None),
    (None, "any"),
]


class Model:
    @staticmethod
    def empty() -> Model:
        return Model({}, [])

    @staticmethod
    def from_kinds(kinds: List[Kind]) -> Model:
        all_kinds = kinds + predefined_kinds
        kind_dict = {kind.fqn: kind for kind in all_kinds}
        for kind in all_kinds:
            kind.resolve(kind_dict)
        resolved = list(
            # several complex kinds might have the same property
            # reduce the list by hash over the path.
            {
                r.path: r
                for c in all_kinds
                if isinstance(c, ComplexKind) and c.aggregate_root
                for r in c.resolved_property_paths()
            }.values()
        )
        return Model(kind_dict, resolved)

    def __init__(self, kinds: Dict[str, Kind], property_kind_by_path: List[ResolvedPropertyPath]):
        self.kinds = kinds
        self.__property_kind_by_path: List[ResolvedPropertyPath] = property_kind_by_path

    def __contains__(self, name_or_object: Union[str, Json]) -> bool:
        if isinstance(name_or_object, str):
            return name_or_object in self.kinds
        elif isinstance(name_or_object, dict) and "kind" in name_or_object:
            return name_or_object["kind"] is self.kinds
        else:
            return False

    def __getitem__(self, name_or_object: Union[str, Json]) -> Kind:
        if isinstance(name_or_object, str):
            return self.kinds[name_or_object]
        elif isinstance(name_or_object, dict) and "kind" in name_or_object:
            return self.kinds[name_or_object["kind"]]
        else:
            raise KeyError(f"Expected string or json with a 'kind' property as key but got: {name_or_object}")

    def __len__(self) -> int:
        return len(self.kinds)

    def get(self, name_or_object: Union[str, Json]) -> Optional[Kind]:
        if isinstance(name_or_object, str):
            return self.kinds.get(name_or_object)
        elif isinstance(name_or_object, dict) and "kind" in name_or_object:
            return self.kinds.get(name_or_object["kind"])
        else:
            return None

    def complex_kinds(self) -> Iterator[ComplexKind]:
        for k in self.kinds.values():
            if isinstance(k, ComplexKind):
                yield k

    def aggregate_roots(self) -> Iterator[ComplexKind]:
        for k in self.complex_kinds():
            if k.aggregate_root:
                yield k

    def property_by_path(self, path_: Union[str, List[str]]) -> ResolvedPropertyPath:
        path = PropertyPath.from_string(path_) if isinstance(path_, str) else PropertyPath.from_list(path_)
        found: Optional[ResolvedPropertyPath] = first(
            lambda prop: prop.path.same_as(path), self.__property_kind_by_path
        )
        # if the path is not known according to known model: it could be anything.
        return found if found else ResolvedPropertyPath(path, Property.any_prop(), AnyKind())

    def kind_by_path(self, path: Union[str, List[str]]) -> Kind:
        return self.property_by_path(path).kind

    def coerce(self, js: Json) -> Json:
        try:
            kind: Kind = self[js["kind"]]
            return kind.coerce(js)  # type: ignore
        except KeyError as ex:
            raise AttributeError(
                f'No kind definition found for {js["kind"]}' if "kind" in js else f"No attribute kind found in {js}"
            ) from ex

    def check_valid(self, js: Json, **kwargs: bool) -> ValidationResult:
        try:
            kind: Kind = self[js["kind"]]
            return kind.check_valid(js, **kwargs)
        except KeyError as ex:
            raise AttributeError(
                f'No kind definition found for {js["kind"]}' if "kind" in js else f"No attribute kind found in {js}"
            ) from ex

    @lru_cache
    def predefined_synthetic_props(self, allowed: Tuple[str, ...]) -> List[ResolvedPropertyPath]:
        predefined = self.get("predefined_properties")
        if isinstance(predefined, ComplexKind):
            return [p for p in predefined.synthetic_props() if p.prop.name in allowed]
        else:
            return []

    def graph(self) -> MultiDiGraph:
        graph = MultiDiGraph()

        def handle_complex(cx: ComplexKind) -> None:
            # do not handle the same complex kind more than once
            if cx.fqn in graph and "data" in graph.nodes[cx.fqn]:
                return

            graph.add_node(cx.fqn, data=cx)
            # inheritance
            if not cx.is_root():
                for base in cx.bases:
                    graph.add_edge(cx.fqn, base, f"inheritance_{cx.fqn}_{base}", type="inheritance")

            # properties
            for _, prop_kind in cx.property_with_kinds():
                for cpl in prop_kind.nested_complex_kinds():
                    graph.add_edge(cx.fqn, cpl.fqn, f"property_{cx.fqn}_{cpl.fqn}", type="property")
                    handle_complex(cpl)

            # dependency
            for name, successors in cx.successor_kinds.items():
                for successor in successors or []:
                    graph.add_edge(
                        cx.fqn, successor, f"successor_{cx.fqn}_{successor}_{name}", type="successor", edge_type=name
                    )

        for kind in self.kinds.values():
            if isinstance(kind, ComplexKind):
                handle_complex(kind)
            elif isinstance(kind, ArrayKind) and isinstance(kind.inner, ComplexKind):
                handle_complex(kind.inner)
            elif isinstance(kind, DictionaryKind) and isinstance(kind.value_kind, ComplexKind):
                handle_complex(kind.value_kind)

        return graph

    def update_kinds(self, kinds: List[Kind], check_overlap: bool = True, replace: bool = False) -> Model:
        """
        Update the model with the given kinds. The kinds are merged with the existing model.
        :param kinds: the kinds to update.
        :param check_overlap: true if paths with different kinds should be avoided, otherwise false.
        :param replace: if true, the existing model is replaced with the new kinds.
        """
        # Create a list of kinds that have changed to the existing model
        to_update = []

        def merge_metadata(update: ComplexKind, existing: ComplexKind) -> None:
            """
            Merge metadata of complex kinds and their properties.
            ATM: we only merge the len property of string kinds.
            """
            existing_props: Dict[str, Property] = {prop.name: prop for prop in existing.properties}
            for prop in update.properties:
                existing_prop = existing_props.get(prop.name)
                meta = prop.metadata or {}
                # take the maximum of all lengths ever seen
                if existing_prop is not None and existing_prop.meta("len", int) is not None:
                    meta["len"] = max(prop.meta_get("len", int, 0), existing_prop.meta_get("len", int, 0))
                    prop.metadata = meta

        for elem in kinds:
            existing_elem = self.kinds.get(elem.fqn)
            # merge old and new metadata for complex kinds and their properties
            if isinstance(elem, ComplexKind) and isinstance(existing_elem, ComplexKind):
                merge_metadata(elem, existing_elem)
            if elem.fqn not in predefined_kinds_by_name and (not existing_elem or existing_elem != elem):
                to_update.append(elem)

        # Short circuit, if there are no changes
        if not to_update:
            return self

        def update_is_valid(from_kind: Kind, to_kind: Kind) -> None:
            # Allowed changes: The update
            # - does not change it's type (e.g. going from SimpleKind to ComplexKind)
            if type(from_kind) is not type(to_kind):  # pylint: disable=unidiomatic-typecheck
                raise AttributeError(f"Update {from_kind.fqn} changes an existing property type {from_kind.fqn}")

        # resolve and build dict
        new_kinds = {kind.fqn: kind for kind in kinds}
        updates = {elem.fqn: elem for elem in to_update}
        filtered_kinds = (
            {k: v for k, v in self.kinds.items() if k in new_kinds or k in predefined_kinds_by_name}
            if replace
            else self.kinds
        )
        updated = {**filtered_kinds, **updates}
        for elem in to_update:
            elem.resolve(updated)

        # check if updating existing kinds is allowed
        for name in self.kinds.keys() & updates.keys():
            update_is_valid(self.kinds[name], updates[name])

        if check_overlap:
            check_overlap_for([to_js(a) for a in updated.values()])

        return Model.from_kinds(list(updated.values()))

    def flat_kinds(self, lookup_model: Optional[Model] = None) -> Model:
        """
        Returns a list of all kinds. The hierarchy of complex kinds is flattened:
        - all properties of all base kinds.
        - all metadata merged in hierarchy.
        - all successor kinds combined in hierarchy.
        """
        model = lookup_model if lookup_model else self

        def get_complex(name: str) -> ComplexKind:
            return ck if isinstance(ck := model.get(name), ComplexKind) else empty_complex_kind

        def all_bases(kind: ComplexKind) -> Set[str]:
            bases: Set[str] = set()
            for base, base_kind in kind.resolved_bases().items():
                bases.add(base)
                bases |= all_bases(base_kind)
            return bases

        def all_props(kind: ComplexKind) -> Dict[str, Property]:
            props_by_name = {}
            for props in [all_props(get_complex(fqn)) for fqn in kind.bases] + [{p.name: p for p in kind.properties}]:
                for key, value in props.items():
                    props_by_name[key] = value
            return props_by_name

        def all_metadata(kind: ComplexKind) -> Dict[str, Any]:
            metadata = {}
            for meta in [all_metadata(get_complex(fqn)) for fqn in kind.bases] + [kind.metadata]:
                for key, value in meta.items():
                    metadata[key] = value
            return metadata

        def all_successor_kinds(kind: ComplexKind) -> Dict[EdgeType, List[str]]:
            successor_kinds = kind.successor_kinds.copy()
            for base in kind.bases:
                for edge_type, succ in all_successor_kinds(get_complex(base)).items():
                    successor_kinds[edge_type] = successor_kinds.get(edge_type, []) + succ
            return successor_kinds

        def all_predecessor_kinds(kind: ComplexKind) -> Dict[EdgeType, List[str]]:
            predecessor_kinds = kind.predecessor_kinds().copy()
            for base in kind.bases:
                for edge_type, succ in all_predecessor_kinds(get_complex(base)).items():
                    predecessor_kinds[edge_type] = predecessor_kinds.get(edge_type, []) + succ
            return predecessor_kinds

        result: Dict[str, Kind] = {}
        for kind in self.kinds.values():
            if isinstance(kind, ComplexKind):
                result[kind.fqn] = kind.copy(
                    bases=list(all_bases(kind)),
                    properties=list(all_props(kind).values()),
                    successor_kinds=all_successor_kinds(kind),
                    predecessor_kinds=all_predecessor_kinds(kind),
                    metadata=all_metadata(kind),
                )
            else:
                result[kind.fqn] = kind
        return Model(result, self.__property_kind_by_path)

    def filter_complex(
        self, filter_fn: Callable[[ComplexKind], bool], with_bases: bool = True, with_prop_types: bool = True
    ) -> Model:
        """
        Returns a model that contains only the aggregates for which the filter function returns true.
        """
        visited: Set[str] = set()
        kinds: Dict[str, Kind] = {}

        def add_kind(cpl: ComplexKind) -> None:
            if cpl.fqn in visited:
                return
            visited.add(cpl.fqn)
            kinds[cpl.fqn] = cpl
            # add bases
            if with_bases:
                for _, base in cpl.resolved_bases().items():
                    add_kind(base)
            # add prop types
            if with_prop_types:
                for prop in cpl.resolved_property_paths():
                    if isinstance(prop.kind, ComplexKind):
                        add_kind(prop.kind)

        for kind in self.kinds.values():
            if isinstance(kind, ComplexKind) and filter_fn(kind):
                add_kind(kind)

        return Model(kinds, self.__property_kind_by_path)

    def complete_path(
        self,
        path: str,
        prop: str,
        *,
        filter_kinds: Optional[List[str]] = None,
        fuzzy: bool = False,
        skip: int = 0,
        limit: int = 20,
    ) -> Tuple[int, Dict[str, str]]:
        if fuzzy:
            prop_re = re.compile(f".*{prop}.*")
            filter_prop: Callable[[str], bool] = lambda p: prop_re.match(p) is not None
        else:
            filter_prop = lambda p: p.startswith(prop)  # noqa

        def sort_key(k: str) -> Tuple[int, str]:
            return 0 if k.startswith(prop) else 1, k

        def from_prop_path(kinds: Iterable[ComplexKind]) -> Tuple[int, Dict[str, str]]:
            props: Dict[str, str] = {}
            for kind in kinds:
                for p, pk in kind.all_props_with_kind():
                    if filter_prop(p.name):
                        if isinstance(pk, ArrayKind):
                            props[p.name + "[*]"] = pk.inner.fqn
                        elif isinstance(pk, TransformKind):
                            props[p.name] = (pk.source_kind or any_kind).fqn
                        elif isinstance(pk, SimpleKind):
                            props[p.name] = pk.runtime_kind
                        else:
                            props[p.name] = pk.fqn
            return len(props), {k: props[k] for k in sorted(props, key=sort_key)[skip : skip + limit]}

        def from_aggregate_roots() -> Tuple[int, Dict[str, str]]:
            roots: Dict[str, str] = {}
            for kind in self.aggregate_roots():
                if filter_prop(kind.fqn) and (not filter_kinds or kind.fqn in filter_kinds):
                    roots[kind.fqn] = "node"
            return len(roots), {k: roots[k] for k in sorted(roots, key=sort_key)[skip : skip + limit]}

        if path:
            parts = path.split(".")
            if parts[0] in ("ancestors", "descendants"):
                if len(parts) == 1:
                    return from_aggregate_roots()
                elif len(parts) == 2:
                    return 1, {"reported": "resource"}
                elif len(parts) == 3 and parts[2] == "reported" and (kind := self.get(parts[1])):
                    return from_prop_path([kind]) if isinstance(kind, ComplexKind) else (0, {})
                elif len(parts) > 3 and parts[2] == "reported":
                    parts = parts[3:]
                else:
                    return 0, {}
            elif parts[0] in ("reported", "metadata", "desired"):
                parts = parts[1:]
            path = ".".join(parts)

        if path:
            resolved = self.property_by_path(path)
            return from_prop_path([resolved.kind]) if isinstance(resolved.kind, ComplexKind) else (0, {})
        else:
            roots = [k for k in self.aggregate_roots() if not filter_kinds or k.fqn in filter_kinds]
            return from_prop_path(roots)


@frozen
class UsageDatapoint:
    """
    A single datapoint of resource usage.

    id: `str`
        Identifier of the resource as named by the cloud.
    at: `int`
        Timestamp of the datapoint in seconds since epoch.
        Name of the metric.
    change_id: `str`
        Id of the import
    v: `Dict[str, List[float]]]`
        Dictionary of metric names to lists of values. The values are `min`, `avg` and `max`.

    """

    id: str
    at: int
    change_id: str
    v: Dict[str, Dict[str, float]]


# register serializer for this class
set_deserializer(Kind.from_json, Kind)
set_serializer(Kind.to_json, Kind)
