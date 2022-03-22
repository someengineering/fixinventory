from __future__ import annotations

import json
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone, date
from json import JSONDecodeError
from typing import Union, Any, Optional, Callable, Type, Sequence, Dict, List, Set, cast, Tuple

import yaml
from dateutil.parser import parse
from jsons import set_deserializer, set_serializer
from networkx import DiGraph
from parsy import regex, string, Parser

from resotocore.durations import duration_parser, DurationRe
from resotocore.model.transform_kind_convert import converters
from resotocore.model.typed_model import from_js
from resotocore.parse_util import make_parser
from resotocore.types import Json, JsonElement, ValidationResult, ValidationFn
from resotocore.util import if_set, utc, duration, first


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


@dataclass(order=True, unsafe_hash=True, frozen=True)
class SyntheticProperty:
    path: List[str]
    """
    A synthetic property does not exist in the underlying data model.
    It is defined by a function on an existing other property.
    Example: age is a duration defined on ctime which is a datetime.
             the function is age=now-ctime.
    """


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Property:
    name: str
    kind: str
    required: bool = False
    synthetic: Optional[SyntheticProperty] = None
    description: Optional[str] = None

    def __post_init__(self) -> None:
        assert self.synthetic is None or not self.required, "Synthetic properties can not be required!"

    def resolve(self, model: Dict[str, Kind]) -> Kind:
        return Property.parse_kind(self.kind, model)

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
            brackets = yield bracket_parser.times(1, float("inf"))
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


class PropertyPath:
    @staticmethod
    def from_path(path: str) -> PropertyPath:
        return PropertyPath(path.split("."), path)

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

    def __repr__(self) -> str:
        return self.path_str

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, PropertyPath) and other.path_str == self.path_str

    def __hash__(self) -> int:
        return hash(self.path_str)


EmptyPath = PropertyPath([], "")


@dataclass(order=True, unsafe_hash=True, frozen=True)
class ResolvedProperty:
    # The path of the resolved property in a complex kind
    path: PropertyPath
    # The metadata of the property (name etc.)
    prop: Property
    # the resolved kind of this property
    kind: SimpleKind


class Kind(ABC):
    def __init__(self, fqn: str):
        self.fqn = fqn

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Kind) else False

    @abstractmethod
    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        pass

    def resolve(self, model: Dict[str, Kind]) -> None:
        pass

    def kind_hierarchy(self) -> Set[str]:
        return {self.fqn}

    def package(self) -> Optional[str]:
        return self.fqn.rsplit(".", 1)[0] if "." in self.fqn else None

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
            bases: Optional[List[str]] = js.get("bases")
            allow_unknown_props = js.get("allow_unknown_props", False)
            return ComplexKind(js["fqn"], bases if bases else [], props, allow_unknown_props)
        else:
            raise JSONDecodeError("Given type can not be read.", json.dumps(js), 0)


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

    # noinspection PyMethodMayBeStatic
    def coerce(self, value: object) -> Any:
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
        return value

    def as_json(self) -> Json:
        return {"fqn": self.fqn, "runtime_kind": self.runtime_kind}

    # noinspection PyUnusedLocal
    @staticmethod
    def to_json(obj: SimpleKind, **kw_args: object) -> Json:
        return obj.as_json()


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
        return self.valid_fn(obj)

    def coerce(self, value: Any) -> Optional[str]:
        if value is None:
            return value
        if isinstance(value, str):
            return value
        else:
            return str(value)

    def as_json(self) -> Json:
        js = super().as_json()
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
        return self.valid_fn(obj)

    def coerce(self, value: object) -> Optional[Union[int, float]]:
        if value is None:
            return value
        elif isinstance(value, (int, float)):
            return value
        else:
            return float(value)  # type: ignore

    def as_json(self) -> Json:
        js = super().as_json()
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
        return self.valid_fn(obj)

    def coerce(self, value: Any) -> Optional[bool]:
        if value is None:
            return value
        elif isinstance(value, bool):
            return value
        else:
            return str(value).lower() == "true"


class DurationKind(SimpleKind):
    def __init__(self, fqn: str):
        super().__init__(fqn, "duration")
        self.valid_fn = validate_fn(check_type_fn(str, "duration"), self.check_duration)

    def check_duration(self, v: Any) -> None:
        if not DurationRe.fullmatch(v):
            raise AttributeError(f"Wrong format for duration: {v}. Examples: 1yr, 3mo, 3d4h3min1s, 3days and 2hours")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value: Any) -> Optional[str]:
        try:
            return f"{int(duration_parser.parse(value))}s"
        except Exception as ex:
            raise AttributeError(f"Expected duration but got: >{value}<") from ex


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
        return self.valid_fn(obj)

    def coerce(self, value: Any) -> Optional[str]:
        try:
            if value is None:
                return value
            elif self.DateTimeRe.fullmatch(value):
                return value  # type: ignore
            elif DurationRe.fullmatch(value):
                return self.from_duration(value)
            else:
                return self.from_datetime(value)
        except Exception as ex:
            raise AttributeError(f"Expected datetime but got: >{value}<") from ex

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
        return self.valid_fn(obj)

    def coerce(self, value: Any) -> Optional[str]:
        try:
            if value is None:
                return value
            elif DurationRe.fullmatch(value):
                # in case of duration, compute the timestamp as: today + duration
                delta = duration(value)
                at = date.today() + delta
                return at.isoformat()
            else:
                return parse(value).date().strftime(DateKind.Format)
        except Exception as ex:
            raise AttributeError(f"Expected date but got: >{value}<") from ex


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

    def coerce(self, value: object) -> Any:
        if value is None:
            return None
        elif self.source_kind:
            coerced_source = self.source_kind.coerce(value)
            real = self.source_to_destination(coerced_source)
            return real
        else:
            raise AttributeError(f"Synthetic kind is not resolved: {self.fqn}")

    def transform(self, value: Any) -> Any:
        if value is None:
            return None
        elif self.destination_kind:
            real_coerced = self.destination_kind.coerce(value)
            synth = self.destination_to_source(real_coerced)
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

    def as_json(self) -> Json:
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

    def resolve(self, model: Dict[str, Kind]) -> None:
        self.inner.resolve(model)

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if not isinstance(obj, list):
            raise AttributeError("Expected property is not an array!")
        has_coerced = False

        def check(item: Any) -> ValidationResult:
            nonlocal has_coerced
            res = self.inner.check_valid(item, **kwargs)
            if res is None:
                return item
            else:
                has_coerced = True
                return res.value

        mapped = [check(elem) for elem in obj]
        return mapped if has_coerced else None

    @staticmethod
    def mk_array(kind: Kind, depth: int) -> Kind:
        return kind if depth == 0 else ArrayKind(ArrayKind.mk_array(kind, depth - 1))


class DictionaryKind(Kind):
    def __init__(self, key_kind: Kind, value_kind: Kind):
        super().__init__(f"dictionary[{key_kind.fqn}, {value_kind.fqn}]")
        self.key_kind = key_kind
        self.value_kind = value_kind

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            for prop, value in obj.items():
                part = "key"
                try:
                    self.key_kind.check_valid(prop)
                    part = "value"
                    self.value_kind.check_valid(value)
                except Exception as at:
                    raise AttributeError(f"{part} of {self.fqn} is not valid: {at}") from at
            return None
        else:
            raise AttributeError(f"dictionary requires a json object, but got this: {obj}")

    def resolve(self, model: Dict[str, Kind]) -> None:
        self.key_kind.resolve(model)
        self.value_kind.resolve(model)


class ComplexKind(Kind):
    def __init__(self, fqn: str, bases: List[str], properties: List[Property], allow_unknown_props: bool = False):
        super().__init__(fqn)
        self.bases = bases
        self.properties = properties
        self.allow_unknown_props = allow_unknown_props
        self.__prop_by_name = {prop.name: prop for prop in properties}
        self.__resolved = False
        self.__resolved_kinds: Dict[str, Tuple[Property, Kind]] = {}
        self.__all_props: List[Property] = list(self.properties)
        self.__resolved_hierarchy: Set[str] = {fqn}
        self.__property_by_path: List[ResolvedProperty] = []
        self.__synthetic_props: List[ResolvedProperty] = []

    def resolve(self, model: Dict[str, Kind]) -> None:
        if not self.__resolved:
            self.__resolved = True
            # resolve properties
            for prop in self.properties:
                kind = prop.resolve(model)
                kind.resolve(model)
                self.__resolved_kinds[prop.name] = (prop, kind)

            # property path -> kind
            self.__property_by_path = ComplexKind.resolve_properties(self)

            # resolve the hierarchy
            if not self.is_root():
                for base_name in self.bases:
                    base: Kind = model[base_name]
                    base.resolve(model)
                    if isinstance(base, ComplexKind):
                        self.__resolved_kinds.update(base.__resolved_kinds)
                        self.__all_props += base.__all_props
                        self.__prop_by_name = {prop.name: prop for prop in self.__all_props}
                        self.__resolved_hierarchy.update(base.__resolved_hierarchy)
                        self.__property_by_path.extend(base.__property_by_path)
            self.__synthetic_props = [p for p in self.__property_by_path if p.prop.synthetic]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ComplexKind):
            return (
                self.fqn == other.fqn
                and self.properties == other.properties
                and self.bases == other.bases
                and self.allow_unknown_props == other.allow_unknown_props
            )
        else:
            return False

    def __contains__(self, name: str) -> bool:
        return name in self.__prop_by_name

    def __getitem__(self, name: str) -> Property:
        return self.__prop_by_name[name]

    def property_kind_of(self, name: str, or_else: Kind) -> Kind:
        maybe = self.__resolved_kinds.get(name)
        return maybe[1] if maybe else or_else

    def property_with_kind_of(self, name: str) -> Optional[Tuple[Property, Kind]]:
        return self.__resolved_kinds.get(name)

    def is_root(self) -> bool:
        return not self.bases or (len(self.bases) == 1 and self.bases[0] == self.fqn)

    def kind_hierarchy(self) -> Set[str]:
        return self.__resolved_hierarchy

    def resolved_properties(self) -> List[ResolvedProperty]:
        return self.__property_by_path

    def all_props(self) -> List[Property]:
        return self.__all_props

    def synthetic_props(self) -> List[ResolvedProperty]:
        return self.__synthetic_props

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            result: Json = {}
            has_coerced = False
            for name, value in obj.items():
                known = self.__resolved_kinds.get(name, None)
                if known:
                    prop, kind = known
                    if prop.synthetic:
                        # synthetic properties are computed and will not be maintained. Ignore.
                        pass
                    elif value is None:
                        if prop.required:
                            raise AttributeError(f"Required property {prop.name} is undefined!")
                        result[name] = None
                    else:
                        try:
                            coerced = kind.check_valid(value, **kwargs)
                            has_coerced |= coerced is not None
                            result[name] = coerced if coerced is not None else value
                        except AttributeError as at:
                            raise AttributeError(
                                f"Kind:{self.fqn} Property:{name} is not valid: {at}: {json.dumps(obj)}"
                            ) from at
                elif name == "kind":
                    # ok since kind is the type discriminator
                    result[name] = value
                elif not self.allow_unknown_props:
                    raise AttributeError(f"Kind:{self.fqn} Property:{name} is not defined in model!")
            if not kwargs.get("ignore_missing"):
                for prop in self.__all_props:
                    if prop.required and prop.name not in obj:
                        raise AttributeError(
                            f"Kind:{self.fqn} Property:{prop.name} is required and missing in {json.dumps(obj)}"
                        )
            return result if has_coerced else None
        else:
            raise AttributeError("Kind:{self.fqn} expected a complex type but got this: {obj}")

    def create_yaml(self, elem: JsonElement, initial_level: int = 0) -> str:
        def walk_element(e: JsonElement, kind: Kind, indent: int, cr_on_object: bool = True) -> str:
            if isinstance(e, dict):
                result = "\n" if cr_on_object else ""
                prepend = "  " * indent
                for prop, value in sorted(e.items()):
                    description = None
                    sub: Kind = AnyKind()
                    if isinstance(kind, ComplexKind):
                        maybe_prop = kind.property_with_kind_of(prop)
                        if maybe_prop:
                            description = maybe_prop[0].description
                            sub = maybe_prop[1]
                    elif isinstance(kind, DictionaryKind):
                        sub = kind.value_kind
                    str_value = walk_element(value, sub, indent + 1)
                    if description:
                        for line in description.splitlines():
                            result += f"{prepend}# {line}\n"
                    maybe_space = "" if str_value.startswith("\n") else " "
                    result += f"{prepend}{prop}:{maybe_space}{str_value}\n"
                return result.rstrip()
            elif isinstance(e, list) and e:
                prepend = "  " * indent + "-"
                sub = kind.inner if isinstance(kind, ArrayKind) else kind
                result = "\n"
                for item in e:
                    item_str = walk_element(item, sub, indent + 1, False).lstrip()
                    result += f"{prepend} {item_str}\n"
                return result.rstrip()
            elif isinstance(e, list):
                return "[]"
            elif isinstance(e, str):
                return yaml.dump(e, allow_unicode=True, width=sys.maxsize).removesuffix("\n...\n")  # type: ignore
            elif e is None:
                return "null"
            elif e is True:
                return "true"
            elif e is False:
                return "false"
            else:
                return str(e)

        return walk_element(elem, self, initial_level)

    @staticmethod
    def resolve_properties(complex_kind: ComplexKind, from_path: PropertyPath = EmptyPath) -> List[ResolvedProperty]:
        def path_for(
            prop: Property, kind: Kind, path: PropertyPath, array: bool = False, add_prop_to_path: bool = True
        ) -> List[ResolvedProperty]:
            arr = "[]" if array else ""
            relative = path.child(f"{prop.name}{arr}") if add_prop_to_path else path
            if isinstance(kind, SimpleKind):
                return [ResolvedProperty(relative if add_prop_to_path else path, prop, kind)]
            elif isinstance(kind, ArrayKind):
                return path_for(prop, kind.inner, path, True)
            elif isinstance(kind, DictionaryKind):
                return path_for(prop, kind.value_kind, relative.child(None), add_prop_to_path=False)
            elif isinstance(kind, ComplexKind):
                return ComplexKind.resolve_properties(kind, relative)
            else:
                return []

        result: List[ResolvedProperty] = []
        for x in complex_kind.properties:
            result.extend(path_for(x, complex_kind.__resolved_kinds[x.name][1], from_path))

        return result


predefined_kinds = [
    StringKind("string"),
    NumberKind("int32", "int32"),
    NumberKind("int64", "int64"),
    NumberKind("float", "float"),
    NumberKind("double", "double"),
    AnyKind(),
    BooleanKind("boolean"),
    DateKind("date"),
    DateTimeKind("datetime"),
    DurationKind("duration"),
    TransformKind("trafo.duration_to_datetime", "duration", "datetime", "duration_to_datetime", reverse_order=True),
    ComplexKind(
        "graph_root",
        [],
        [
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
            Property("expires", "datetime", False, None, "datetime when the node expires."),
        ],
    ),
]
predefined_kinds_by_name = {k.fqn: k for k in predefined_kinds}


class Model:
    @staticmethod
    def empty() -> Model:
        return Model({})

    @staticmethod
    def from_kinds(kinds: List[Kind]) -> Model:
        all_kinds = kinds + predefined_kinds
        kind_dict = {kind.fqn: kind for kind in all_kinds}
        for kind in all_kinds:
            kind.resolve(kind_dict)
        return Model(kind_dict)

    def __init__(self, kinds: Dict[str, Kind]):
        self.kinds = kinds
        self.__property_kind_by_path: List[ResolvedProperty] = list(
            # several complex kinds might have the same property
            # reduce the list by hash over the path.
            {r.path: r for c in kinds.values() if isinstance(c, ComplexKind) for r in c.resolved_properties()}.values()
        )

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

    def complex_kinds(self) -> List[ComplexKind]:
        return [k for k in self.kinds.values() if isinstance(k, ComplexKind)]

    def property_by_path(self, path_: str) -> ResolvedProperty:
        path = PropertyPath.from_path(path_)
        found: Optional[ResolvedProperty] = first(lambda prop: prop.path.same_as(path), self.__property_kind_by_path)
        # if the path is not known according to known model: it could be anything.
        return found if found else ResolvedProperty(path, Property.any_prop(), AnyKind())

    def kind_by_path(self, path_: str) -> SimpleKind:
        return self.property_by_path(path_).kind

    def check_valid(self, js: Json, **kwargs: bool) -> ValidationResult:
        try:
            kind: Kind = self[js["kind"]]
            return kind.check_valid(js, **kwargs)
        except KeyError as ex:
            raise AttributeError(
                f'No kind definition found for {js["kind"]}' if "kind" in js else f"No attribute kind found in {js}"
            ) from ex

    def graph(self) -> DiGraph:
        graph = DiGraph()

        def handle_complex(cx: ComplexKind) -> None:
            graph.add_node(cx.fqn, data=cx)
            if not cx.is_root():
                for base in cx.bases:
                    graph.add_edge(cx.fqn, base)

        for kind in self.kinds.values():
            if isinstance(kind, ComplexKind):
                handle_complex(kind)
            elif isinstance(kind, ArrayKind) and isinstance(kind.inner, ComplexKind):
                handle_complex(kind.inner)
            elif isinstance(kind, DictionaryKind) and isinstance(kind.value_kind, ComplexKind):
                handle_complex(kind.value_kind)

        return graph

    def update_kinds(self, kinds: List[Kind]) -> Model:

        # Create a list of kinds that have changed to the existing model
        to_update = []
        for elem in kinds:
            existing_props = self.kinds.get(elem.fqn)
            if elem.fqn not in predefined_kinds_by_name and (not existing_props or existing_props != elem):
                to_update.append(elem)

        # Short circuit, if there are no changes
        if not to_update:
            return self

        def update_is_valid(from_kind: Kind, to_kind: Kind) -> None:
            def hint() -> str:
                return f"Update {from_kind.fqn}"

            # Allowed changes: The update
            # - does not change it's type (e.g. going from SimpleKind to ComplexKind)
            if type(from_kind) != type(to_kind):  # pylint: disable=unidiomatic-typecheck
                raise AttributeError(f"{hint()} changes an existing property type {from_kind.fqn}")

        # resolve and build dict
        updates = {elem.fqn: elem for elem in to_update}
        updated = {**self.kinds, **updates}
        for elem in to_update:
            elem.resolve(updated)

        # check if updating existing kinds is allowed
        for name in self.kinds.keys() & updates.keys():
            update_is_valid(self.kinds[name], updates[name])

        # check if no property path is overlapping
        def check_no_overlap() -> None:
            existing_complex = [c for c in self.kinds.values() if isinstance(c, ComplexKind)]
            update_complex = [c for c in to_update if isinstance(c, ComplexKind)]
            ex = {p.path: p for k in existing_complex for p in k.resolved_properties()}
            up = {p.path: p for k in update_complex for p in k.resolved_properties()}

            def simple_kind_incompatible(p: PropertyPath) -> bool:
                left = ex[p].kind
                right = up[p].kind
                return (left.fqn != right.fqn) and not (isinstance(left, AnyKind) or isinstance(right, AnyKind))

            # Filter out duplicates that have the same kind or any side is any
            non_unique = [a for a in ex.keys() & up.keys() if simple_kind_incompatible(a)]
            if non_unique:
                # PropertyPath -> str
                name_by_kind = {p.path: k.fqn for k in update_complex for p in k.resolved_properties()}
                message = ", ".join(f"{name_by_kind[a]}.{a} ({ex[a].kind.fqn} -> {up[a].kind.fqn})" for a in non_unique)
                raise AttributeError(
                    f"Update not possible: following properties would be non unique having "
                    f"the same path but different type: {message}"
                )

        check_no_overlap()
        return Model(updated)


# register serializer for this class
set_deserializer(Kind.from_json, Kind)
set_serializer(SimpleKind.to_json, SimpleKind)
