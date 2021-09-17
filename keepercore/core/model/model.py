from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone, date
from functools import reduce
from json import JSONDecodeError
from typing import Union, Any, Optional, Callable, Type, Sequence

from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from durations_nlp import Duration
from jsons import set_deserializer, set_serializer
from networkx import DiGraph
from parsy import regex, string, Parser

from core.model.typed_model import from_js
from core.types import Json, JsonElement, ValidationResult, ValidationFn
from core.util import if_set, utc
from core.parse_util import make_parser


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


class Property:
    def __init__(self, name: str, kind: str, required: bool = False, description: Optional[str] = None):
        self.name = name
        self.kind = kind
        self.required = required
        self.description = description

    def resolve(self, model: dict[str, Kind]) -> Kind:
        return Property.parse_kind(self.kind, model)

    @staticmethod
    def parse_kind(name: str, model: dict[str, Kind]) -> Kind:
        def kind_by_name(kind_name: str) -> Kind:
            if kind_name not in model:
                raise AttributeError(f"Property kind is not known: {kind_name}. Have you registered it?")
            return model[kind_name]

        simple_kind_parser = regex("[A-Za-z][A-Za-z0-9]*").map(kind_by_name)
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
            key_kind: Kind = yield simple_kind_parser
            yield comma_parser
            value_kind = yield array_parser | dictionary_parser | simple_kind_parser
            yield bracket_r
            return Dictionary(key_kind, value_kind)

        return (array_parser | dictionary_parser | simple_kind_parser).parse(name)  # type: ignore


class PropertyPath:
    @staticmethod
    def from_path(path: str) -> PropertyPath:
        return PropertyPath(path.split("."))

    def __init__(self, path: Sequence[Optional[str]]):
        self.path = path

    @property
    def root(self) -> bool:
        return not bool(self.path)

    def child(self, part: Optional[str]) -> PropertyPath:
        update = list(self.path)
        update.append(part)
        return PropertyPath(update)

    def __repr__(self) -> str:
        return ".".join(a if a else "" for a in self.path)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, PropertyPath) and len(other.path) == len(self.path):
            for left, right in zip(self.path, other.path):
                if left is not None and right is not None and left != right:
                    return False
            return True
        else:
            return False

    def __hash__(self) -> int:
        return len(self.path)


EmptyPath = PropertyPath([])


class Kind(ABC):
    def __init__(self, fqn: str):
        self.fqn = fqn

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__ if isinstance(other, Kind) else False

    @abstractmethod
    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        pass

    def resolve(self, model: dict[str, Kind]) -> None:
        pass

    def kind_hierarchy(self) -> set[str]:
        return {self.fqn}

    def package(self) -> Optional[str]:
        return self.fqn.rsplit(".", 1)[0] if "." in self.fqn else None

    # noinspection PyUnusedLocal
    @staticmethod
    def from_json(js: Json, _: type = object, **kwargs: object) -> Kind:
        if "inner" in js:
            inner = Kind.from_json(js["inner"])
            return ArrayKind(inner)
        elif "fqn" in js and "runtime_kind" in js and js["runtime_kind"] in SimpleKind.Kind_to_type:
            fqn = js["fqn"]
            rk = js["runtime_kind"]
            if rk == "string":
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
            elif rk == "boolean":
                return BooleanKind(fqn)
            else:
                raise TypeError(f"Unhandled runtime kind: {rk}")
        elif "fqn" in js and ("properties" in js or "bases" in js):
            props = list(map(lambda p: from_js(p, Property), js.get("properties", [])))
            bases: list[str] = js.get("bases")  # type: ignore
            allow_unknown_props = js.get("allow_unknown_props", False)
            return Complex(js["fqn"], bases, props, allow_unknown_props)
        else:
            raise JSONDecodeError("Given type can not be read.", json.dumps(js), 0)


class SimpleKind(Kind, ABC):
    def __init__(self, fqn: str, runtime_kind: str):
        self.fqn = fqn
        super().__init__(fqn)
        self.runtime_kind = runtime_kind

    Kind_to_type: dict[str, Type[Union[str, int, float, bool]]] = {
        "string": str,
        "int32": int,
        "int64": int,
        "float": float,
        "double": float,
        "boolean": bool,
        "date": str,
        "datetime": str,
    }

    # noinspection PyMethodMayBeStatic
    def coerce(self, value: object) -> object:
        return value

    def as_json(self) -> Json:
        return {"fqn": self.fqn, "runtime_kind": self.runtime_kind}

    # noinspection PyUnusedLocal
    @staticmethod
    def to_json(obj: SimpleKind, **kw_args: object) -> Json:
        return obj.as_json()


class AnyKind(SimpleKind):
    def __init__(self, fqn: str):
        super().__init__(fqn, "any")

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        return None

    __singleton: Optional[AnyKind] = None

    @classmethod
    def any(cls) -> AnyKind:
        if not cls.__singleton:
            cls.__singleton = cls("any")
        return cls.__singleton


class StringKind(SimpleKind):
    def __init__(
        self,
        fqn: str,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        enum: Optional[set[str]] = None,
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

    def coerce(self, value: Any) -> object:
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
        enum: Optional[set[Union[float, int]]] = None,
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

    def coerce(self, value: object) -> object:
        if isinstance(value, (int, float)):
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

    def coerce(self, value: Any) -> object:
        if isinstance(value, bool):
            return value
        else:
            return str(value).lower() == "true"


class DateTimeKind(SimpleKind):
    Format = "%Y-%m-%dT%H:%M:%SZ"
    DateTimeRe = re.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z")
    DurationRe = re.compile("^[+-]?([\\d.]+([smhdwMy]|second|minute|hour|day|week|month|year)s?)+$")

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

    def coerce(self, value: Any) -> str:
        try:
            if self.DateTimeRe.fullmatch(value):
                return value  # type: ignore
            elif self.DurationRe.fullmatch(value):
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
        delta = relativedelta(seconds=Duration(value).seconds)
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

    def coerce(self, value: Any) -> str:
        try:
            if DateTimeKind.DurationRe.fullmatch(value):
                # in case of duration, compute the timestamp as: today + duration
                delta = relativedelta(seconds=Duration(value).seconds)
                at = date.today() + delta
                return at.isoformat()
            else:
                return parse(value).date().strftime(DateKind.Format)
        except Exception as ex:
            raise AttributeError(f"Expected date but got: >{value}<") from ex


class ArrayKind(Kind):
    def __init__(self, inner: Kind):
        super().__init__(f"{inner.fqn}[]")
        self.inner = inner

    def resolve(self, model: dict[str, Kind]) -> None:
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


class Dictionary(Kind):
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

    def resolve(self, model: dict[str, Kind]) -> None:
        self.key_kind.resolve(model)
        self.value_kind.resolve(model)


class Complex(Kind):
    def __init__(self, fqn: str, bases: list[str], properties: list[Property], allow_unknown_props: bool = False):
        super().__init__(fqn)
        self.bases = bases
        self.properties = properties
        self.allow_unknown_props = allow_unknown_props
        self.__prop_by_name = {prop.name: prop for prop in properties}
        self.__resolved = False
        self.__resolved_kinds: dict[str, tuple[Property, Kind]] = {}
        self.__all_props: list[Property] = list(self.properties)
        self.__resolved_hierarchy: set[str] = {fqn}
        self.__properties_kind_by_path: dict[PropertyPath, SimpleKind] = {}

    def resolve(self, model: dict[str, Kind]) -> None:
        if not self.__resolved:
            # resolve properties
            for prop in self.properties:
                kind = prop.resolve(model)
                kind.resolve(model)
                self.__resolved_kinds[prop.name] = (prop, kind)

            # property path -> kind
            self.__properties_kind_by_path = self.__resolve_property_paths()

            # resolve the hierarchy
            if not self.is_root():
                for base_name in self.bases:
                    base: Kind = model[base_name]
                    base.resolve(model)
                    if isinstance(base, Complex):
                        self.__resolved_kinds |= base.__resolved_kinds
                        self.__all_props += base.__all_props
                        self.__prop_by_name = {prop.name: prop for prop in self.__all_props}
                        self.__resolved_hierarchy |= base.__resolved_hierarchy
                        self.__properties_kind_by_path |= base.__properties_kind_by_path
        self.__resolved = True

    def __resolve_property_paths(self, from_path: PropertyPath = EmptyPath) -> dict[PropertyPath, SimpleKind]:
        def path_for(
            prop: Property, kind: Kind, path: PropertyPath, array: bool = False, add_prop_to_path: bool = True
        ) -> dict[PropertyPath, SimpleKind]:
            arr = "[]" if array else ""
            relative = path.child(f"{prop.name}{arr}") if add_prop_to_path else path
            if isinstance(kind, SimpleKind):
                return {relative if add_prop_to_path else path: kind}
            elif isinstance(kind, ArrayKind):
                return path_for(prop, kind.inner, path, True)
            elif isinstance(kind, Dictionary):
                return path_for(prop, kind.value_kind, relative.child(None), add_prop_to_path=False)
            elif isinstance(kind, Complex):
                return kind.__resolve_property_paths(relative)
            else:
                return {}

        result: dict[PropertyPath, SimpleKind] = {}
        for x in self.properties:
            result |= path_for(x, self.__resolved_kinds[x.name][1], from_path)

        return result

    def __contains__(self, name: str) -> bool:
        return name in self.__prop_by_name

    def __getitem__(self, name: str) -> Property:
        return self.__prop_by_name[name]

    def is_root(self) -> bool:
        return not self.bases or (len(self.bases) == 1 and self.bases[0] == self.fqn)

    def kind_hierarchy(self) -> set[str]:
        return self.__resolved_hierarchy

    def property_kind_by_path(self) -> dict[PropertyPath, SimpleKind]:
        if not self.__resolved:
            raise AttributeError(f"property_kind_by_path {self.fqn}: References are not resolved yet!")
        return self.__properties_kind_by_path

    def check_valid(self, obj: JsonElement, **kwargs: bool) -> ValidationResult:
        if isinstance(obj, dict):
            result: Json = {}
            has_coerced = False
            for name, value in obj.items():
                known = self.__resolved_kinds.get(name, None)
                if known:
                    prop, kind = known
                    if value is None:
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
                    pass
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


predefined_kinds = [
    StringKind("string"),
    NumberKind("int32", "int32"),
    NumberKind("int64", "int64"),
    NumberKind("float", "float"),
    NumberKind("double", "double"),
    AnyKind.any(),
    BooleanKind("boolean"),
    DateKind("date"),
    DateTimeKind("datetime"),
    Complex(
        "graph_root",
        [],
        [
            Property("name", "string", False, "The name of this node."),
            Property("tags", "dictionary[string, string]", False, "All attached tags of this node."),
        ],
        allow_unknown_props=True,
    ),
    Complex(
        "predefined_properties",
        [],
        [
            Property("kind", "string", False, "The kind property of every node."),
            Property("ctime", "datetime", False, "datetime when the node has been created."),
            Property("expires", "datetime", False, "datetime when the node expires."),
        ],
    ),
]


class Model:
    @staticmethod
    def empty() -> Model:
        return Model({})

    @staticmethod
    def from_kinds(kinds: list[Kind]) -> Model:
        all_kinds = kinds + predefined_kinds
        kind_dict = {kind.fqn: kind for kind in all_kinds}
        for kind in all_kinds:
            kind.resolve(kind_dict)
        return Model(kind_dict)

    def __init__(self, kinds: dict[str, Kind]):
        self.kinds = kinds
        complexes = (k for k in kinds.values() if isinstance(k, Complex))
        paths: dict[PropertyPath, SimpleKind] = reduce(lambda res, k: res | k.property_kind_by_path(), complexes, {})
        self.__property_kind_by_path = paths

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

    def kind_by_path(self, path_: str) -> SimpleKind:
        path = PropertyPath.from_path(path_)
        if path not in self.__property_kind_by_path:
            # path not known according to known model: it could be anything.
            return AnyKind.any()
        return self.__property_kind_by_path[path]

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

        def handle_complex(cx: Complex) -> None:
            graph.add_node(cx.fqn, data=cx)
            if not cx.is_root():
                for base in cx.bases:
                    graph.add_edge(cx.fqn, base)

        for kind in self.kinds.values():
            if isinstance(kind, Complex):
                handle_complex(kind)
            elif isinstance(kind, ArrayKind) and isinstance(kind.inner, Complex):
                handle_complex(kind.inner)
            elif isinstance(kind, Dictionary) and isinstance(kind.value_kind, Complex):
                handle_complex(kind.value_kind)

        return graph

    def update_kinds(self, kinds: list[Kind]) -> Model:
        def update_is_valid(from_kind: Kind, to_kind: Kind) -> None:
            def hint() -> str:
                return f"Update {from_kind.fqn}"

            # Allowed changes: The update
            # - does not change it's type (e.g. going from SimpleKind to ComplexKind)
            # - no required property is removed or marked as not required
            if type(from_kind) != type(to_kind):  # pylint: disable=unidiomatic-typecheck
                raise AttributeError(f"{hint()} changes an existing property type {from_kind.fqn}")
            elif isinstance(from_kind, Complex) and isinstance(to_kind, Complex):
                for prop in from_kind.properties:
                    if prop.required and (prop.name not in to_kind):
                        raise AttributeError(f"{hint()} existing required property {prop.name} cannot be removed!")
                    elif prop.required and to_kind[prop.name].required is False:
                        raise AttributeError(f"{hint()} existing required property {prop.name} marked as not required!")

        # resolve and build dict
        updates = {kind.fqn: kind for kind in kinds}
        updated = self.kinds | updates
        for kind in kinds:
            kind.resolve(updated)

        # check if updating existing kinds is allowed
        for name in self.kinds.keys() & updates.keys():
            update_is_valid(self.kinds[name], updates[name])

        # check if no property path is overlapping
        def check(all_paths: dict[PropertyPath, SimpleKind], kind: Kind) -> dict[PropertyPath, SimpleKind]:
            if isinstance(kind, Complex):
                paths = kind.property_kind_by_path()
                intersect = paths.keys() & all_paths.keys()

                def simple_kind_incompatible(p: PropertyPath) -> bool:
                    left = paths[p]
                    right = all_paths[p]
                    return (left.fqn != right.fqn) and not (isinstance(left, AnyKind) or isinstance(right, AnyKind))

                # Filter out duplicates that have the same kind or any side is any
                non_unique = list(filter(simple_kind_incompatible, intersect))
                if non_unique:
                    message = ", ".join(f"{a} ({all_paths[a].fqn} -> {paths[a].fqn})" for a in non_unique)
                    raise AttributeError(
                        f"Update not possible. {kind.fqn}: following properties would be non unique having "
                        f"the same path but different type: {message}"
                    )
                return paths | all_paths
            else:
                return all_paths

        reduce(check, updates.values(), reduce(check, self.kinds.values(), {}))  # type: ignore

        return Model(updated)


# register serializer for this class
set_deserializer(Kind.from_json, Kind)
set_serializer(SimpleKind.to_json, SimpleKind)
