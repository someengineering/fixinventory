from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone, date
from functools import reduce
from json import JSONDecodeError
from re import compile
from typing import List, Union, Dict, Any, Optional, Set, Callable

from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from durations_nlp import Duration
from jsons import set_deserializer, set_serializer
from networkx import DiGraph

from core.model.typed_model import from_js
from core.util import if_set

Json = Dict[str, Any]

ValidationResult = Optional[Any]
ValidationFn = Callable[[Any], ValidationResult]


def check_type_fn(t: type, type_name: str) -> ValidationFn:
    def check_type(x) -> ValidationResult:
        if isinstance(x, t):
            return None
        else:
            raise AttributeError(f"Expected type {type_name} but got {type(x).__name__}")

    return check_type


def check_fn(x: Optional[Any], func: Callable[[Any, Any], Optional[Any]], message: str):
    def check_single(value) -> ValidationResult:
        if func(x, value):
            return None
        else:
            raise AttributeError(f">{value}< {message}")

    return None if x is None else check_single


def validate_fn(*fns: Optional[ValidationFn]) -> ValidationFn:
    defined = list(filter(lambda x: x is not None, fns))

    def always_valid(_):
        return None

    def check_defined(value):
        for fn in defined:
            res = fn(value)
            if res is not None:
                return res
        return None

    return check_defined if defined else always_valid


class Property:
    def __init__(self, name: str, kind: str, required: bool = False, description: str = None):
        self.name = name
        self.kind = kind
        self.required = required
        self.description = description


class Internal:
    pass


class Kind(ABC):
    def __init__(self, fqn: str):
        self.fqn = fqn

    @abstractmethod
    def check_valid(self, obj, **kwargs) -> ValidationResult:
        pass

    def resolve(self, model: dict):
        pass

    def kind_hierarchy(self) -> List[str]:
        return [self.fqn]

    def package(self) -> Optional[str]:
        return self.fqn.rsplit(".", 1)[0] if "." in self.fqn else None

    # noinspection PyUnusedLocal
    @staticmethod
    def from_json(js: dict, _: type = object, **kwargs):
        if "fqn" in js and "properties" in js:
            props = list(map(lambda prop: from_js(prop, Property), js["properties"]))
            return Complex(js["fqn"], js.get("base"), props)
        elif "inner" in js:
            inner = Kind.from_json(js["inner"])
            return Array(inner)
        elif "fqn" in js and "runtime_kind" in js and js["runtime_kind"] in SimpleKind.Kind_to_type:
            fqn = js["fqn"]
            rk = js["runtime_kind"]
            if rk == "string":
                minimum = js.get("min_length")
                maximum = js.get("max_length")
                p = js.get("pattern")
                e = js.get("enum")
                return StringKind(fqn, minimum, maximum, p, e)
            elif rk == "int32" or rk == "int64" or rk == "float" or rk == "double":
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
        else:
            raise JSONDecodeError("Given type can not be read.", json.dumps(js), 0)


class SimpleKind(Kind, ABC):
    def __init__(self, fqn: str, runtime_kind: str):
        self.fqn = fqn
        super().__init__(fqn)
        self.runtime_kind = runtime_kind
        self.__runtime_type: type = self.Kind_to_type[runtime_kind]

    Kind_to_type = {
        "string": str,
        "int32": int,
        "int64": int,
        "float": float,
        "double": float,
        "boolean": bool,
        "date": str,
        "datetime": str
    }

    # noinspection PyMethodMayBeStatic
    def coerce(self, value) -> object:
        return value

    def as_json(self) -> Json:
        return {"fqn": self.fqn, "runtime_kind": self.runtime_kind}

    # noinspection PyUnusedLocal
    @staticmethod
    def to_json(obj, **kw_args):
        return obj.as_json()


class StringKind(SimpleKind):
    def __init__(self,
                 fqn: str,
                 min_length: Optional[int] = None,
                 max_length: Optional[int] = None,
                 pattern: Optional[str] = None,
                 enum: Optional[Set[str]] = None
                 ):
        super().__init__(fqn, "string")
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.pattern_compiled = if_set(pattern, lambda x: compile(x))
        self.enum = enum
        self.valid_fn = validate_fn(
            check_type_fn(str, "string"),
            check_fn(self.pattern_compiled, lambda p, obj: p.fullmatch(obj) is not None,
                     f"does not conform to regex: {self.pattern}"),
            check_fn(self.enum, lambda x, obj: obj in x, f"should be one of: {self.enum}"),
            check_fn(self.min_length, lambda x, obj: len(obj) >= x, f"does not have minimal length: {self.min_length}"),
            check_fn(self.max_length, lambda x, obj: len(obj) <= x, f"is too long! Allowed: {self.max_length}")
        )

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value) -> object:
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

    def __init__(self,
                 fqn: str,
                 runtime_kind: str,
                 minimum: Union[None, float, int] = None,
                 maximum: Union[None, float, int] = None,
                 enum: Optional[Set[Union[float, int]]] = None
                 ):
        super().__init__(fqn, runtime_kind)
        self.minimum = minimum
        self.maximum = maximum
        self.enum = enum
        self.valid_fn = validate_fn(
            check_type_fn(int, "int") if runtime_kind == "int" else self.check_float,
            check_fn(self.enum, lambda x, obj: obj in x, f"should be one of: {self.enum}"),
            check_fn(self.minimum, lambda x, obj: obj >= x, f"should be greater or equals than: {self.minimum}"),
            check_fn(self.maximum, lambda x, obj: obj <= x, f"should be smaller or equals than: {self.maximum}")
        )

    @staticmethod
    def check_float(obj):
        if isinstance(obj, float) or isinstance(obj, int):
            return None
        else:
            raise AttributeError(f"Expected number but got {obj}")

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value) -> object:
        if isinstance(value, int) or isinstance(value, float):
            return value
        else:
            return float(value)

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

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value) -> object:
        if isinstance(value, bool):
            return value
        else:
            return str(value).lower() == "true"


class DateTimeKind(SimpleKind):
    Format = '%Y-%m-%dT%H:%M:%SZ'
    DateTimeRe = re.compile('\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z')
    DurationRe = re.compile('^[+-]?[\\d.]+([smhdwMy]|second|minute|hour|day|week|month|year)s?$')

    def __init__(self, fqn: str):
        super().__init__(fqn, "datetime")
        self.valid_fn = validate_fn(
            check_type_fn(str, "datetime"),
            self.check_datetime
        )

    @staticmethod
    def parse_datetime(date_string: str) -> Optional[datetime]:
        try:
            return datetime.strptime(date_string, DateTimeKind.Format)
        except ValueError:
            return None

    @staticmethod
    def check_datetime(obj) -> ValidationResult:
        def parse_datetime():
            parsed = datetime.fromisoformat(str(obj))
            utc_parsed = datetime.fromtimestamp(parsed.timestamp(), tz=timezone.utc)
            return utc_parsed.strftime(DateTimeKind.Format)

        return None if DateTimeKind.DateTimeRe.fullmatch(obj) else parse_datetime()

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value) -> str:
        try:
            if self.DurationRe.fullmatch(value):
                # in case of duration, compute the timestamp as: now + duration
                delta = relativedelta(seconds=Duration(value).seconds)
                instant = datetime.now(timezone.utc) + delta
                return instant.strftime(DateTimeKind.Format)
            else:
                dt = datetime.fromtimestamp(parse(value).timestamp(), timezone.utc)
                return dt.strftime(DateTimeKind.Format)
        except Exception:
            raise AttributeError(f"Expected datetime but got: >{value}<")


class DateKind(SimpleKind):
    Format = '%Y-%m-%d'
    DateRe = re.compile('\\d{4}-\\d{2}-\\d{2}')

    def __init__(self, fqn: str):
        super().__init__(fqn, "date")
        self.valid_fn = validate_fn(
            check_type_fn(str, "date"),
            self.check_date
        )

    @staticmethod
    def check_date(obj) -> ValidationResult:
        return None if DateKind.DateRe.fullmatch(obj) else date.fromisoformat(obj)

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        return self.valid_fn(obj)

    def coerce(self, value) -> str:
        try:
            if DateTimeKind.DurationRe.fullmatch(value):
                # in case of duration, compute the timestamp as: today + duration
                delta = relativedelta(seconds=Duration(value).seconds)
                at = date.today() + delta
                return at.isoformat()
            else:
                return parse(value).date().strftime(DateKind.Format)
        except Exception:
            raise AttributeError(f"Expected date but got: >{value}<")


class Array(Kind):
    def __init__(self, inner: Kind):
        super().__init__(f"{inner.fqn}[]")
        self.inner = inner

    def resolve(self, model):
        self.inner.resolve(model)

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        if not isinstance(obj, list):
            raise AttributeError("Expected property is not an array!")

        def check(item):
            nonlocal has_coerced
            res = self.inner.check_valid(item, **kwargs)
            if res is None:
                return item
            else:
                has_coerced = True
                return res.value

        has_coerced = False
        mapped = [check(elem) for elem in obj]
        return mapped if has_coerced else None


class ComplexBase(Kind):
    def __init__(self, fqn: str, base: Union[str, None], properties: List[Property], allow_unknown_props: bool):
        super().__init__(fqn)
        self.base = base
        self.properties = properties
        self.allow_unknown_props = allow_unknown_props
        self.__prop_by_name = {prop.name: prop for prop in properties}
        self.__resolved = False
        self.__resolved_base: Optional[Kind] = None
        self.__resolved_kinds: Dict[str, Kind] = dict()
        self.__all_props = list(self.properties)
        self.__resolved_hierarchy = [fqn]
        self.__properties_kind_by_path: Dict[str, SimpleKind] = dict()

    def resolve(self, model: Dict[str, Kind]):
        if not self.__resolved:
            # resolve properties
            for prop in self.properties:
                kind_name, is_array = (prop.kind[:-2], True) if prop.kind.endswith("[]") else (prop.kind, False)
                if kind_name not in model:
                    raise AttributeError(f"Property kind is not known: {kind_name}. Have you registered it?")
                kind = model[kind_name]
                kind.resolve(model)
                self.__resolved_kinds[prop.name] = Array(kind) if is_array else kind

            # property path -> kind
            self.__properties_kind_by_path = self.__resolve_property_paths()

            # resolve the hierarchy
            if self.base is not None and not self.is_root():
                base: Kind = model[self.base]
                base.resolve(model)
                if isinstance(base, StringDict):
                    raise TypeError("Can not inherit from simple dictionary!")
                elif isinstance(base, ComplexBase):
                    self.__resolved_base = base
                    self.__resolved_kinds |= base.__resolved_kinds
                    self.__all_props += base.__all_props
                    self.__prop_by_name = {prop.name: prop for prop in self.__all_props}
                    self.__resolved_hierarchy = base.__resolved_hierarchy + [self.fqn]
                    self.__properties_kind_by_path |= base.__properties_kind_by_path
        self.__resolved = True

    def __resolve_property_paths(self, from_path: str = "") -> Dict[str, SimpleKind]:
        def path_for(kind, path, array: bool = False) -> Dict[str, SimpleKind]:
            root = "" if path == "" else f"{path}."
            arr = "[]" if array else ""
            if isinstance(kind, SimpleKind):
                return {f"{root}{x.name}{arr}": kind}
            elif isinstance(kind, Array):
                return path_for(kind.inner, root, True)
            elif isinstance(kind, ComplexBase):
                return kind.__resolve_property_paths(f"{root}{x.name}{arr}")
            else:
                return {}

        result: Dict[str, SimpleKind] = {}
        for x in self.properties:
            result |= path_for(self.__resolved_kinds[x.name], from_path)

        return result

    def __contains__(self, name):
        return name in self.__prop_by_name

    def __getitem__(self, name):
        return self.__prop_by_name[name]

    def is_root(self) -> bool:
        return self.base is None or self.base == self.fqn

    def kind_hierarchy(self) -> List[str]:
        return self.__resolved_hierarchy

    def property_kind_by_path(self) -> Dict[str, SimpleKind]:
        if not self.__resolved:
            raise AttributeError(f"property_kind_by_path {self.fqn}: References are not resolved yet!")
        return self.__properties_kind_by_path

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        if isinstance(obj, dict):
            result = {}
            has_coerced = False
            for prop, value in obj.items():
                if prop in self.__resolved_kinds:
                    try:
                        coerced = self.__resolved_kinds[prop].check_valid(value, **kwargs)
                        has_coerced |= coerced is not None
                        result[prop] = coerced if coerced is not None else value
                    except AttributeError as at:
                        raise AttributeError(f"Kind:{self.fqn} Property:{prop} is not valid: {at}: {json.dumps(obj)}")
                elif not self.allow_unknown_props:
                    raise AttributeError(f"Kind:{self.fqn} Property:{prop} is not defined in model!")
            if not kwargs.get('ignore_missing'):
                for prop in self.__all_props:
                    if prop.required and prop.name not in obj:
                        raise AttributeError(
                            f"Kind:{self.fqn} Property:{prop.name} is required and missing in {json.dumps(obj)}")
            return result if has_coerced else None
        else:
            raise AttributeError("Kind:{self.fqn} expected a complex type but got this: {obj}")


class Complex(ComplexBase):
    def __init__(self, fqn: str, base: Union[str, None], properties: List[Property]):
        super().__init__(fqn, base, properties, False)


class StringDict(ComplexBase, Internal):
    def __init__(self, fqn: str):
        super().__init__(fqn, None, [], True)

    def check_valid(self, obj, **kwargs) -> ValidationResult:
        if isinstance(obj, dict):
            for prop, value in obj.items():
                if not isinstance(prop, str) or not isinstance(value, str):
                    raise AttributeError(f"dictionary allows for simple key/value strings, but got {prop}:{value}")
        return None


predefined_kinds = [
    StringKind("string"),
    NumberKind("int32", "int32"),
    NumberKind("int64", "int64"),
    NumberKind("float", "float"),
    NumberKind("double", "double"),
    BooleanKind("boolean"),
    DateKind("date"),
    DateTimeKind("datetime"),
    StringDict("dictionary"),
    Complex("graph_root", None, [
        Property("kind", "string", True, "Kind of this node."),
        Property("name", "string", False, "The name of this node."),
        Property("label", "string", False, "The label of this node."),
        Property("tags", "dictionary", False, "All attached tags of this node.")
    ])
]


class Model:

    @staticmethod
    def empty():
        return Model({})

    @staticmethod
    def from_kinds(kinds: List[Kind]):
        all_kinds = kinds + predefined_kinds
        kind_dict = {kind.fqn: kind for kind in all_kinds}
        for kind in all_kinds:
            kind.resolve(kind_dict)
        return Model(kind_dict)

    def __init__(self, kinds: Dict[str, Kind]):
        self.kinds = kinds
        complexes = (k for k in kinds.values() if isinstance(k, ComplexBase))
        paths: Dict[str, SimpleKind] = reduce(lambda res, k: res | k.property_kind_by_path(), complexes, {})
        self.property_kind_by_path = paths

    def __contains__(self, name_or_object: Union[str, Json]):
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

    def kind_by_path(self, path: str):
        if path not in self.property_kind_by_path:
            raise AttributeError(f"Query contains a predicate path {path} which is not defined in the model!")
        return self.property_kind_by_path[path]

    def check_valid(self, js: Json, **kwargs) -> ValidationResult:
        try:
            kind = self[js["kind"]]
            return kind.check_valid(js, **kwargs)
        except KeyError:
            raise AttributeError(f'No kind definition found for {js["kind"]}' if "kind" in js
                                 else f'No attribute kind found in {js}')

    def graph(self) -> DiGraph:
        graph = DiGraph()

        def handle_complex(base: ComplexBase):
            graph.add_node(base.fqn, data=base)
            if not base.is_root():
                graph.add_edge(base.fqn, base.base)

        for kind in self.kinds.values():
            if isinstance(kind, ComplexBase) and not isinstance(kind, Internal):
                handle_complex(kind)
        return graph

    def update_kinds(self, kinds: List[Kind]) -> Model:
        def update_is_valid(from_kind: Kind, to_kind: Kind):
            def hint():
                return f"Update {from_kind.fqn}"
            # Allowed changes: The update
            # - does not change it's type (e.g. going from SimpleKind to ComplexKind)
            # - no required property is removed or marked as not required
            if type(from_kind) != type(to_kind):
                raise AttributeError(f"{hint()} changes an existing property type {from_kind.fqn}")
            elif isinstance(from_kind, ComplexBase) and isinstance(to_kind, ComplexBase):
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
        def check(all_paths: dict, kind: Kind):
            if isinstance(kind, ComplexBase):
                paths = kind.property_kind_by_path()
                intersect = paths.keys() & all_paths.keys()
                # Filter out duplicates that have the same kind
                non_unique = list(filter(lambda k: paths[k].fqn != all_paths[k].fqn, intersect))
                if non_unique:
                    message = ", ".join(non_unique)
                    raise AttributeError(f"Update not possible. Following properties would be non unique having "
                                         f"the same path but different type: {message}")
                return paths | all_paths
            else:
                return all_paths

        reduce(check, updates.values(), reduce(check, self.kinds.values(), {}))

        return Model(updated)


# register serializer for this class
set_deserializer(Kind.from_json, Kind)
set_serializer(SimpleKind.to_json, SimpleKind)
