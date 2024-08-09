from __future__ import annotations

import os
import re
from collections.abc import Sequence, MutableSequence, Mapping, MutableMapping
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterator, Any, Union, Tuple

from attr import define
from jsons import pascalcase
from prance import ResolvingParser
from prance.util.resolver import RefResolver
from prance.util.url import ResolutionError

from fixlib.json import value_in_path

Json = Dict[str, Any]


def to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


@define
class AzureApiInfo:
    service: str
    version: str
    path: str
    path_parameters: List[str] = []
    query_parameters: List[str] = []
    access_path: Optional[str] = None
    expect_array: bool = False


@define
class AzureProperty:
    name: str
    from_name: Union[str, List[str]]
    type: str
    description: str
    is_array: bool = False
    is_complex: bool = False
    is_complex_dict: bool = False
    field_default: Optional[str] = None
    extractor: Optional[str] = None

    def assignment(self) -> str:
        default = self.field_default or "default=None"
        desc = re.sub("[\n\r'\"]", " ", self.description)  # remove invalid characters
        desc = re.sub("<br\\s*/?>", " ", desc)  # replace <br/> tags
        desc = re.sub("\\s\\s+", " ", desc)  # remove multiple spaces
        metadata = f", metadata={{'description': '{desc}'}}"
        result = f"field({default}{metadata})"
        if (len(result) + len(self.name) + len(self.type_name)) > 100:
            result += "  # fmt: skip"
        return result

    @property
    def is_any(self) -> bool:
        return self.type == "any"

    @property
    def type_name(self) -> str:
        if self.is_any:
            return "Any"

        return ("Azure" + self.type) if (self.is_complex or self.is_complex_dict) else self.type

    def type_string(self) -> str:
        if self.is_array:
            return f"Optional[List[{self.type_name}]]"
        elif self.is_complex_dict:
            return f"Optional[Dict[str, {self.type_name}]]"
        else:
            return f"Optional[{self.type_name}]"

    def mapping(self) -> str:
        # in case an extractor is defined explicitly
        if self.extractor:
            return f'"{self.name}": ' + self.mapping_from()
        return f'"{self.name}": ' + self.mapping_from()

    def mapping_from(self) -> str:
        # in case an extractor is defined explicitly
        if self.extractor:
            return self.extractor
        from_p = self.from_name if isinstance(self.from_name, list) else [self.from_name]
        from_p_path = ",".join(f'"{p}"' for p in from_p)
        base = f"S({from_p_path}"
        if self.is_array and self.is_complex:
            base += f") >> ForallBend({self.type_name}.mapping)"
        elif self.is_array:
            base += ")"
        elif self.is_complex and not self.is_any:
            base += f") >> Bend({self.type_name}.mapping)"
        elif self.is_complex_dict:
            base += f") >> MapDict(value_bender=Bend({self.type_name}.mapping))"
        else:
            base += ")"
        return base


@define
class AzureClassModel:
    spec: AzureRestSpec
    name: str
    props: Dict[str, AzureProperty]
    ignored: Dict[str, AzureProperty]
    aggregate_root: bool
    base_classes: List[str]
    api_info: Optional[AzureApiInfo] = None

    @property
    def class_name(self) -> str:
        return "Azure" + pascalcase(self.name)

    def sorted_props(self) -> List[AzureProperty]:
        return sorted(self.props.values(), key=lambda p: p.name)

    def to_class(self) -> str:
        bases = (["MicrosoftResource"] if self.aggregate_root else []) + [f"Azure{b}" for b in self.base_classes]
        base = ("(" + ", ".join(bases) + ")") if bases else ""
        kind = f'    kind: ClassVar[str] = "azure_{to_snake(self.name)}"'

        api = (
            f"    api_spec: ClassVar[AzureResourceSpec] = AzureResourceSpec{str(self.api_info)[12:]}\n"
            if self.api_info
            else ""
        )

        # add mappings for base properties
        base_mappings: Dict[str, str] = {}
        # tags need a default value
        for bp in ["id", "tags", "name", "ctime", "mtime", "atime"]:
            if bp in self.props or bp in self.ignored:
                base_mappings[bp] = f'S("{bp}")'
            elif bp == "ctime":
                for candidate in ["created_at", "time_created"]:
                    if (p := self.props.get(candidate)) and p.type == "datetime":
                        base_mappings[bp] = p.mapping_from()
                        break
            elif bp == "mtime":
                for candidate in ["last_modified_at"]:
                    if (p := self.props.get(candidate)) and p.type == "datetime":
                        base_mappings[bp] = p.mapping_from()
                        break
            elif bp == "atime":
                for candidate in ["last_accessed_at"]:
                    if (p := self.props.get(candidate)) and p.type == "datetime":
                        base_mappings[bp] = p.mapping_from()
                        break

            if bp not in base_mappings:
                base_mappings[bp] = "K(None)"
            base_mappings["tags"] = "S('tags', default={})"

        # take class hierarchy into account and assemble the mappings
        bmp = " | ".join(f"Azure{base}.mapping" for base in self.base_classes if base != "MicrosoftResource")
        bmp = f"{bmp} | " if bmp else ""
        mapping = f"    mapping: ClassVar[Dict[str, Bender]] = {bmp} {{\n"
        if self.aggregate_root:
            mapping += ",\n".join(f'        "{k}": {v}' for k, v in base_mappings.items())
            mapping += ",\n"
        mapping += ",\n".join(f"        {p.mapping()}" for p in self.sorted_props())
        mapping += "\n    }"
        props = "\n".join(f"    {p.name}: {p.type_string()} = {p.assignment()}" for p in self.sorted_props())
        debug = f"# {self.spec.file}\n" if Debug else ""
        return (
            f"{debug}@define(eq=False, slots=False)\nclass {self.class_name}{base}:\n{kind}\n{api}{mapping}\n{props}\n"
        )


simple_type_map = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
}


def is_complex_type(s: Json) -> bool:
    return (s.get("type") == "object" or "allOf" in s) or "properties" in s


def simple_shape(s: Json) -> Optional[str]:
    if s.get("type") == "string" and s.get("format") == "date-time":
        return "datetime"
    elif spl := simple_type_map.get(s.get("type")):
        return spl
    else:
        return None


def complex_simple_shape(in_shape: Json) -> Optional[Tuple[str, str]]:
    if props := in_shape.get("properties"):
        props = props.copy()
        # in case this shape is complex, but has only property of simple type, return that type
        if len(props) == 1:
            p_name, p_shape = next(iter(props.items()))
            p_simple = simple_shape(p_shape)
            return (p_name, p_simple) if p_simple else None
        else:
            return None


def type_name(s: Json, name_hint: Optional[str] = None) -> str:
    spl = simple_shape(s)
    if spl:
        return spl
    elif "ref" in s:
        return s["ref"]
    elif s.get("type") == "object" and "properties" not in s:
        return "any"
    elif allOf := s.get("allOf"):
        # combine a name of all ingredients
        return "".join(sorted(type_name(a) for a in allOf))
    else:
        name = name_hint or "_".join(s.get("properties", {}))
        return pascalcase(name) if name else "nameless"


ignore_properties = {"name", "id", "type", "location", "tags", "zones"}


def classes_from_model(
    model: Dict[str, AzureRestSpec], allowed_names: Optional[Set[str]] = None
) -> Dict[str, AzureClassModel]:
    result: Dict[str, AzureClassModel] = {}

    for name, spec in model.items():
        if allowed_names and name not in allowed_names:
            continue
        # print("Generate: ", name, spec.file)
        class_method(spec, spec.schema, model, result, ignore_properties, {"properties"}, spec.api_info)

    return result


def class_method(
    spec: AzureRestSpec,
    shape: Json,
    model: Dict[str, AzureRestSpec],
    result: Dict[str, AzureClassModel],
    ignore_properties: Optional[Set[str]] = None,
    unfold_properties: Optional[Set[str]] = None,
    api_info: Optional[AzureApiInfo] = None,
) -> Dict[str, AzureClassModel]:
    ignore_props = ignore_properties or set()
    unfold_props = (unfold_properties or set()) | {"properties"}  # always unfold properties

    def add_types(acs: Dict[str, AzureClassModel]) -> None:
        for k, v in acs.items():
            if k not in result:
                result[k] = v

    if "properties" in shape or "allOf" in shape:
        name = type_name(shape)
        # if name in result:
        #     return {}
        props: Dict[str, AzureProperty] = {}
        bases: List[str] = []
        existing_ignored: Dict[str, AzureProperty] = {}

        def add_prop(ap: AzureProperty) -> None:
            (existing_ignored if ap.name in ignore_props else props)[ap.name] = ap

        for base in shape.get("allOf", []):
            base_type = type_name(base)
            base_defs = class_method(spec, base, model, result)
            if base_type == "Resource":
                # swallow the resource base class
                rd = result["Resource"]
                for p in (rd.props | rd.ignored).values():
                    add_prop(p)

            else:
                bases.append(base_type)
                add_types(base_defs)

        for prop_name, prop_shape in shape.get("properties", {}).items():
            prop = to_snake(prop_name)
            if simple := simple_shape(prop_shape):
                add_prop(AzureProperty(prop, prop_name, simple, prop_shape.get("description", "")))
            elif simple_path := complex_simple_shape(prop_shape):
                inner_name, prop_type = simple_path
                add_prop(AzureProperty(prop, [prop_name, inner_name], prop_type, prop_shape.get("description", "")))
            elif prop_shape.get("type") == "array":
                inner = prop_shape["items"]
                if simple := simple_shape(inner):
                    add_prop(AzureProperty(prop, prop_name, simple, prop_shape.get("description", ""), is_array=True))
                elif simple_path := complex_simple_shape(inner):
                    inner_name, prop_type = simple_path
                    add_prop(
                        AzureProperty(
                            prop,
                            [prop_name, inner_name],
                            prop_type,
                            prop_shape.get("description", ""),
                            is_array=True,
                            extractor=f'S("{prop_name}", default=[]) >> ForallBend(S("{inner_name}"))',
                        )
                    )
                else:
                    add_types(class_method(spec, inner, model, result))
                    add_prop(
                        AzureProperty(
                            prop,
                            prop_name,
                            type_name(inner, prop_name),
                            prop_shape.get("description", ""),
                            is_array=True,
                            is_complex=True,
                        )
                    )
            elif prop_shape.get("additionalProperties") is True:
                for ref in ["full_ref.$ref", "$ref"]:
                    if ref := value_in_path(prop_shape, ref):
                        add_prop(AzureProperty(prop, prop_name, ref, prop_shape.get("description", "")))
                        add_types(class_method(spec, ref, model, result))

            elif isinstance(add_props := prop_shape.get("additionalProperties"), dict):
                extractor: Optional[str] = None
                if simple := simple_shape(add_props):
                    pt = simple
                elif simple_path := complex_simple_shape(add_props):
                    pn, pt = simple_path
                    prop_name = [prop_name, pn]
                    extractor = f'S("{name}") >> MapDict(value_bender=S("{pn}"))'
                else:
                    add_types(class_method(spec, add_props, model, result))
                    pt = "Azure" + type_name(add_props)
                add_prop(
                    AzureProperty(
                        prop, prop_name, f"Dict[str, {pt}]", prop_shape.get("description", ""), extractor=extractor
                    )
                )
            elif is_complex_type(prop_shape):
                add_types(class_method(spec, prop_shape, model, result, set()))
                prop_type = type_name(prop_shape)
                if prop_name in unfold_props and is_complex_type(prop_shape) and prop_type in result:
                    for np in result[prop_type].props.values():
                        add_prop(
                            AzureProperty(
                                np.name,
                                [prop_name] + (np.from_name if isinstance(np.from_name, list) else [np.from_name]),
                                np.type,
                                np.description,
                                is_complex=np.is_complex,
                                is_complex_dict=np.is_complex_dict,
                                is_array=np.is_array,
                                extractor=(f'S("{prop_name}") >> ' + np.extractor) if np.extractor else None,
                            )
                        )

                else:
                    add_prop(
                        AzureProperty(prop, prop_name, prop_type, prop_shape.get("description", ""), is_complex=True)
                    )
            elif prop_shape.get("type") == "object":
                pass  # type object but no properties
            else:
                raise ValueError(f"Unknown property type: {prop_shape}")
        result[name] = AzureClassModel(
            spec, name, props, existing_ignored, api_info is not None, bases, api_info=api_info
        )
    return result


@define
class AzureRestSpec:
    name: str
    api_info: AzureApiInfo
    schema: Json
    file: Path

    @staticmethod
    def parse_spec(service: str, version: str, resolved: Json, file: Path) -> Iterator[AzureRestSpec]:
        for path, path_spec in resolved["paths"].items():
            if "get" in path_spec:
                method = path_spec["get"]
                # ignore any API that doesn't have a 200 response with a schema
                if "200" not in method["responses"] or "schema" not in method["responses"]["200"]:
                    continue
                parameters = method.get("parameters", [])
                required_params = [p for p in parameters if p.get("required", False) is True]
                # api-version and subscriptionId are always there
                param_names = {p["name"] for p in required_params} - {
                    "api-version",
                    "subscriptionId",
                    "location",
                    "scope",
                    # "databaseName",
                    # "serverName",
                    "vaultName",
                    "resourceGroupName",
                }
                if len(param_names) == 0:
                    schema = method["responses"]["200"]["schema"]
                    access_path: Optional[str] = None
                    is_array = False
                    if "properties" in schema:
                        props = list(set(schema["properties"].keys()) - {"nextLink"})
                        if len(props) == 1 and schema["properties"][props[0]].get("type") == "array":
                            value_prop = props[0]
                            access_path = value_prop
                            is_array = True
                            type_definition = schema["properties"][value_prop]["items"]
                        else:
                            type_definition = schema
                    elif schema.get("type") == "array":
                        is_array = True
                        type_definition = schema["items"]
                    else:
                        raise ValueError("Found unknown: ", schema)

                    info = AzureApiInfo(
                        service,
                        version,
                        path,
                        [p["name"] for p in required_params if p["in"] == "path"],
                        [p["name"] for p in required_params if p["in"] == "query"],
                        access_path,
                        is_array,
                    )
                    if ssh := simple_shape(type_definition):
                        yield AzureRestSpec(ssh, info, type_definition, file)
                    elif tdef := type_definition.get("ref"):
                        yield AzureRestSpec(tdef, info, type_definition, file)


class AzureModel:
    def __init__(self, path_to_repo: Path) -> None:
        assert path_to_repo.is_dir()
        self.path_to_spec = path_to_repo / "specification"

    def list_all_specs(self, allowed_services: Optional[Set[str]] = None) -> Iterator[AzureRestSpec]:
        def is_spec_dir(path: Path) -> Dict[str, Path]:
            if path.is_dir():
                return {p.name: p for p in path.iterdir() if p.is_dir() and p.name in ("preview", "stable")}
            return {}

        def walk_dir(service: str, part: Path) -> Iterator[AzureRestSpec]:
            for child in part.iterdir():
                if specs := is_spec_dir(child):
                    for kd in sorted(specs, reverse=True):
                        spec_dir = specs[kd]
                        sub_dir = sorted((d for d in spec_dir.iterdir() if d.is_dir()), reverse=True)
                        spec_by_version = {}
                        for version_path in sub_dir:
                            for file in version_path.iterdir():
                                if file.is_file() and file.name.endswith(".json") and file.name not in spec_by_version:
                                    spec_by_version[file.name] = version_path

                        for file_name, version_path in spec_by_version.items():
                            file = version_path / file_name
                            parsed = ResolvingRefParser(str(file))
                            for aspec in AzureRestSpec.parse_spec(
                                service, version_path.name, parsed.specification, file
                            ):
                                yield aspec
                elif child.is_dir():
                    yield from walk_dir(service, child)

        for srv_spec in self.path_to_spec.iterdir():
            if allowed_services and srv_spec.name not in allowed_services:
                continue
            yield from walk_dir(srv_spec.name, srv_spec)

    def list_specs(self, allowed_services: Optional[Set[str]] = None) -> List[AzureRestSpec]:
        result = {}
        for spec in self.list_all_specs(allowed_services):
            if spec.name in result:  # in case there is a spec with the same name: take the one with less parameters
                spec = min(result[spec.name], spec, key=lambda s: len(s.api_info.path_parameters))
            result[spec.name] = spec
        return list(result.values())


# region keep resolver
class RefKeepResolver(RefResolver):
    def _resolve_partial(self, base_url, partial, recursions):
        changes = dict(tuple(self._dereferencing_iterator(base_url, partial, (), recursions)))
        paths = sorted(changes.keys(), key=len)
        for path in paths:
            value = changes[path]
            if len(path) == 0:
                partial = value
            else:
                # noinspection PyTypeChecker
                path_set(partial, list(path), value, create=True)

        return partial

    def _dereferencing_iterator(self, base_url, partial, path, recursions):
        try:
            yield from super()._dereferencing_iterator(base_url, partial, path, recursions)
        except ResolutionError as e:
            if Debug:
                print(">>>>> Can not parse spec. Ignore: ", e)
            pass


class ResolvingRefParser(ResolvingParser):
    def __init__(self, url=None, spec_string=None, lazy=False, **kwargs):
        self.__reference_cache = {}
        super().__init__(url, spec_string, lazy, **kwargs)

    def _validate(self):
        forward_arg_names = (
            "encoding",
            "recursion_limit",
            "recursion_limit_handler",
            "resolve_types",
            "resolve_method",
            "strict",
        )
        forward_args = {k: v for (k, v) in self.options.items() if k in forward_arg_names}
        resolver = RefKeepResolver(
            self.specification,
            self.url,
            reference_cache=self.__reference_cache,
            recursion_limit=1,
            **forward_args,
        )
        resolver.resolve_references()
        self.specification = resolver.specs

        # do not validate.
        # BaseParser._validate(self)


def path_set(obj, path, value, **options):
    def fill_sequence(seq, index, value_index_type):
        if len(seq) > index:
            return

        while len(seq) < index:
            seq.append(None)

        if value_index_type == int:
            seq.append([])
        elif value_index_type is None:
            seq.append(None)
        else:
            seq.append({})

    def safe_idx(seq, index):
        try:
            return type(seq[index])
        except IndexError:
            return None

    if path is not None and not isinstance(path, Sequence):
        raise TypeError(f"Path is a {type(path)}, but must be None or a Collection!")

    if len(path) < 1:
        raise KeyError("Cannot set with an empty path!")

    if isinstance(obj, Mapping):
        # If we don't have a mutable mapping, we should raise a TypeError
        if not isinstance(obj, MutableMapping):  # pragma: nocover
            raise TypeError(f"Mapping is not mutable: {type(obj)}")

        if len(path) == 1:
            if isinstance(value, MutableMapping):
                existing = obj.get(path[0])
                if isinstance(existing, MutableMapping) and "$ref" in existing:
                    value["ref"] = existing["$ref"].split("/")[-1]
                else:
                    value["ref"] = existing
                value["full_ref"] = existing
            obj[path[0]] = value
        else:
            if path[0] not in obj:
                if type(path[1]) is int:
                    obj[path[0]] = []
                else:
                    obj[path[0]] = {}
            path_set(obj[path[0]], path[1:], value)

        return obj

    elif isinstance(obj, Sequence):
        idx = path[0]

        # If we don't have a mutable sequence, we should raise a TypeError
        if not isinstance(obj, MutableSequence):
            raise TypeError(f"Sequence is not mutable: {type(obj)}")

        # Ensure integer indices
        try:
            idx = int(idx)
        except ValueError:
            raise KeyError("Sequences need integer indices only.")

        fill_sequence(obj, idx, safe_idx(path, 1))

        if len(path) == 1:
            if isinstance(value, MutableMapping):
                existing = obj[idx]
                if isinstance(existing, MutableMapping) and "$ref" in existing:
                    value["ref"] = existing["$ref"].split("/")[-1]
                else:
                    value["ref"] = existing
                value["full_ref"] = existing

            obj[idx] = value
        else:
            path_set(obj[idx], path[1:], value)

        return obj
    else:
        raise TypeError(f"Cannot set anything on type {type(obj)}!")


# endregion

# To run this script, make sure you have fix venv plus: pip install "prance[osv,cli]"
Debug = False
if __name__ == "__main__":
    specs_path = os.environ.get("AZURE_REST_API_SPECS", "../../../../azure-rest-api-specs")
    assert specs_path, (
        "AZURE_REST_API_SPECS need to be defined! "
        "Checkout https://github.com/Azure/azure-rest-api-specs and set path in env"
    )
    model = AzureModel(Path(specs_path))
    shapes = {spec.name: spec for spec in sorted(model.list_specs({"resources"}), key=lambda x: x.name)}
    models = classes_from_model(shapes)
    for model in models.values():
        if model.name != "Resource":
            print(model.to_class())
