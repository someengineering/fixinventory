import json
import re
from typing import Union, List, Optional, Tuple, Dict, Any, Set

from attr import define
from google.auth.credentials import AnonymousCredentials
from googleapiclient import discovery
from googleapiclient.discovery import Resource

from fix_plugin_gcp.utils import MemoryCache


def to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


@define
class GcpProperty:
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
        return f"field({default})"

    def type_string(self) -> str:
        if self.is_array:
            return f"Optional[List[{self.type}]]"
        elif self.is_complex_dict:
            return f"Optional[Dict[str, {self.type}]]"
        else:
            return f"Optional[{self.type}]"

    def mapping(self) -> str:
        # in case an extractor is defined explicitly
        if self.extractor:
            return f'"{self.name}": {self.extractor}'
        from_p = self.from_name if isinstance(self.from_name, list) else [self.from_name]
        from_p_path = ",".join(f'"{p}"' for p in from_p)
        base = f'"{self.name}": S({from_p_path}'
        if self.is_array and self.is_complex:
            base += f", default=[]) >> ForallBend({self.type}.mapping)"
        elif self.is_array:
            base += ", default=[])"
        elif self.is_complex:
            base += f", default={{}}) >> Bend({self.type}.mapping)"
        elif self.is_complex_dict:
            base += f", default={{}}) >> MapDict(value_bender=Bend({self.type}.mapping))"
        else:
            base += ")"

        return base


@define
class GcpApiInfo:
    service: str
    version: str
    action_path: List[str]
    action: str
    response_path: str
    required_params_definition: Dict[str, Any]
    response_regional_sub_path: Optional[str] = None

    def required_params(self) -> Dict[str, str]:
        return {k: known_api_parameters[self.service][k] for k in self.required_params_definition}

    def request_params(self) -> Set[str]:
        return {p for param in self.required_params().values() for p in re.findall(r"(?<={)([^}]+)", param)}


@define
class GcpModel:
    name: str
    props: List[GcpProperty]
    aggregate_root: bool
    base_class: Optional[str] = None
    api_info: Optional[GcpApiInfo] = None

    def roundtrip_test(self) -> str:
        return (
            f"def test_{to_snake(self.name)}(random_builder: GraphBuilder) -> None:\n"
            f"  roundtrip({self.name}, random_builder)"
        )

    def to_class(self) -> str:
        bc = ", " + self.base_class if self.base_class else ""
        base = f"(GcpResource{bc}):" if self.aggregate_root else ":"
        kind = f'    kind: ClassVar[str] = "gcp_{to_snake(self.name[3:])}"'

        if self.aggregate_root and self.api_info:
            a = self.api_info
            sub_path = f'"{a.response_regional_sub_path}"' if a.response_regional_sub_path else "None"
            param_set = "{" + ", ".join(f'"{p}"' for p in a.request_params()) + "}" if a.request_params() else "set()"
            api = (
                f'    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(service="{a.service}", version="{a.version}", '
                f"accessors={json.dumps(a.action_path)}, "
                f'action="{a.action}", '
                f"request_parameter={a.required_params()}, "
                f"request_parameter_in={param_set}, "
                f'response_path="{a.response_path}", '
                f"response_regional_sub_path={sub_path})\n"
            )
        else:
            api = ""
        base_mapping = {
            "id": 'S("name").or_else(S("id")).or_else(S("selfLink"))',
            "tags": 'S("labels", default={})',
            "name": 'S("name")',
            "ctime": 'S("creationTimestamp")',
            "description": 'S("description")',
            "link": 'S("selfLink")',
            "label_fingerprint": 'S("labelFingerprint")',
            "deprecation_status": 'S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping)',
        }
        mapping = "    mapping: ClassVar[Dict[str, Bender]] = {\n"
        if self.aggregate_root:
            mapping += ",\n".join(f'        "{k}": {v}' for k, v in base_mapping.items())
            mapping += ",\n"
        mapping += ",\n".join(f"        {p.mapping()}" for p in self.props)
        mapping += "\n    }"
        props = "\n".join(f"    {p.name}: {p.type_string()} = {p.assignment()}" for p in self.props)
        return f"@define(eq=False, slots=False)\nclass {self.name}{base}\n{kind}\n{api}{mapping}\n{props}\n"


Shape = Dict[str, Any]

simple_type_map = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
}

ignore_root = {
    "labels",
    "selfLink",
    "creationTimestamp",
    "labelFingerprint",
    "id",
    "name",
    "region",
    "zone",
    "description",
    "deprecated",
}
ignore_always = {"kind"}


def clazz_model(
    model: Dict[str, Shape],
    shape: Shape,
    visited: Set[str],
    prop_hint: Optional[str] = None,
    prefix: Optional[str] = None,
    prop_prefix: Optional[str] = None,
    clazz_name: Optional[str] = None,
    base_class: Optional[str] = None,
    aggregate_root: bool = False,
    api_info: Optional[GcpApiInfo] = None,
) -> List[GcpModel]:
    def type_name_of(gcp_name: str) -> str:
        return f"Gcp{prefix if prefix is not None else api_info.service.capitalize()}{gcp_name}"

    def type_name(s: Shape, no_name_hint: Optional[str] = None) -> str:
        spl = simple_shape(s)
        # if we can not find a name in the shape, we use the hint
        name = s.get("$ref", s.get("id", no_name_hint.capitalize() if no_name_hint else "Unknown"))
        return spl if spl else type_name_of(name)

    def simple_shape(s: Shape) -> Optional[str]:
        if s.get("type") == "string" and (
            s.get("format") == "google-datetime"
            or s.get("format") == "date-time"
            or "RFC3339" in s.get("description", "")
        ):
            return "datetime"
        elif spl := simple_type_map.get(s.get("type")):
            return spl
        else:
            return None

    def complex_simple_shape(in_shape: Shape) -> Optional[Tuple[str, str]]:
        # resolve reference
        s = model[in_shape["$ref"]] if in_shape.get("$ref") is not None else in_shape
        shape_props = s.get("properties", {}).copy()
        for ignore in ignore_always:
            shape_props.pop(ignore, None)

        # in case this shape is complex, but has only property of simple type, return that type
        if len(shape_props) == 1:
            p_name, p_shape = next(iter(shape_props.items()))
            p_simple = simple_shape(p_shape)
            return (p_name, p_simple) if p_simple else None
        else:
            return None

    if type_name(shape, prop_hint) in visited:
        return []
    visited.add(type_name(shape, prop_hint))
    result: List[GcpModel] = []
    props = []
    prefix = prefix or ""
    prop_prefix = prop_prefix or ""
    if "type" not in shape and "$ref" in shape:
        # in case we have a reference to another shape, we use that shape
        shape = model[shape["$ref"]]
    if shape.get("type") == "object":
        for name, prop_shape in shape.get("properties", {}).items():
            if name in ignore_always:
                continue
            if aggregate_root and name in ignore_root:
                continue
            prop = to_snake(name)
            if simple := simple_shape(prop_shape):
                props.append(GcpProperty(prop_prefix + prop, name, simple, prop_shape.get("description", "")))
            elif prop_shape.get("type") == "array":
                inner = prop_shape["items"]
                if simple := simple_shape(inner):
                    props.append(
                        GcpProperty(prop_prefix + prop, name, simple, prop_shape.get("description", ""), is_array=True)
                    )
                elif simple_path := complex_simple_shape(inner):
                    prop_name, prop_type = simple_path
                    props.append(
                        GcpProperty(
                            prop_prefix + prop,
                            [name, prop_name],
                            prop_type,
                            prop_shape.get("description", ""),
                            is_array=True,
                            extractor=f'S("{name}", default=[]) >> ForallBend(S("{prop_name}"))',
                        )
                    )
                else:
                    result.extend(clazz_model(model, inner, visited, name, prefix, api_info=api_info))
                    props.append(
                        GcpProperty(
                            prop_prefix + prop,
                            name,
                            type_name(inner, name),
                            prop_shape.get("description", ""),
                            is_array=True,
                            is_complex=True,
                        )
                    )
            elif prop_shape.get("$ref") is not None:
                if maybe_simple := complex_simple_shape(prop_shape):
                    s_prop_name, s_prop_type = maybe_simple
                    props.append(
                        GcpProperty(
                            prop_prefix + prop, [name, s_prop_name], s_prop_type, prop_shape.get("description", "")
                        )
                    )
                else:
                    result.extend(
                        clazz_model(model, model[prop_shape["$ref"]], visited, name, prefix, api_info=api_info)
                    )
                    props.append(
                        GcpProperty(
                            prop_prefix + prop,
                            name,
                            type_name(prop_shape, name),
                            prop_shape.get("description", ""),
                            is_complex=True,
                        )
                    )
            elif (
                prop_shape.get("type") == "object"
                and prop_shape.get("additionalProperties", {}).get("type") == "string"
            ):
                props.append(GcpProperty(prop_prefix + prop, name, "Dict[str, str]", prop_shape.get("description", "")))
            elif (
                prop_shape.get("type") == "object"
                and (ref := prop_shape.get("additionalProperties", {}).get("$ref")) is not None
            ):
                result.extend(clazz_model(model, model[ref], visited, name, prefix, api_info=api_info))
                props.append(
                    GcpProperty(
                        prop_prefix + prop,
                        name,
                        type_name_of(ref),
                        prop_shape.get("description", ""),
                        is_complex_dict=True,
                    )
                )
            elif (
                prop_shape.get("type") == "object"
                and prop_shape.get("properties")
                or prop_shape.get("additionalProperties")
            ):
                result.extend(clazz_model(model, prop_shape, visited, name, prefix, api_info=api_info))
                props.append(
                    GcpProperty(
                        prop_prefix + prop,
                        name,
                        type_name(prop_shape, name),
                        prop_shape.get("description", ""),
                        is_complex=True,
                    )
                )
            elif prop_shape.get("type") == "any":
                props.append(GcpProperty(prop_prefix + prop, name, "Any", prop_shape.get("description", "")))
            else:
                raise NotImplementedError(f"Unsupported shape: \n{prop_shape}\nFull Shape: \n{shape}\n")

        clazz_name = clazz_name if clazz_name else type_name(shape, prop_hint)
        result.append(GcpModel(clazz_name, props, aggregate_root, base_class, api_info))
    return result


@define
class GcpFixModel:
    # is_global: bool
    # resource_action_path: List[str]  # path to the resource action
    # resource_action: str  # action to perform on the client
    # result_property: str  # this property holds the resulting list
    result_shape: str  # the shape of the result according to the service specification
    prefix: Optional[str] = None  # prefix for the resources
    prop_prefix: Optional[str] = None  # prefix for the attributes
    name: Optional[str] = None  # name of the clazz - uses the shape name by default
    base: Optional[str] = None  # the base class to use, BaseResource otherwise
    api_info: Optional[GcpApiInfo] = None  # the api info to use for the resource

    def class_model(self, shapes: Dict[str, Shape], visited: Set[str]) -> List[GcpModel]:
        # Toggle flag if the resource class properties should be prefixed or not
        prop_prefix = self.prop_prefix if False else None
        return clazz_model(
            shapes,
            shapes[self.result_shape],
            visited,
            aggregate_root=True,
            clazz_name=self.name,
            base_class=self.base,
            prop_prefix=prop_prefix,
            prefix=self.prefix,
            api_info=self.api_info,
        )


prefix_map = {}


def adjust_prefix(name: str) -> str:
    if name in prefix_map:
        return prefix_map[name]
    parts = name.split("_")
    if len(parts) > 1:
        return parts[-1]
    return name


# noinspection PyProtectedMember
def generate_models(
    service: str, version: str, client: Resource, prefix: Optional[str], ignore: List[str]
) -> List[GcpFixModel]:
    schemas: Dict[str, Shape] = client._rootDesc["schemas"]

    def result_prop(shape: Shape) -> Tuple[str, str]:
        for name, prop in shape["properties"].items():
            if prop.get("type") == "array" and (ref := prop.get("items", {}).get("$ref")) is not None:
                return name, ref

        raise ValueError(f"Could not find result property in shape: {shape}")

    def resource_models(path: List[str], desc: Shape) -> Optional[GcpFixModel]:
        if "aggregatedList" in desc["methods"]:
            method = desc["methods"]["aggregatedList"]
            response = schemas[method["response"]["$ref"]]
            required_parameters = {p: pd for p, pd in method["parameters"].items() if pd.get("required", False)}
            list_kind = response["properties"]["items"]["additionalProperties"]["$ref"]
            op = next(iter(set(schemas[list_kind]["properties"].keys()) - {"warning"}))
            resource_list_kind = schemas[list_kind]["properties"][op]
            resource_kind = resource_list_kind["items"]["$ref"]
            return GcpFixModel(
                resource_kind,
                prefix,
                adjust_prefix(to_snake(resource_kind)) + "_",
                api_info=GcpApiInfo(service, version, path, "aggregatedList", "items", required_parameters, op),
            )
        elif "list" in desc["methods"]:
            method = desc["methods"]["list"]
            response = schemas[method["response"]["$ref"]]
            required_parameters = {p: pd for p, pd in method["parameters"].items() if pd.get("required", False)}
            prop, kind = result_prop(response)
            return GcpFixModel(
                kind,
                prefix,
                adjust_prefix(to_snake(kind)) + "_",
                api_info=GcpApiInfo(service, version, path, "list", prop, required_parameters),
            )
        else:
            # print(">>>> NO LIST FOR", resource, " ", list(desc["methods"].keys()))
            return None

    def models(path: List[str], schemas: Dict[str, Any]) -> List[GcpFixModel]:
        result = []
        for resource, desc in schemas.items():
            if "methods" in desc:
                if res := resource_models(path + [resource], desc):
                    if res.result_shape not in ignore:
                        result.append(res)
            if "resources" in desc:
                result.extend(models(path + [resource], desc["resources"]))
        return result

    def reduce_global_models(all_models: List[GcpFixModel]) -> List[GcpFixModel]:
        # There are multiple APIs to get the same resource
        # Example backend services can be listed on project level or in any region:
        #     backendServices.aggregatedList :  {'project'}
        #     regionBackendServices.list :  {'project', 'region'}
        # We prefer to use the global API if possible
        model_by_shape = {}
        for m in all_models:
            if m.api_info and (existing := model_by_shape.get(m.result_shape)):
                ex_action = existing.api_info.action_path[-1]
                m_action = m.api_info.action_path[-1]
                # the name of either action should be either regionXXX or globalXXX
                ex_reg_glob = ex_action.startswith("region") or ex_action.startswith("global")
                m_reg_glob = m_action.startswith("region") or m_action.startswith("global")
                # the name of one action needs to be included in the other
                is_included = ex_action.lower() in m_action.lower() or m_action.lower() in ex_action.lower()
                if is_included and (ex_reg_glob or m_reg_glob):
                    # same shape, one is region/global and one action name is included in the other
                    if existing.api_info.request_params() > m.api_info.request_params():
                        # print(f"Replace {ex_action}.{existing.api_info.action} with {m_action}.{m.api_info.action}")
                        model_by_shape[m.result_shape] = m
                    elif m.api_info.action == "aggregatedList":
                        # print(f"Replace {ex_action}.{existing.api_info.action} with {m_action}.{m.api_info.action}")
                        model_by_shape[m.result_shape] = m
                    else:
                        # print(f"Keep {ex_action}.{existing.api_info.action} instead {m_action}.{m.api_info.action}")
                        pass  # keep
            else:
                model_by_shape[m.result_shape] = m
        return list(model_by_shape.values())

    return reduce_global_models(models([], client._resourceDesc["resources"]))


def generate_class_models() -> Dict[str, List[GcpModel]]:
    # mark those classes as visited, since they are predefined in base.py
    visited = {"GcpRegion", "GcpZone", "GcpProject", "GcpQuota", "GcpDeprecationStatus"}
    result: Dict[str, List[GcpModel]] = {}
    for service, version, prefix, ignore in apis:
        client = discovery.build(service, version, credentials=AnonymousCredentials(), cache=MemoryCache())
        schemas: Dict[str, Shape] = client._rootDesc["schemas"]
        models = generate_models(service, version, client, prefix, ignore)
        result[service] = [clazz for model in models for clazz in model.class_model(schemas, visited)]
    return result


def generate_classes() -> None:
    for service, clazz_models in generate_class_models().items():
        print(
            """from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus
from fixlib.json_bender import Bender, S, Bend, ForallBend, MapDict
    """
        )
        for clazz in clazz_models:
            print(clazz.to_class())
        print(
            "resources = [",
        )
        print(", ".join(cm.name for cm in clazz_models if cm.aggregate_root))
        print("]")


def generate_test_classes() -> None:
    for service, clazz_models in generate_class_models().items():
        print(
            f"""from .random_client import roundtrip
from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.{service} import *
"""
        )
        for clazz in clazz_models:
            if clazz.aggregate_root:
                print(clazz.roundtrip_test())


# Following parameters are known by the collector:
#  - project_id
#  - region (only if the resource is regional)
# Parameters can be created by creating templates from the given parameters.
# Note: the generator will fail for all unknown parameters.
known_api_parameters = {
    "compute": {"project": "{project}", "region": "{region}"},
    "container": {"parent": "projects/{project}/locations/-"},
    "sqladmin": {"project": "{project}", "instance": "{instance}"},
    "cloudbilling": {"project": "{project}", "region": "{region}", "name": "{name}", "parent": "{parent}"},
    "storage": {"project": "{project}", "bucket": "{bucket}"},
    "aiplatform": {
        "name": "",
        "parent": "projects/{project}/locations/{region}",
    },
}

# See https://googleapis.github.io/google-api-python-client/docs/dyn/ for the list of available resources
apis = [
    # (service, version, prefix, list_of_ignore_resources)
    # ("compute", "v1", "", []),
    # ("container", "v1", "Container", ["UsableSubnetwork"]),
    # ("sqladmin", "v1", "Sql", ["Tier"]),
    # ("cloudbilling", "v1", "", []),
    # ("storage", "v1", "", [])
    ("aiplatform", "v1", "", [])
]


if __name__ == "__main__":
    generate_classes()
    # generate_test_classes()
