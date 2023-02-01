import random
import string
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Type, Callable
from typing import Tuple, List

from google.auth.credentials import AnonymousCredentials
from googleapiclient import discovery

from resoto_plugin_gcp.gcp_client import RegionProp, GcpApiSpec, GcpClient
from resoto_plugin_gcp.resources.base import GcpZone, GcpRegion, GcpResource, GcpResourceType, GraphBuilder
from resotolib.json import set_value_in_path
from resotolib.types import JsonElement, Json
from resotolib.utils import utc_str

RequestResponse = Tuple[List[str], JsonElement]
Schema = Dict[str, Any]

random_regions = [GcpRegion(id="us-east1"), GcpRegion(id="europe-west3")]
random_zones = [
    GcpZone(id="us-east1-b"),
    GcpZone(id="us-east1-c"),
    GcpZone(id="europe-west3-a"),
    GcpZone(id="europe-west3-b"),
]
random_predefined: List[GcpResource] = random_regions + random_zones  # type: ignore
region_us, region_eu = random_regions
zone_us_b, zone_us_c, zone_eu_a, zone_eu_b = random_zones


def random_int(mn: int = 0, mx: int = sys.maxsize) -> int:
    return random.randint(mn, mx)


def random_double(mn: int = 0, mx: int = sys.maxsize) -> float:
    return random.randint(mn, mx) / random_int(1, 100)


def random_string(max_length: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase) for i in range(random_int(1, max_length)))


def random_ipv4() -> str:
    return ".".join(str(random_int(0, 255)) for _ in range(4))


def random_choice(choices: list) -> Any:
    return random.choice(choices)


def random_datetime() -> str:
    return utc_str(datetime.fromtimestamp(random_int(1400000000, 1600000000)))


IDCounter = defaultdict(int)

# random client: will not return any regions or zones
PredefinedResults = {
    "compute.regions.list": {"id": "regions", "items": []},
    "compute.zones.list": {"id": "regions", "items": []},
}
# dictionary keys under .items (used for aggregated list zone result) -> return zone ids
PredefinedDictKeys = {".items": [a.id for a in random_zones]}


def random_json(schemas: Dict[str, Schema], response_schema: Schema) -> JsonElement:
    def value_for(schema: Schema, level: int, path: str) -> JsonElement:
        def prop_value(type_name: str, name: str, prop_schema: Schema) -> JsonElement:
            # create "referencable" ids
            if name == "id" and prop_schema["type"] == "string":
                IDCounter[type_name] += 1
                return f"{type_name}-{IDCounter[type_name]}"
            elif name == "creationTimestamp":
                return random_datetime()
            elif name == "kind":
                return type_name
            elif name == RegionProp:
                return random_choice(random_regions).id
            else:
                return value_for(prop_schema, level + 1, f"{path}.{name}")

        if level > 20:
            return None
        if "type" in schema:
            if schema["type"] == "object" and "properties" in schema:
                kind = schema.get("id")
                return {k: prop_value(kind, k, v) for k, v in schema["properties"].items()}
            elif schema["type"] == "object" and "additionalProperties" in schema:
                keys = PredefinedDictKeys.get(path, [random_string() for _ in range(random_int(1, 3))])
                return {key: value_for(schema["additionalProperties"], level + 1, f"{path}.{key}") for key in keys}
            elif schema["type"] == "array":
                count = random_int(1, 3)
                return [value_for(schema["items"], level + 1, f"{path}[]") for _ in range(count)]
            elif schema["type"] == "string" and "enum" in schema:
                return random_choice(schema["enum"])
            elif schema["type"] == "string" and "in RFC3339 text format" in schema.get("description", ""):
                return random_datetime()
            elif schema["type"] == "string" and "URL" in schema.get("description", ""):
                return f"https://example.{random_string()}.{random_choice(['com', 'org', 'net'])}"
            elif schema["type"] == "string" and "IPv4" in schema.get("description", ""):
                return random_ipv4()
            elif schema["type"] == "string" and "int" in schema.get("format", ""):
                return str(random_int())
            elif schema["type"] == "string":
                return random_string()
            elif schema["type"] == "number":
                return random_double()
            elif schema["type"] == "integer":
                return random_int()
            elif schema["type"] == "boolean":
                return random_choice([True, False])
            elif schema["type"] == "any":
                return {random_string(): random_string(), random_string(): random_int()}
        if "$ref" in schema:
            return value_for(schemas[schema["$ref"]], level, path)
        raise ValueError(f"Unknown schema: {schema}")

    return value_for(response_schema, 0, "")


class RandomDataClient:
    def __init__(self, service: str, version: str, root: Dict[str, Any]) -> None:
        self.service = service
        self.version = version
        self.root = root
        self.schemas = root["schemas"]
        self.path = []
        self.next_pages = random_int(0, 1)

    def execute(self) -> JsonElement:
        part = self.root
        for path, _, _ in self.path[:-1]:
            part = part["resources"][path]
        path, args, kwargs = self.path[-1]
        method = part["methods"][path]
        response_kind_name = method["response"]["$ref"]
        response_kind = self.schemas[response_kind_name]
        path_full = ".".join(p for p, _, _ in self.path)
        return PredefinedResults.get(f"{self.service}.{path_full}", random_json(self.schemas, response_kind))

    def __getattr__(self, name: Any) -> Any:
        def add_path(*args, **kwargs) -> Any:
            if name.endswith("_next") and self.next_pages > 0:
                # simulate paging
                self.next_pages -= 1
                return self
            elif name.endswith("_next"):
                # reset state
                self.path = []
                self.next_pages = random_int(1, 2)
                # no more pages
                return None
            else:
                # path construction: add path
                self.path.append((name, args, kwargs))
                return self

        return add_path


def build_random_data_client(service: str, version: str, *args, **kwargs) -> RandomDataClient:
    """
    This is the random data client discovery function (replaces discovery.build in tests).
    """
    real_client = discovery.build(service, version, credentials=AnonymousCredentials())
    root = real_client._rootDesc
    return RandomDataClient(service, version, root)


def json_roundtrip(resource_clazz: Type[GcpResourceType], builder: GraphBuilder) -> None:
    assert len(builder.resources_of(resource_clazz)) > 0
    for resource in builder.resources_of(resource_clazz):
        # create json representation
        js_repr = resource.to_json()
        # make sure that the resource can be json serialized and read back
        again = resource_clazz.from_json(js_repr)
        # since we can not compare objects, we use the json representation to see that no information is lost
        again_js = again.to_json()
        assert js_repr == again_js, f"Left: {js_repr}\nRight: {again_js}"


def roundtrip(resource_clazz: Type[GcpResourceType], builder: GraphBuilder) -> GcpResourceType:
    resource_clazz.collect_resources(builder)
    json_roundtrip(resource_clazz, builder)
    return builder.resources_of(resource_clazz)[0]


def create_node_for(
    clazz: Type[GcpResourceType], spec: GcpApiSpec, adapt: Callable[[Json], Json]
) -> Tuple[Json, GcpResourceType]:
    client = GcpClient(AnonymousCredentials())
    result = client.list(api_spec=spec)
    assert len(result) > 0
    raw = adapt(result[0])
    return raw, clazz.from_api(raw)


def create_node(clazz: Type[GcpResourceType], **kwargs: Any) -> Tuple[Json, GcpResourceType]:
    spec = clazz.api_spec
    assert spec is not None

    def set_value(json: Json) -> Json:
        for key, value in kwargs.items():
            json = set_value_in_path(value, key, json)
        return json

    return create_node_for(clazz, spec, set_value)


def connect_resource(
    builder: GraphBuilder, source: GcpResourceType, target: Type[GcpResourceType], **kwargs: Any
) -> GcpResourceType:
    raw, node = create_node(target, **kwargs)
    builder.add_node(node, raw)
    node_data = builder.graph.nodes(data=True)[source]
    source.connect_in_graph(builder, node_data["source"])
    return node
