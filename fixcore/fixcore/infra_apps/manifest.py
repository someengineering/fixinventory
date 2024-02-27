from typing import List, Optional, Dict
from attrs import frozen
from fixcore.types import Json
from fixcore.model.typed_model import from_js
from fixcore.ids import InfraAppName
from yaml import safe_load
from jsons import loads as jsons_loads


ArgName = str


@frozen
class AppManifest:
    """
    The manifest of an infrastructure app. The manifest is a YAML file that describes the infrastsucture app.

    @param name: The name of the app. Acts as the unique identifier of the app. Allowed characters are [a-zA-Z0-9_].
    @param description: A short human-readable description of the app.
    @param version: The version of the app. Must be a valid semantic version.
    @param readme: A long human-readable description of the app in markdown format.
    @param language: The programming language the app is written. Currently only "jinja2" is supported.
    @param url: The URL to the app's source code location.
    @param icon: base64 encoded icon of the app.
    @param categories: A list of categories the app belongs to.
    @param config_schema: A JSON schema that describes the configuration of the app.
    See https://json-schema.org/ for more information.
    @param default_config: The default configuration of the app.
    @param args_schema: A list of command line arguments that can be passed to the app.
    Must be compatible with the Python argparse library.
    @param source: The source code of the app.

    """

    name: InfraAppName
    description: str
    version: str
    readme: str
    language: str
    url: str
    icon: str
    categories: List[str]
    config_schema: Optional[List[Json]]
    default_config: Optional[Json]
    args_schema: Optional[Dict[ArgName, Json]]
    source: str

    # Object creation methods. Use these instead of the __init__ method.

    @staticmethod
    def from_json(json: Json) -> "AppManifest":
        return from_js(json, AppManifest)

    @staticmethod
    def from_json_str(json_str: str) -> "AppManifest":
        json = jsons_loads(json_str)
        manifest = AppManifest.from_json(json)
        return manifest

    @staticmethod
    def from_bytes(b: bytes) -> "AppManifest":
        return AppManifest.from_json_str(b.decode("utf-8"))

    @staticmethod
    def from_yaml_str(yaml_str: str) -> "AppManifest":
        return AppManifest.from_json(safe_load(yaml_str))
