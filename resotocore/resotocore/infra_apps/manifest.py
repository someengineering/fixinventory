from typing import Literal, List, Union, Optional, Any
from attrs import frozen
from resotocore.types import Json
from yaml import safe_load
from jsons import loads as jsons_loads


@frozen
class AppArgs:
    """
    A command line argument that can be passed to the app. Must be compatible with the Python argparse library.

    @param name: The name of the argument. Must be a valid Python variable name.
    @param help: A short human-readable description of the argument.
    @param action: The action to be taken when the argument is encountered at the command line. See https://docs.python.org/3/library/argparse.html#action for more information.
    @param type: The type of the argument. See https://docs.python.org/3/library/argparse.html#type for more information.
    @param nargs: The number of command-line arguments that should be consumed. See https://docs.python.org/3/library/argparse.html#nargs for more information.
    @param default: The default value of the argument. See https://docs.python.org/3/library/argparse.html#default for more information.
    """

    name: str
    help: str
    action: Literal[
        "store", "store_const", "store_true", "append", "append_const", "count", "help", "version"
    ] = "store"
    type: Literal["str", "int", "float", "bool"] = "str"
    nargs: Union[None, int, Literal["?", "*", "+"]] = None
    default: Optional[Any] = None


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
    @param config_schema: A JSON schema that describes the configuration of the app. see https://json-schema.org/ for more information.
    @param default_config: The default configuration of the app.
    @param args_schema: A list of command line arguments that can be passed to the app. Must be compatible with the Python argparse library.
    @param source: The source code of the app.

    """

    name: str
    description: str
    version: str
    readme: str
    language: Literal["jinja2"]
    url: str
    icon: str
    categories: List[str]
    config_schema: Optional[Json]
    default_config: Optional[Json]
    args_schema: List[AppArgs]
    source: str

    ### Object creation methods. Use these instead of the __init__ method. ###

    @staticmethod
    def from_json(json: Json) -> "AppManifest":
        return AppManifest(**json)

    @staticmethod
    def from_json_str(json_str: str) -> "AppManifest":
        return AppManifest.from_json(jsons_loads(json_str))

    @staticmethod
    def from_yaml_str(yaml_str: str) -> "AppManifest":
        return AppManifest.from_json(safe_load(yaml_str))

    @staticmethod
    def new(
        name: str,
        description: str,
        version: str,
        readme: str,
        language: Literal["jinja2"],
        url: str,
        icon: str,
        categories: List[str],
        config_schema: Optional[Json],
        default_config: Optional[Json],
        args_schema: List[AppArgs],
        source: str,
    ) -> "AppManifest":
        return AppManifest(
            name=name,
            description=description,
            version=version,
            readme=readme,
            language=language,
            url=url,
            icon=icon,
            categories=categories,
            config_schema=config_schema,
            default_config=default_config,
            args_schema=args_schema,
            source=source,
        )
