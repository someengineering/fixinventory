import re
from attrs import define
from typing import List, Dict, Tuple, Type

from resotolib.baseresources import BaseResource
from resotolib.core.model_export import dataclasses_to_resotocore_model
from resotolib.json import from_json
from resotolib.types import Json


@define
class CheckProp:
    name: str
    kind: str


@define
class CheckClass:
    fqn: str
    aggregate_root: bool
    bases: List[str]
    properties: List[CheckProp]

    def ignore(self) -> bool:
        # Those types were created during development of 2.4 and renamed. They were never available in a final release.
        # In case somebody operated on edge, we want to ignore them.
        return self.fqn.startswith("aws_auto_scaling") or self.fqn.startswith("aws_quota")


def check_overlap_for(models: List[Json]) -> None:
    # make sure that all model names are unique
    all_fqns = set()
    for model in models:
        if model["fqn"] in all_fqns:
            raise Exception(f"Model {model['fqn']} is defined multiple times")
        all_fqns.add(model["fqn"])
    # convert json representation to intermediate python structure
    classes = {model["fqn"]: from_json(model, CheckClass) for model in models if "properties" in model}
    # this variable holds all possible property paths
    all_paths: Dict[str, Tuple[CheckClass, str]] = {}

    # checks if 2 kinds are compatible
    def is_compatible(left: str, right: str) -> bool:
        return left == "any" or right == "any" or left == right

    def add_path(path: List[str], kinds: List[CheckClass], model: CheckClass) -> None:
        # This check is required to prevent endless loops: consider class Foo with property inner of type Foo.
        # We would walk this chain infinitely, that's why we return as early as possible
        for c in kinds:
            if c == model:
                return

        # Walk all properties of the model and add them to the all_paths dict.
        for prop in model.properties:
            # add the current kind to the list: this must be a new list which is unique for the property path
            pkinds = kinds + [model]
            kind = prop.kind
            prop_path = path + [prop.name]
            if "[]" in prop.kind:
                kind = prop.kind.replace("[]", "")
                prop_path += ["[0]"]  # use always the first element for simplicity
            elif "dictionary[" in prop.kind:
                kind = re.sub("dictionary\\[[^,]+,\\s*(\\S*)\\s*]", r"\1", prop.kind)
                prop_path += ["foo"]  # always use foo as lookup key

            # Create a string representation of the path. E.g. user.address.city.zip
            str_path = ".".join(prop_path)

            # Check if the path is already in the list of all paths and has a compatible kind.
            if existing := all_paths.get(str_path):
                existing_class, existing_kind = existing
                if not is_compatible(existing_kind, prop.kind):
                    raise AttributeError(
                        f"{str_path} is defined in {existing_class.fqn} as {existing_kind} and in {model.fqn} as {kind}"
                    )

            # update the dict of all paths, ignoring any existing value
            all_paths[str_path] = (model, prop.kind)

            # if this property  kind is complex too: walk it.
            if check_kind := classes.get(kind):
                add_path(prop_path, pkinds, check_kind)

    for _, clazz in classes.items():
        if clazz.aggregate_root and not clazz.ignore():
            add_path([], [], clazz)


def check_overlap(*base: Type[BaseResource]) -> None:
    """
    Call this method from your collector plugin to check for overlapping properties.
    This will try to load all models from all known plugins.
    The call will fail if the imports are not working - make sure the calling side has all those plugins installed.

    @param base: additional base classes to check for overlapping properties. All existing known plugins are added.
    :raise Exception: if there is an overlap
    """

    def dynamic_import(name) -> List[type]:
        components = name.split(".")
        mod = __import__(components[0])
        for comp in components[1:]:
            mod = getattr(mod, comp)
        if isinstance(mod, type):
            return [mod]
        elif isinstance(mod, list):
            return mod
        else:
            raise AttributeError(f"Import {name}: expected type or list of types, got {type(mod)}")

    # List of all plugin classes that need to be imported.
    model_classes = {
        *dynamic_import("resoto_plugin_aws.collector.all_resources"),
        *dynamic_import("resoto_plugin_digitalocean.resources.DigitalOceanResource"),
        *dynamic_import("resoto_plugin_dockerhub.resources.DockerHubResource"),
        *dynamic_import("resoto_plugin_example_collector.ExampleResource"),
        *dynamic_import("resoto_plugin_gcp.resources.GCPResource"),
        *dynamic_import("resoto_plugin_github.resources.GithubResource"),
        *dynamic_import("resoto_plugin_k8s.resources.KubernetesResource"),
        *dynamic_import("resoto_plugin_onelogin.OneLoginResource"),
        *dynamic_import("resoto_plugin_onprem.resources.OnpremResource"),
        *dynamic_import("resoto_plugin_posthog.resources.PosthogResource"),
        *dynamic_import("resoto_plugin_random.resources.RandomResource"),
        *dynamic_import("resoto_plugin_scarf.resources.ScarfResource"),
        *dynamic_import("resoto_plugin_slack.resources.SlackResource"),
        *dynamic_import("resoto_plugin_vsphere.resources.VSphereResource"),
        *base,
    }
    # check overlap for all plugin classes
    check_overlap_for(dataclasses_to_resotocore_model(model_classes, aggregate_root=BaseResource))
