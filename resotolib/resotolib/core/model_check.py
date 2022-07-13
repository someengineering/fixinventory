import re
from attrs import define
from typing import List, Dict, Tuple, Type

from resotolib.baseresources import BaseResource
from resotolib.core.model_export import dataclasses_to_resotocore_model
from resotolib.json import from_json


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

    model_classes = {
        # TODO: uncomment, once the new aws classes are ready
        # *dynamic_import("resoto_plugin_aws.collector.all_resources"),
        *dynamic_import("resoto_plugin_aws.resources.AWSResource"),
        *dynamic_import("resoto_plugin_gcp.resources.GCPResource"),
        *dynamic_import("resoto_plugin_digitalocean.resources.DigitalOceanResource"),
        *dynamic_import("resoto_plugin_k8s.resources.KubernetesResource"),
        *dynamic_import("resoto_plugin_onelogin.OneLoginResource"),
        *dynamic_import("resoto_plugin_example_collector.ExampleResource"),
        *dynamic_import("resoto_plugin_github.resources.GithubResource"),
        *dynamic_import("resoto_plugin_onprem.resources.OnpremResource"),
        *dynamic_import("resoto_plugin_slack.resources.SlackResource"),
        *dynamic_import("resoto_plugin_vsphere.resources.VSphereResource"),
        *dynamic_import("resoto_plugin_onelogin.OneLoginResource"),
        *base,
    }
    models = dataclasses_to_resotocore_model(model_classes, aggregate_root=BaseResource)

    classes = {model["fqn"]: from_json(model, CheckClass) for model in models if "properties" in model}
    all_paths: Dict[str, Tuple[CheckClass, str]] = {}

    def is_compatible(left: str, right: str) -> bool:
        return left == "any" or right == "any" or left == right

    def add_path(path: List[str], model: CheckClass) -> None:
        for prop in model.properties:
            kind = prop.kind
            prop_path = path + [prop.name]
            if "[]" in prop.kind:
                kind = prop.kind.replace("[]", "")
                prop_path += ["[0]"]  # use always the first element for simplicity
            elif "dictionary[" in prop.kind:
                kind = re.sub("dictionary\\[[^,]+,\\s*(\\S*)\\s*]", r"\1", prop.kind)
                prop_path += ["foo"]  # always use foo as lookup key

            str_path = ".".join(prop_path)
            if existing := all_paths.get(str_path):
                existing_class, existing_kind = existing
                if not is_compatible(existing_kind, prop.kind):
                    raise Exception(
                        f"{str_path} is defined in {existing_class.fqn} as {existing_kind} and in {model.fqn} as {kind}"
                    )
            all_paths[str_path] = (model, prop.kind)

            if kind := classes.get(kind):
                add_path(prop_path, kind)

    for _, clazz in classes.items():
        if clazz.aggregate_root:
            add_path([], clazz)
