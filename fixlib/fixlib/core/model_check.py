import re
from typing import List, Dict, Tuple, Type, Optional, Any, Set

from attrs import define

from fixlib.basecategories import Category
from fixlib.baseresources import BaseResource
from fixlib.core.model_export import transitive_classes
from fixlib.graph import resource_classes_to_fixcore_model
from fixlib.json import from_json
from fixlib.types import Json

# fmt: off

# Possible group value: any addition needs to be supported in the frontend
ResourceGroups: Set[str] = {c.name for c in Category}
# Possible icon value: any addition needs to be supported in the frontend
ResourceIcons: Set[str] = {
    "access_control", "account", "alarm", "application", "autoscaling_group", "backup",
    "bucket", "cdn", "certificate", "cloud", "cluster", "config", "connection", "container",
    "database", "dns", "dns_record", "endpoint", "environment", "firewall", "function",
    "gateway", "graph_root", "group", "health", "host", "image", "instance", "job", "key",
    "link", "load_balancer", "lock", "log", "network", "network_address", "network_share",
    "plan", "policy", "profile", "provider", "proxy", "queue", "quota", "region",
    "repository", "resource", "role", "routing_table", "security_group", "service",
    "snapshot", "stack", "subnet", "type", "user", "vault", "version", "volume", "zone",
}
# Define classes that should be ignored for the resource check
IgnoredClasses: Set[str] = {
    "aws_resource", "aws_account", "aws_region",
    "microsoft_resource",
    "gcp_resource", "gcp_region", "gcp_project", "gcp_zone", "gcp_region_quota"
}
# fmt: on


@define
class CheckProp:
    name: str
    kind: str


@define
class CheckClass:
    fqn: str
    aggregate_root: bool
    bases: Optional[List[str]]
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

            # if this property kind is complex too: walk it.
            if check_kind := classes.get(kind):
                add_path(prop_path, pkinds, check_kind)

    # Walk all models and add all properties to the all_paths dict.
    for _, clazz in classes.items():
        if clazz.aggregate_root and not clazz.ignore():
            add_path([], [], clazz)

    # Check that all successor kinds exist
    for model in models:
        if succ_dict := model.get("successor_kinds"):
            for kinds in succ_dict.values():
                for kind in kinds:
                    if kind not in all_fqns:
                        raise AttributeError(f"Successor kind {kind} does not exist")

    # Check that no property is redeclared
    def check_not_redeclared(root: CheckClass, clazz: CheckClass, props: Set[str]) -> None:
        props = {prop.name for prop in clazz.properties} | props
        for base in clazz.bases or []:
            if base_class := classes.get(base):
                for prop in base_class.properties:
                    if prop.name in props:
                        raise AttributeError(f"Property {prop.name} is redeclared in {root.fqn}")
                check_not_redeclared(root, base_class, props)

    for clazz in classes.values():
        check_not_redeclared(clazz, clazz, set())


def check_model_class(clazz: Type[BaseResource]) -> None:
    name = clazz.__name__
    kind = clazz.kind
    if any(kind.startswith(a) for a in ["aws", "gcp", "azure", "microsoft"]):  # only selected providers support this
        props = vars(clazz)
        if "_kind_display" not in props:
            raise AttributeError(f"Class {name} does not have a _kind_display attribute")
        assert clazz._kind_service is not None, f"Class {name} does not have a _kind_service attribute"

    # make sure _metadata is valid
    if icon := clazz._metadata.get("icon"):
        assert icon in ResourceIcons, f"{name} has unknown icon {icon}"
    if group := clazz._metadata.get("group"):
        assert group in ResourceGroups, f"{name} has unknown group {group}"


def load_plugin_classes(*base: Type[BaseResource]) -> Set[Type[BaseResource]]:
    def dynamic_import(name: str) -> List[Type[Any]]:
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
    return {
        *dynamic_import("fix_plugin_aws.collector.all_resources"),
        *dynamic_import("fix_plugin_azure.collector.all_resources"),
        *dynamic_import("fix_plugin_digitalocean.resources.DigitalOceanResource"),
        *dynamic_import("fix_plugin_dockerhub.resources.DockerHubResource"),
        *dynamic_import("fix_plugin_example_collector.ExampleResource"),
        *dynamic_import("fix_plugin_gcp.resources.base.GcpResource"),
        *dynamic_import("fix_plugin_github.resources.GithubResource"),
        *dynamic_import("fix_plugin_k8s.resources.KubernetesResource"),
        *dynamic_import("fix_plugin_onelogin.OneLoginResource"),
        *dynamic_import("fix_plugin_posthog.resources.PosthogResource"),
        *dynamic_import("fix_plugin_random.resources.RandomResource"),
        *dynamic_import("fix_plugin_scarf.resources.ScarfResource"),
        *dynamic_import("fix_plugin_slack.resources.SlackResource"),
        *base,
    }


def check_overlap(*base: Type[BaseResource]) -> None:
    """
    Call this method from your collector plugin to check for overlapping properties.
    This will try to load all models from all known plugins.
    The call will fail if the imports are not working - make sure the calling side has all those plugins installed.

    @param base: additional base classes to check for overlapping properties. All existing known plugins are added.
    :raise Exception: if there is an overlap
    """

    kind_names: Dict[str, Type[Any]] = {}
    model_classes = load_plugin_classes(*base)
    for model in transitive_classes(model_classes):
        if kind := getattr(model, "kind", None):
            if (existing := kind_names.get(kind)) and existing != model:
                raise AttributeError(f"Kind {kind} is defined in {model.__name__} and {existing.__name__}")
            kind_names[kind] = model

        if issubclass(model, BaseResource) and not getattr(model, "__abstractmethods__"):
            # check that the model class is not abstract and has no abstract methods
            if model.kind not in IgnoredClasses:
                check_model_class(model)

    check_overlap_for(resource_classes_to_fixcore_model(model_classes, aggregate_root=BaseResource))


if __name__ == "__main__":
    check_overlap()
