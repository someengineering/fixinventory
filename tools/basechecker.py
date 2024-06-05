#!/usr/bin/env python3
import pkgutil
import importlib
import inspect
from typing import List, Type, Any, Dict, Set, Optional
from pprint import pprint


def list_submodules(package_name: str) -> List[str]:
    package = importlib.import_module(package_name)
    package_path = package.__path__
    submodules = [f"{package_name}.{name}" for _, name, _ in pkgutil.iter_modules(package_path)]
    return submodules


def list_fix_resource_modules(plugin_name: str) -> List[str]:
    plugin_package = f"fix_plugin_{plugin_name}"
    package_name = f"{plugin_package}.resource"
    submodules = []
    try:
        submodules = list_submodules(package_name)
    except ModuleNotFoundError:
        try:
            package_name = f"{plugin_package}.resources"
            submodules = list_submodules(package_name)
        except ModuleNotFoundError:
            raise
    except Exception:
        print(f"Failed to load {plugin_package}")
    return submodules


def list_classes_in_module(module_name: str) -> List[Type[Any]]:
    module = importlib.import_module(module_name)
    classes = [cls for _, cls in inspect.getmembers(module, inspect.isclass) if cls.__module__ == module_name]
    return classes


def get_fix_baseresource_classes() -> List[Type[Any]]:
    return [cls for cls in list_classes_in_module("fixlib.baseresources") if cls.__name__.startswith("Base")]


def get_attrs(cls: Type[Any]) -> Set[str]:
    return set(attr.fields_dict(cls).keys())


def analyze_plugin_implementations(base_classes: List[Type[Any]], plugins: List[str]) -> Dict[str, Dict[str, Any]]:
    results = {
        cls.__name__: {"implemented_by": set(), "not_implemented_by": set(), "partial_implementation": {}}
        for cls in base_classes
    }
    for plugin in plugins:
        print(f"Analyzing plugin: {plugin}")
        try:
            plugin_classes = []
            for module in list_fix_resource_modules(plugin):
                plugin_classes.extend(list_classes_in_module(module))
            for base_cls in base_classes:
                base_attrs = get_attrs(base_cls)
                implemented = False
                for cls in plugin_classes:
                    if issubclass(cls, base_cls):
                        cls_attrs = get_attrs(cls)
                        if base_attrs <= cls_attrs:
                            results[base_cls.__name__]["implemented_by"].add(plugin)
                            implemented = True
                            break
                        else:
                            results[base_cls.__name__]["partial_implementation"][plugin] = base_attrs - cls_attrs
                if not implemented:
                    results[base_cls.__name__]["not_implemented_by"].add(plugin)
        except Exception as e:
            print(f"Error analyzing {plugin}: {e}")

    return results


def filter_fix_resources(all_classes: List[Type[Any]], base_classes: List[Type[Any]]) -> List[Type[Any]]:
    filtered_classes = [cls for cls in all_classes if any(issubclass(cls, base) for base in base_classes)]
    return filtered_classes


def analyze_plugin_implementations(
    base_classes: List[Type[Any]], plugins: List[str]
) -> Dict[Type[Any], Dict[str, Optional[Type[Any]]]]:
    results = {cls: {plugin: None for plugin in plugins} for cls in base_classes}
    for plugin in plugins:
        print(f"Analyzing plugin: {plugin}")
        try:
            plugin_classes = []
            for module in list_fix_resource_modules(plugin):
                plugin_classes.extend(list_classes_in_module(module))
            for base_cls in base_classes:
                for cls in plugin_classes:
                    if issubclass(cls, base_cls):
                        results[base_cls][plugin] = cls
                        break
        except Exception as e:
            print(f"Error analyzing {plugin}: {e}")
    return results


def print_stats(implementation_stats: Dict[Type[Any], Dict[str, Optional[Type[Any]]]]):
    for base_cls, plugins in implementation_stats.items():
        print(f"Base Resource: {base_cls.__name__}")
        for plugin, impl_cls in plugins.items():
            cls_name = impl_cls.__name__ if impl_cls else "None"
            print(f"  Plugin {plugin}: {cls_name}")


if __name__ == "__main__":
    base_classes = get_fix_baseresource_classes()
    plugins = ["aws", "gcp", "azure"]
    implementation_stats = analyze_plugin_implementations(base_classes, plugins)
    print_stats(implementation_stats)
