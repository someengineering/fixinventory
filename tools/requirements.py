# Before calling this script:
# pip install toml pip-tools
#
# Run this script from the root of the repository
# python tools/requirements.py
#
# It will gather all project requirements and compile them into
# - a single requirements.txt file
# - a requirements-all.txt file with all dependencies
# - a requirements-dev.txt file with project and development dependencies
# - a requirements-test.txt file with project and test dependencies
#
import os
from collections import defaultdict
from typing import Any, Dict, List, Iterator, Optional
import toml


class ProjectDefinition:
    def __init__(self, definition: Dict[str, Any]) -> None:
        self.definition = definition

    @property
    def name(self) -> str:
        return self.definition["project"]["name"]

    @property
    def dependencies(self) -> List[str]:
        return self.definition["project"].get("dependencies", [])

    @property
    def optional_dependencies(self) -> Dict[str, List[str]]:
        return self.definition["project"].get("optional-dependencies", {})

    @property
    def all_dependencies(self) -> List[str]:
        return self.dependencies + [dep for deps in self.optional_dependencies.values() for dep in deps]


def all_project_definitions() -> Iterator[ProjectDefinition]:
    for root, _, files in os.walk("."):
        if "site-packages" in root or ".git" in root:
            continue
        for file in files:
            if file == "pyproject.toml":
                print(f"Found pyproject.toml in {root}")
                file_path = os.path.join(root, file)
                try:
                    with open(file_path) as f:
                        yield ProjectDefinition(toml.load(f))
                except Exception as e:
                    print(f"Failed to parse {file_path}: {e}")
                    raise


filter_out = ["fixinventorylib", "fixinventory-plugin-aws"]


def filter_dependencies(deps: List[str]) -> List[str]:
    return [dep for dep in deps if not any(name in dep for name in filter_out)]


def compile_dependencies(name: Optional[str], deps: List[str], use_version: Optional[List[str]] = None) -> List[str]:
    print(f"Compile dependencies for {name or 'prod'}")
    delim = "-" + name if name else ""
    if use_version:
        lookup = dict(((dep.split("==", maxsplit=1)[0], dep) for dep in use_version))
        deps = [lookup.get(dep.split("==", maxsplit=1)[0], dep) for dep in deps]
    with open(f"requirements{delim}-in.txt", "w") as f:
        f.write("\n".join(deps))
    args = "-q --no-annotate --resolver=backtracking --upgrade --allow-unsafe --no-header  --unsafe-package n/a --no-strip-extras"
    os.system(f"pip-compile {args} --output-file requirements{delim}.txt requirements{delim}-in.txt")
    os.remove(f"requirements{delim}-in.txt")
    # make sure, none of the filtered dependencies was selected as transitive dependency
    with open(f"requirements{delim}.txt", "r+") as f:
        lines = [line for line in f.readlines() if not any(name in line for name in filter_out)]
        # required for transitive dependencies not defined in deps
        if use_version:
            lookup = dict(((dep.split("==", maxsplit=1)[0], dep) for dep in use_version))
            lines = [lookup.get(dep.split("==", maxsplit=1)[0], dep) for dep in lines]
        f.seek(0)
        f.writelines(lines)
        f.truncate()
        return lines


def combine_dependencies() -> None:
    prod_dependencies = []
    optional_dependencies = defaultdict(list)
    for project in all_project_definitions():
        prod_dependencies.extend(filter_dependencies(project.dependencies))
        for name, deps in project.optional_dependencies.items():
            assert name in ("test", "extra"), f"How to handle: {name}? dev (all) or prod dependency?"
            optional_dependencies[name].extend(filter_dependencies(deps))

    # gather dependencies
    extra_dependencies = prod_dependencies.copy()
    for name, deps in optional_dependencies.items():
        if name != "test":
            extra_dependencies.extend(deps)
    # compile all prod + extra dependencies
    extra_compiled = compile_dependencies("extra", extra_dependencies)
    # compile prod, by using the extra-compiled versions
    compile_dependencies(None, prod_dependencies, extra_compiled)
    # compile all dependencies by adding test to the extra-compiled dependencies
    compile_dependencies("all", extra_compiled + optional_dependencies.get("test", []))


if __name__ == "__main__":
    combine_dependencies()
