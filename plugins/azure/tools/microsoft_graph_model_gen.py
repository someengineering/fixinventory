from __future__ import annotations
import os
import re
from typing import Union, Dict, List, Set, Optional, Iterator

import yaml
from attr import define
from jsons import pascalcase

from fixlib.types import Json


def to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub("__([A-Z])", r"_\1", name)
    name = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.lower()


simple_type_map = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
}

# denylist: specific properties require a SPO license or have other restrictions
forbidden_props = {
    "user": set(
        "aboutMe,preferredName,print,mySite,skills,schools,responsibilities,mailboxSettings,deviceEnrollmentLimit,"
        "pastProjects,signInActivity,birthday,hireDate,interests,isLicenseReconciliationNeeded".split(",")
    ),
    "group": set(
        "allowExternalSenders,autoSubscribeNewMembers,hasMembersWithLicenseErrors,hideFromAddressLists,"
        "hideFromOutlookClients,isArchived,isSubscribedByMail,unseenCount".split(",")
    ),
}


@define
class MSGraphProperty:
    name: str
    type: Union[str, list[Json]]
    description: str
    definition: Json
    model: MSSchemaModel

    def assignment(self) -> str:
        default = "default=None"
        desc = re.sub("[\n\r'\"]", " ", self.description)  # remove invalid characters
        desc = re.sub("<br\\s*/?>", " ", desc)  # replace <br/> tags
        desc = re.sub("\\s\\s+", " ", desc)  # remove multiple spaces
        metadata = f", metadata={{'description': '{desc}'}}"
        result = f"field({default}{metadata})"
        if (len(result) + len(self.prop_name) + len(self.type_name)) > 100:
            result += "  # fmt: skip"
        return result

    @property
    def prop_name(self) -> str:
        return to_snake(self.name)

    @property
    def is_nav_prop(self) -> bool:
        return self.definition.get("x-ms-navigationProperty") is True

    @property
    def is_any(self) -> bool:
        return self.type == "any"

    @property
    def is_array(self) -> bool:
        return self.type == "array"

    def array_inner(self) -> str:
        if inner := self.definition.get("items"):
            if it := inner.get("type"):
                return it
            elif it := inner.get("$ref"):
                return it
        return "Any"

    def complex_class(self) -> Optional[MSGraphClassModel]:
        ref = self.array_inner() if self.is_array else self.definition.get("$ref", self.type)
        return self.model.get(ref) if ref else None

    @property
    def is_complex(self) -> bool:
        return not (
            (isinstance(self.type, str) and self.type in simple_type_map)
            or (self.is_array and self.array_inner() in simple_type_map)
        )

    @property
    def type_name(self) -> str:
        if self.is_any:
            return "Any"
        if isinstance(self.type, list):
            return "Any"
        if name := simple_type_map.get(self.type):
            return name
        if self.type == "array":
            return self.model.type_name(self.array_inner())
        return self.model.type_name(self.type)

    def type_string(self) -> str:
        if self.is_array:
            return f"Optional[List[{self.type_name}]]"
        return f"Optional[{self.type_name}]"

    def mapping(self) -> str:
        return f'"{self.prop_name}": ' + self.mapping_from()

    def mapping_from(self) -> str:
        # in case an extractor is defined explicitly
        from_p = [self.name]
        from_p_path = ",".join(f'"{p}"' for p in from_p)
        base = f"S({from_p_path}"
        if self.is_array and self.is_complex:
            base += f") >> ForallBend({self.type_name}.mapping)"
        elif self.is_array:
            base += ")"
        elif self.is_complex and not self.is_any:
            base += f") >> Bend({self.type_name}.mapping)"
        else:
            base += ")"
        return base


@define
class MSGraphClassModel:
    title: str
    base_classes: list[str]
    properties: dict[str, MSGraphProperty]
    model: MSSchemaModel
    aggregate_root: bool = False

    @property
    def class_name(self) -> str:
        return "MicrosoftGraph" + pascalcase(self.title)

    def sorted_props(self) -> List[MSGraphProperty]:
        # filter properties
        filtered = (v for k, v in self.properties.items() if not k.startswith("@") and not v.is_nav_prop)
        if denied := forbidden_props.get(self.title):
            filtered = (p for p in filtered if p.name not in denied)
        return sorted(filtered, key=lambda p: p.name)

    def hierarchy_props(self) -> List[MSGraphProperty]:
        def base_props(clazz: MSGraphClassModel) -> Iterator[MSGraphProperty]:
            for base in clazz.base_classes:
                if base_clazz := self.model.get(base):
                    for prop in base_clazz.sorted_props():
                        yield prop
                    yield from base_props(base_clazz)

        return sorted(self.sorted_props() + list(base_props(self)), key=lambda p: p.name)

    def to_class(self) -> str:
        bases = [self.model.type_name(b) for b in self.base_classes]
        base = ("(" + ", ".join(bases) + ")") if bases else ""
        kind = f'    kind: ClassVar[str] = "azure_{to_snake(self.title)}"'
        api = ""
        if self.aggregate_root:
            parameters = {
                "$select": ",".join(p.name for p in self.hierarchy_props()),
            }
            api = f'    api_spec: ClassVar[MicrosoftRestSpec] = RestApiSpec("graph", "https://graph.microsoft.com/v1.0/{self.title.lower()}s", parameters={parameters}, access_path="value")'
        # tags need a default value
        base_mappings: Dict[str, str] = {}
        for bp in ["id", "tags", "name", "ctime", "mtime", "atime"]:
            if bp not in base_mappings:
                if bp == "id":
                    base_mappings[bp] = 'S("id")'
                else:
                    base_mappings[bp] = "K(None)"
        # take class hierarchy into account and assemble the mappings
        bmp = " | ".join(f"{self.model.type_name(base)}.mapping" for base in self.base_classes)
        bmp = f"{bmp} | " if bmp else ""
        mapping = f"    mapping: ClassVar[Dict[str, Bender]] = {bmp} {{\n"
        if self.aggregate_root:
            mapping += ",\n".join(f'        "{k}": {v}' for k, v in base_mappings.items())
            mapping += ",\n"
        mapping += ",\n".join(f"        {p.mapping()}" for p in self.sorted_props())
        mapping += "\n    }"
        props = "\n".join(f"    {p.prop_name}: {p.type_string()} = {p.assignment()}" for p in self.sorted_props())
        return f"@define(eq=False, slots=False)\nclass {self.class_name}{base}:\n{kind}\n{api}\n{mapping}\n{props}\n"


@define
class MSSchemaModel:
    specs: dict[str, MSGraphClassModel]

    def id_name(self, name: str) -> str:
        return name.replace("#/components/schemas/", "") if name else None

    def type_name(self, id_name: str) -> str:
        id_name = self.id_name(id_name)
        if sn := simple_type_map.get(id_name):
            return sn
        elif schema := self.specs.get(id_name):
            return schema.class_name
        else:
            return "Any"

    def __getitem__(self, item: str) -> MSGraphClassModel:
        return self.specs[self.id_name(item)]

    def __contains__(self, item: str) -> bool:
        return self.id_name(item) in self.specs

    def get(self, item: str) -> MSGraphClassModel:
        return self.specs.get(self.id_name(item))

    def render_class_transitively(self, names: Set[str]) -> None:
        selected = {}

        def add_class(clazz: MSGraphClassModel) -> None:
            selected[clazz.class_name] = clazz
            for base in clazz.base_classes:
                if cc := self.get(base):
                    add_class(cc)
            for prop in clazz.sorted_props():
                if cc := prop.complex_class():
                    add_class(cc)

        for name in names:
            if cm := self.get(name):
                cm.aggregate_root = True  # mark all selected classes as root
                add_class(cm)
        for cm in reversed(selected.values()):
            print(cm.to_class())


def process_schema(path: str) -> MSSchemaModel:
    with open(path) as f:
        spec = yaml.safe_load(f)
        schema_model = MSSchemaModel(specs={})
        for sid, schema in spec["components"]["schemas"].items():
            title: str = schema.get("title", sid)
            bases = []
            properties = {}

            def walk_object(part: Json) -> None:
                nonlocal title
                title = part.get("title", title)
                if ref := part.get("$ref"):
                    bases.append(ref)
                elif props := part.get("properties"):
                    for name, props in props.items():
                        pt = props.get("type", props.get("anyOf"))
                        # apispec defines anyOf something or nullable object. Ignore nullable object.
                        if (
                            isinstance(pt, list)
                            and len(pt) == 2
                            and pt[1] == dict(type="object", nullable=True)
                            and (ref := pt[0].get("$ref"))
                        ):
                            pt = ref
                        properties[name] = MSGraphProperty(
                            name=name,
                            type=pt,
                            description=props.get("description", ""),
                            definition=props,
                            model=schema_model,
                        )

            walk_object(schema)
            if all_off := schema.get("allOf"):
                for part in all_off:
                    walk_object(part)

            schema_model.specs[sid] = MSGraphClassModel(
                title=title, base_classes=bases, properties=properties, model=schema_model
            )
        return schema_model


if __name__ == "__main__":
    specs_path = os.environ.get("GRAPH_REST_API", "../../../../msgraph-metadata/openapi/v1.0/openapi.yaml")
    assert specs_path, (
        "GRAPH_REST_API need to be defined! "
        "Checkout https://github.com/microsoftgraph/msgraph-metadata and set path in env"
    )
    specs = process_schema(specs_path)
    # specs.render_class_transitively({"microsoft.graph.user", "microsoft.graph.group", "microsoft.graph.unifiedRoleDefinition", "microsoft.graph.servicePrincipal", "microsoft.graph.device"})
    specs.render_class_transitively({"microsoft.graph.organization"})
