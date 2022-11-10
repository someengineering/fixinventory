import inspect
from functools import lru_cache
from typing import List, Any, Type, Tuple, Dict, Optional

from resotoclient.models import Kind, Model, Property, JsObject
from resotolib import baseresources
from resotolib.baseresources import BaseResource
from resotolib.types import Json
from sqlalchemy import (
    MetaData,
    Table,
    Integer,
    Column,
    String,
    JSON,
    Boolean,
    Float,
    Double,
    ForeignKey,
    Insert,
    ValuesBase,
)
from sqlalchemy.sql.type_api import TypeEngine


class SqlModel:
    def __init__(self, model: Model):
        self.model = model
        self.metadata = MetaData()

    carz = [
        Property("cloud", "string"),
        Property("account", "string"),
        Property("region", "string"),
        Property("zone", "string"),
    ]

    @staticmethod
    def column_type_from(kind: str) -> Type[TypeEngine[Any]]:
        if "[]" in kind:
            return JSON
        elif kind.startswith("dict"):
            return JSON
        elif kind in ("int32", "int64"):
            return Integer
        elif kind in "float":
            return Float
        elif kind in "double":
            return Double
        elif kind in ("string", "date", "datetime", "duration"):
            return String
        elif kind == "boolean":
            return Boolean
        else:
            return JSON

    @staticmethod
    def table_name(kind: str) -> str:
        return kind.replace(".", "_")

    def link_table_name(self, from_kind: str, to_kind: str) -> str:
        # postgres table names are not allowed to be longer than 63 characters
        return f"link_{self.table_name(from_kind)[0:28]}_{self.table_name(to_kind)[0:28]}"

    def kind_properties(self, kind: Kind) -> Tuple[List[Property], List[str]]:
        visited = set()

        def base_props_not_visited(kd: Kind) -> Tuple[List[Property], List[str]]:
            if kd.fqn in visited:
                return [], []
            visited.add(kd.fqn)
            # take all properties that are not synthetic
            # also ignore the kind property, since it is available in the table name
            properties: Dict[str, Property] = {
                prop.name: prop for prop in (kd.properties or []) if prop.synthetic is None and prop.name != "kind"
            }
            defaults = kd.successor_kinds.get("default") if kd.successor_kinds else None
            successors: List[str] = defaults.copy() if defaults else []
            for kind_name in kd.bases or []:
                if ck := self.model.kinds.get(kind_name):  # and kind_name != "resource":
                    props, succs = base_props_not_visited(ck)
                    for prop in props:
                        properties[prop.name] = prop
                    successors.extend(succs)
            return list(properties.values()), successors

        prs, scs = base_props_not_visited(kind)
        return prs + self.carz, scs

    def create_schema(self) -> MetaData:
        def table_schema(kind: Kind) -> None:
            table_name = self.table_name(kind.fqn)
            if table_name not in self.metadata.tables:
                properties, _ = self.kind_properties(kind)
                Table(
                    self.table_name(kind.fqn),
                    self.metadata,
                    *[
                        Column("_id", String, primary_key=True),
                        *[Column(p.name, self.column_type_from(p.kind)) for p in properties],
                    ],
                )

        def link_table_schema(from_kind: str, to_kind: str) -> None:
            from_table = self.table_name(from_kind)
            to_table = self.table_name(to_kind)
            link_table = self.link_table_name(from_kind, to_kind)
            if (
                link_table not in self.metadata.tables
                and from_table in self.metadata.tables
                and to_table in self.metadata.tables
            ):
                Table(
                    link_table,
                    self.metadata,
                    Column("from_id", String, ForeignKey(f"{from_table}._id")),
                    Column("to_id", String, ForeignKey(f"{to_table}._id")),
                )

        def link_table_schema_from_successors(kind: Kind) -> None:
            _, successors = self.kind_properties(kind)
            # create link table for all linked entities
            for successor in successors:
                link_table_schema(kind.fqn, successor)

        # This set will hold the names of all "base" resources
        # Since that are abstract classes, there will be no instances of them - hence we do not need a table for them.
        base_kinds = {
            clazz.kind
            for _, clazz in inspect.getmembers(baseresources, inspect.isclass)
            if issubclass(clazz, BaseResource)
        }

        # step 1: create tables for all kinds
        for kind in self.model.kinds.values():
            if kind.aggregate_root and kind.runtime_kind is None and kind.fqn not in base_kinds:
                table_schema(kind)
        # step 2: create link tables for all kinds
        for kind in self.model.kinds.values():
            if kind.aggregate_root and kind.runtime_kind is None and kind.fqn not in base_kinds:
                link_table_schema_from_successors(kind)
        return self.metadata


class SqlUpdater:
    def __init__(self, model: SqlModel):
        self.model = model
        self.kind_by_id: Dict[str, str] = {}

    @lru_cache(maxsize=2048)
    def insert(self, kind: str) -> Optional[Insert]:
        table = self.model.metadata.tables.get(kind)
        return table.insert() if table is not None else None

    def insert_value(self, kind: str, values: Any) -> Optional[Insert]:
        maybe_insert = self.insert(kind)
        return maybe_insert.values(values) if maybe_insert is not None else None

    def insert_node(self, node: JsObject) -> Optional[ValuesBase]:
        if node.get("type") == "node" and "id" in node and "reported" in node:
            reported: Json = node.get("reported", {})
            reported["_id"] = node["id"]
            reported["cloud"] = node["ancestors"]["cloud"]["reported"]["id"]
            reported["account"] = node["ancestors"]["account"]["reported"]["id"]
            reported["region"] = node["ancestors"]["region"]["reported"]["id"]
            reported["zone"] = node["ancestors"]["zone"]["reported"]["id"]
            kind = reported.pop("kind")
            self.kind_by_id[node["id"]] = kind
            return self.insert_value(kind, reported)
        elif node.get("type") == "edge" and "from" in node and "to" in node:
            from_id = node["from"]
            to_id = node["to"]
            if (from_kind := self.kind_by_id.get(from_id)) and (to_kind := self.kind_by_id.get(to_id)):
                link_table = self.model.link_table_name(from_kind, to_kind)
                return self.insert_value(link_table, {"from_id": from_id, "to_id": to_id})
        else:
            raise ValueError(f"Unknown node: {node}")


if __name__ == "__main__":
    pass
