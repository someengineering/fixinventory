from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from functools import reduce, lru_cache
from typing import Optional, List, Set, Callable, Dict, Iterator

from plantuml import PlantUML

from fixcore.async_extensions import run_async
from fixcore.db.db_access import DbAccess
from fixcore.ids import GraphName, valid_root_graph_name
from fixcore.model.model import Model, Kind, ComplexKind, Property
from fixcore.model.typed_model import from_js
from fixcore.service import Service
from fixcore.types import EdgeType
from fixcore.util import exist
from fixlib.core.model_check import load_plugin_classes
from fixlib.graph import export_model

log = logging.getLogger(__name__)


class ModelHandler(ABC):
    @abstractmethod
    async def load_model(self, graph_name: GraphName, *, force: bool = False) -> Model:
        pass

    @abstractmethod
    async def uml_image(
        self,
        graph_name: GraphName,
        output: str = "svg",
        *,
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        with_inheritance: bool = True,
        with_base_classes: bool = False,
        with_subclasses: bool = False,
        dependency_edges: Optional[Set[EdgeType]] = None,
        with_predecessors: bool = False,
        with_successors: bool = False,
        with_properties: bool = True,
        link_classes: bool = False,
        only_aggregate_roots: bool = True,
        sort_props: bool = True,
    ) -> bytes:
        """
        Generate a PlantUML image of the model.

        :param graph_name: the name of the graph
        :param output: "svg" or "png"
        :param show_packages: regexp that matches packages to show
        :param hide_packages: regexp that matches packages to hide
        :param with_inheritance: draw inheritance relationship between classes
        :param with_base_classes: include base classes for all matching classes to show in the diagram
        :param with_subclasses: include subclasses for all matching classes to show in the diagram
        :param dependency_edges: draw dependency edges of given edge type between classes
        :param with_predecessors: include predecessors for all matching classes to show in the diagram
        :param with_successors: include successors for all matching classes to show in the diagram
        :param with_properties: include properties for all matching classes to show in the diagram
        :param link_classes: add anchor links to all classes
        :param only_aggregate_roots: if the list of classes should be filtered for aggregate roots
        :param sort_props: if the properties should be sorted by name
        :return: the generated image
        """

    @abstractmethod
    async def update_model(self, graph_name: GraphName, kinds: List[Kind], replace: bool) -> Model:
        pass


PlantUmlAttrs = (
    "hide empty members\n"
    "skinparam ArrowColor #ffaf37\n"
    "skinparam ArrowFontColor #ffaf37\n"
    "skinparam ArrowFontName Helvetica\n"
    "skinparam ArrowThickness 2\n"
    "skinparam BackgroundColor transparent\n"
    "skinparam ClassAttributeFontColor #d9b8ff\n"
    "skinparam ClassBackgroundColor #3d176e\n"
    "skinparam ClassBorderColor #000d19\n"
    "skinparam ClassFontColor #d9b8ff\n"
    "skinparam ClassFontName Helvetica\n"
    "skinparam ClassFontSize 17\n"
    "skinparam NoteBackgroundColor #d9b8ff\n"
    "skinparam NoteBorderColor #000d19\n"
    "skinparam NoteFontColor #3d176e\n"
    "skinparam NoteFontName Helvetica\n"
    "skinparam Padding 5\n"
    "skinparam RoundCorner 5\n"
    "skinparam Shadowing false\n"
    "skinparam stereotypeCBackgroundColor #e98df7\n"
    "skinparam stereotypeIBackgroundColor #e98df7\n"
)


class ModelHandlerDB(ModelHandler, Service):
    def __init__(self, db_access: DbAccess, plantuml_server: str = "https://plantuml.fix.org"):
        super().__init__()
        self.db_access = db_access
        self.plantuml_server = plantuml_server
        self.__loaded_model: Dict[GraphName, Model] = {}

    async def load_model(self, graph_name: GraphName, *, force: bool = False) -> Model:
        if not force and (model := self.__loaded_model.get(graph_name)) is not None:
            return model
        else:
            graph_model_db = await self.db_access.get_graph_model_db(graph_name)
            model = Model.from_kinds([kind async for kind in graph_model_db.all()])
            self.__loaded_model[graph_name] = model
            return model

    async def uml_image(
        self,
        graph_name: GraphName,
        output: str = "svg",
        *,
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        with_inheritance: bool = True,
        with_base_classes: bool = False,
        with_subclasses: bool = False,
        dependency_edges: Optional[Set[EdgeType]] = None,
        with_predecessors: bool = False,
        with_successors: bool = False,
        with_properties: bool = True,
        link_classes: bool = False,
        only_aggregate_roots: bool = True,
        sort_props: bool = True,
    ) -> bytes:
        allowed_edge_types: Set[EdgeType] = dependency_edges or set()
        assert output in ("svg", "png", "puml"), "Only svg, png and puml is supported!"
        model = await self.load_model(graph_name)
        graph = model.graph()
        show = [re.compile(s) for s in show_packages] if show_packages else None
        hide = [re.compile(s) for s in hide_packages] if hide_packages else None
        visited_complex: Set[str] = set()

        def not_hidden(key: str) -> bool:
            k: Kind = graph.nodes[key]["data"]
            return not (hide and exist(lambda r: r.fullmatch(k.fqn), hide))

        def node_visible(key: str) -> bool:
            k: Kind = graph.nodes[key]["data"]
            ar_visible = not only_aggregate_roots or getattr(k, "aggregate_root", False)
            if hide and exist(lambda r: r.fullmatch(k.fqn), hide):
                return False
            if show is None:
                return ar_visible
            else:
                return ar_visible and exist(lambda r: r.fullmatch(k.fqn), show)

        def class_node(cpx: ComplexKind) -> str:
            sth = {k.prop.name: k for k in cpx.synthetic_props() if len(k.path.path) == 1}

            def kind_name(p: Property) -> str:
                return (sth[p.name].simple_kind.runtime_kind if p.name in sth else p.kind) if p.synthetic else p.kind

            cpx_props = sorted(cpx.properties, key=lambda p: p.name) if sort_props else cpx.properties
            props = "\n".join([f"**{p.name}**: {kind_name(p)}" for p in cpx_props]) if with_properties else ""
            link = f" [[#{cpx.fqn}]]" if link_classes else ""
            return f"class {cpx.fqn}{link} {{\n{props}\n}}"

        def descendants(cpx: ComplexKind) -> Set[str]:
            return {kind.fqn for kind in model.complex_kinds() if cpx.fqn in kind.kind_hierarchy()}

        def predecessors(cpx: ComplexKind) -> Set[str]:
            return {
                kind.fqn
                for kind in model.complex_kinds()
                for et in allowed_edge_types
                if cpx.fqn in kind.successor_kinds.get(et, [])
            }

        def successors(cpx: ComplexKind) -> Set[str]:
            return (
                {kind for et in allowed_edge_types for kind in cpx.successor_kinds.get(et, [])}
                if isinstance(cpx, ComplexKind)
                else set()
            )

        def complex_property_kinds(cpx: ComplexKind) -> Set[str]:
            if cpx.fqn in visited_complex:
                return set()
            visited_complex.add(cpx.fqn)
            result: Set[str] = set()
            for _, k in cpx.property_with_kinds():
                for cpl in k.nested_complex_kinds():
                    result.add(cpl.fqn)
                    result.update(complex_property_kinds(cpl))
            return result

        visible_kinds = [node["data"] for nid, node in graph.nodes(data=True) if node_visible(nid)]
        visible = {v.fqn for v in visible_kinds}

        def add_visible(fn: Callable[[ComplexKind], Set[str]]) -> None:
            selected: Set[str] = reduce(lambda res, cpl: res.union(fn(cpl)), visible_kinds, set())
            visible.update(n for n in selected if not_hidden(n))

        if with_base_classes:
            add_visible(lambda cpl: cpl.kind_hierarchy())
        if with_subclasses:
            add_visible(descendants)
        if with_predecessors:
            add_visible(predecessors)
        if with_successors:
            add_visible(successors)
        if with_properties:
            add_visible(complex_property_kinds)

        visible_nodes: Iterator[ComplexKind] = (node["data"] for nid, node in graph.nodes(data=True) if nid in visible)
        nodes = "\n".join(class_node(node) for node in sorted(visible_nodes, key=lambda n: n.fqn))
        edges = ""
        for fr, to, data in sorted(graph.edges(data=True), key=lambda e: (e[0], e[1])):
            if fr in visible and to in visible:
                if with_inheritance and data["type"] == "inheritance":
                    edges += f"{to} <|--- {fr}\n"
                elif data["type"] == "successor" and data["edge_type"] in allowed_edge_types:
                    edges += f"{fr} -[#1A83AF]-> {to}\n"
                elif data["type"] == "property" and with_properties:
                    edges += f"{fr} --> {to}\n"

        puml = f"@startuml\n{PlantUmlAttrs}\n{nodes}\n{edges}\n@enduml"
        if output == "puml":
            return puml.encode("utf-8")
        else:
            plant_uml = PlantUML(f"{self.plantuml_server}/{output}/")
            return await run_async(plant_uml.processes, puml)

    async def update_model(self, graph_name: GraphName, kinds: List[Kind], replace: bool) -> Model:
        # load existing model
        model = await self.load_model(graph_name)
        # make sure the update is valid
        updated = model.update_kinds(kinds, replace=replace)
        # store all updated kinds
        db = await self.db_access.get_graph_model_db(graph_name)
        await db.update_many(kinds)
        if deleted := set(model.kinds) - set(updated.kinds):
            log.info(f"Deleted kinds: {deleted}")
            await db.delete_many(list(deleted))
        # unset loaded model
        self.__loaded_model[graph_name] = updated
        return updated


@lru_cache
def code_model() -> Model:
    """
    The model is only loaded on demand and only once.
    """
    load_plugin_classes()
    return Model.from_kinds([from_js(m, Kind) for m in export_model()])  # type: ignore


class ModelHandlerFromCodeAndDB(ModelHandlerDB):
    async def load_model(self, graph_name: GraphName, *, force: bool = False) -> Model:
        if valid_root_graph_name(graph_name):
            return code_model()
        else:
            return await super().load_model(graph_name, force=force)

    @staticmethod
    def on_startup() -> None:
        # make sure the model is loaded on startup
        code_model()
