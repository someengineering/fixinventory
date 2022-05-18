import logging
import re
from abc import ABC, abstractmethod
from functools import reduce
from typing import Optional, List, Set, Callable

from plantuml import PlantUML

from resotocore.async_extensions import run_async
from resotocore.db.modeldb import ModelDb
from resotocore.model.model import Model, Kind, ComplexKind
from resotocore.util import exist

log = logging.getLogger(__name__)


class ModelHandler(ABC):
    @abstractmethod
    async def load_model(self) -> Model:
        pass

    @abstractmethod
    async def uml_image(
        self,
        output: str = "svg",
        *,
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        with_inheritance: bool = True,
        with_base_classes: bool = False,
        with_subclasses: bool = False,
        dependency_edges: Optional[Set[str]] = None,
        with_predecessors: bool = False,
        with_successors: bool = False,
        with_properties: bool = True,
        link_classes: bool = False,
    ) -> bytes:
        """
        Generate a PlantUML image of the model.

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
        :return: the generated image
        """

    @abstractmethod
    async def update_model(self, kinds: List[Kind]) -> Model:
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


class ModelHandlerDB(ModelHandler):
    def __init__(self, db: ModelDb, plantuml_server: str):
        self.db = db
        self.plantuml_server = plantuml_server
        self.__loaded_model: Optional[Model] = None

    async def load_model(self) -> Model:
        if self.__loaded_model:
            return self.__loaded_model
        else:
            kinds = [kind async for kind in self.db.all()]
            model = Model.from_kinds(list(kinds))
            self.__loaded_model = model
            return model

    async def uml_image(
        self,
        output: str = "svg",
        *,
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        with_inheritance: bool = True,
        with_base_classes: bool = False,
        with_subclasses: bool = False,
        dependency_edges: Optional[Set[str]] = None,
        with_predecessors: bool = False,
        with_successors: bool = False,
        with_properties: bool = True,
        link_classes: bool = False,
    ) -> bytes:
        allowed_edge_types: Set[str] = dependency_edges or set()
        assert output in ("svg", "png"), "Only svg and png is supported!"
        model = await self.load_model()
        graph = model.graph()
        show = [re.compile(s) for s in show_packages] if show_packages else None
        hide = [re.compile(s) for s in hide_packages] if hide_packages else None

        def not_hidden(key: str) -> bool:
            k: Kind = graph.nodes[key]["data"]
            return not (hide and exist(lambda r: r.fullmatch(k.fqn), hide))

        def node_visible(key: str) -> bool:
            k: Kind = graph.nodes[key]["data"]
            if hide and exist(lambda r: r.fullmatch(k.fqn), hide):
                return False
            if show is None:
                return True
            else:
                return exist(lambda r: r.fullmatch(k.fqn), show)

        def class_node(cpx: ComplexKind) -> str:
            props = "\n".join([f"**{p.name}**: {p.kind}" for p in cpx.properties]) if with_properties else ""
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

        nodes = "\n".join([class_node(node["data"]) for nid, node in graph.nodes(data=True) if nid in visible])
        edges = ""
        for fr, to, data in graph.edges(data=True):
            if fr in visible and to in visible:
                if with_inheritance and data["type"] == "inheritance":
                    edges += f"{to} <|--- {fr}\n"
                elif data["type"] == "successor" and data["edge_type"] in allowed_edge_types:
                    edges += f"{fr} -[#1A83AF]-> {to}\n"

        puml = PlantUML(f"{self.plantuml_server}/{output}/")
        return await run_async(puml.processes, f"@startuml\n{PlantUmlAttrs}\n{nodes}\n{edges}\n@enduml")  # type: ignore

    async def update_model(self, kinds: List[Kind]) -> Model:
        # load existing model
        model = await self.load_model()
        # make sure the update is valid
        updated = model.update_kinds(kinds)
        # store all updated kinds
        await self.db.update_many(kinds)
        # unset loaded model
        self.__loaded_model = updated
        return updated
