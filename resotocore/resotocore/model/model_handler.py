import logging
import re
from abc import ABC, abstractmethod
from functools import reduce
from typing import Optional, List, Set

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
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        output: str = "svg",
        *,
        with_bases: bool = False,
        with_descendants: bool = False,
    ) -> bytes:
        pass

    @abstractmethod
    async def update_model(self, kinds: List[Kind]) -> Model:
        pass


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
        show_packages: Optional[List[str]] = None,
        hide_packages: Optional[List[str]] = None,
        output: str = "svg",
        *,
        with_bases: bool = False,
        with_descendants: bool = False,
    ) -> bytes:
        assert output in ("svg", "png"), "Only svg and png is supported!"
        model = await self.load_model()
        graph = model.graph()
        show = [re.compile(s) for s in show_packages] if show_packages else None
        hide = [re.compile(s) for s in hide_packages] if hide_packages else None

        def node_visible(key: str) -> bool:
            k: Kind = graph.nodes[key]["data"]
            if hide and exist(lambda r: r.fullmatch(k.fqn), hide):  # type: ignore
                return False
            if show is None:
                return True
            else:
                return exist(lambda r: r.fullmatch(k.fqn), show)  # type: ignore

        def class_node(cpx: ComplexKind) -> str:
            props = "\n".join([f"**{p.name}**: {p.kind}" for p in cpx.properties])
            return f"class {cpx.fqn} {{\n{props}\n}}"

        def class_inheritance(from_node: str, to_node: str) -> str:
            return f"{to_node} <|--- {from_node}"

        def descendants(fqn: str) -> Set[str]:
            return {kind.fqn for kind in model.complex_kinds if fqn in kind.kind_hierarchy()}

        visible_kinds = [node["data"] for nid, node in graph.nodes(data=True) if node_visible(nid)]
        visible = {v.fqn for v in visible_kinds}
        if with_bases:
            bases: Set[str] = reduce(lambda res, cpl: res.union(cpl.kind_hierarchy()), visible_kinds, set())
            visible.update(bases)
        if with_descendants:
            desc: Set[str] = reduce(lambda res, cpl: res.union(descendants(cpl.fqn)), visible_kinds, set())
            visible.update(desc)

        params = (
            "hide empty members\n"
            "skinparam ArrowColor #ffaf37\n"
            "skinparam ArrowThickness 2\n"
            "skinparam BackgroundColor transparent\n"
            "skinparam ClassAttributeFontColor #d9b8ff\n"
            "skinparam ClassBackgroundColor #3d176e\n"
            "skinparam ClassBorderColor #000d19\n"
            "skinparam ClassFontColor #d9b8ff\n"
            "skinparam ClassFontName Helvetica\n"
            "skinparam ClassFontSize 17\n"
            "skinparam Padding 5\n"
            "skinparam RoundCorner 5\n"
            "skinparam Shadowing false\n"
            "skinparam stereotypeCBackgroundColor #e98df7\n"
            "skinparam stereotypeIBackgroundColor #e98df7\n"
        )

        nodes = "\n".join([class_node(node["data"]) for nid, node in graph.nodes(data=True) if nid in visible])
        edges = "\n".join([class_inheritance(fr, to) for fr, to in graph.edges() if fr in visible and to in visible])
        puml = PlantUML(f"{self.plantuml_server}/{output}/")
        return await run_async(puml.processes, f"@startuml\n{params}\n{nodes}\n{edges}\n@enduml")  # type: ignore

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
