from typing import Optional, List, Set, Any

from fixcore.model.model import Model, Kind
from fixcore.model.model_handler import ModelHandler
from fixcore.types import EdgeType
from fixcore.ids import GraphName


class ModelHandlerStatic(ModelHandler):
    def __init__(self, model: Model):
        self.model = model

    async def load_model(self, graph_name: GraphName, **kwargs: Any) -> Model:
        return self.model

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
        raise NotImplementedError

    async def update_model(self, graph_name: GraphName, kinds: List[Kind], replace: bool) -> Model:
        self.model = Model.from_kinds(kinds)
        return self.model
