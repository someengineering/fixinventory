from typing import Optional, List, Set

from resotocore.model.model import Model, Kind
from resotocore.model.model_handler import ModelHandler
from resotocore.types import EdgeType


class ModelHandlerStatic(ModelHandler):
    def __init__(self, model: Model):
        self.model = model

    async def load_model(self) -> Model:
        return self.model

    async def uml_image(
        self,
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
        filter_aggregate_roots: bool = False,
    ) -> bytes:
        raise NotImplemented

    async def update_model(self, kinds: List[Kind]) -> Model:
        self.model = Model.from_kinds(kinds)
        return self.model
