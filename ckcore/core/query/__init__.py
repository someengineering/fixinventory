from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, List

from core.types import Json


@dataclass
class Expandable:
    template: str
    props: Json


class TemplateExpander(ABC):
    @abstractmethod
    async def render(self, maybe_template: str) -> Tuple[str, List[Expandable]]:
        pass
