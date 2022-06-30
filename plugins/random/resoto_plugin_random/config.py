from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class RandomConfig:
    kind: ClassVar[str] = "random"
    seed: int = field(default=0, metadata={"description": "Random Seed"})
