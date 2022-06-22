from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class FakeConfig:
    values: Dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        value = self.values[name]
        if isinstance(value, dict):
            return FakeConfig(value)
        else:
            return value
