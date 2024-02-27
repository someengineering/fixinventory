from attrs import define
from typing import Dict, Any


@define
class FakeConfig:
    values: Dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        value = self.values[name]
        if isinstance(value, dict):
            return FakeConfig(value)
        else:
            return value
