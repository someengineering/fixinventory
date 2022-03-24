from dataclasses import dataclass, field
from typing import ClassVar
from resotolib.utils import parse_delta


@dataclass
class CleanupVolumesConfig:
    kind: ClassVar[str] = "plugin_cleanup_volumes"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?"},
    )
    age: str = field(
        default="14 days",
        metadata={"description": "Minimum age of unused volumes to delete"},
    )

    @staticmethod
    def validate(config: "CleanupVolumesConfig") -> bool:
        try:
            parse_delta(config.age)
        except ValueError:
            return False
        return True
