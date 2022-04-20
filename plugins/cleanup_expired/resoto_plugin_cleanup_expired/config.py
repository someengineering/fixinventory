from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class CleanupExpiredConfig:
    kind: ClassVar[str] = "plugin_cleanup_expired"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?", "restart_required": True},
    )
