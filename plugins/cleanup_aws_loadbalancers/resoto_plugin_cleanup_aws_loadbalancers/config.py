from dataclasses import dataclass, field
from typing import ClassVar
from resotolib.utils import parse_delta


@dataclass
class CleanupAWSLoadbalancersConfig:
    kind: ClassVar[str] = "plugin_cleanup_aws_loadbalancers"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?"},
    )
    min_age: str = field(
        default="7 days",
        metadata={"description": "Minimum age of unused load balancers to cleanup"},
    )

    @staticmethod
    def validate(config: "CleanupAWSLoadbalancersConfig") -> bool:
        try:
            parse_delta(config.min_age)
        except ValueError:
            return False
        return True
