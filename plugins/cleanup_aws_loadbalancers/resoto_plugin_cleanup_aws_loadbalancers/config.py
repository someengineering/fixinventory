from attrs import define, field
from typing import ClassVar
from resotolib.durations import parse_duration


@define
class CleanupAWSLoadbalancersConfig:
    kind: ClassVar[str] = "plugin_cleanup_aws_loadbalancers"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?", "restart_required": True},
    )
    min_age: str = field(
        default="7 days",
        metadata={
            "description": "Minimum age of unused load balancers to cleanup",
            "type_hint": "duration",
        },
    )

    @staticmethod
    def validate(config: "CleanupAWSLoadbalancersConfig") -> bool:
        parse_duration(config.min_age)
        return True
