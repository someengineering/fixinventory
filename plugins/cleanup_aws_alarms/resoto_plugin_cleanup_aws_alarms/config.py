from attrs import define, field
from typing import ClassVar, Dict, List


@define
class CleanupAWSAlarmsConfig:
    kind: ClassVar[str] = "plugin_cleanup_aws_alarms"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?", "restart_required": True},
    )
    config: Dict[str, List[str]] = field(
        factory=lambda: {"aws": ["1234567", "567890"]},
        metadata={
            "description": (
                "Dictionary of key cloud with list of account IDs" " for which the plugin should be active as value"
            )
        },
    )

    @staticmethod
    def validate(config: Dict) -> bool:
        if not isinstance(config, dict):
            raise ValueError("Config is no dict")

        for cloud_id, account_ids in config.items():
            if not isinstance(cloud_id, str):
                raise ValueError(f"Cloud ID {cloud_id} is no string")
            if not isinstance(account_ids, list):
                raise ValueError(f"Account IDs {account_ids} is no list")

            for account_id in account_ids:
                if not isinstance(account_id, str):
                    raise ValueError(f"Account ID {account_id} is no string")
        return True
