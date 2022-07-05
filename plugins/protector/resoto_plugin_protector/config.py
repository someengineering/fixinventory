from attrs import define, field
from typing import ClassVar, Dict, List


default_config = {
    "example": {
        "Example Account": {
            "us-west": {"example_instance": ["someInstance1"]},
        },
    },
}


@define
class ProtectorConfig:
    kind: ClassVar[str] = "plugin_protector"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?", "restart_required": True},
    )
    config: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]] = field(
        factory=lambda: default_config,
        metadata={
            "description": (
                "Configuration for the plugin\n"
                "Format:\n"
                "  cloud.id:\n"
                "    account.id:\n"
                "      region.id:\n"
                "        kind:\n"
                "          - resource.id"
            )
        },
    )

    @staticmethod
    def validate(cfg: "ProtectorConfig") -> bool:
        config = cfg.config
        if not isinstance(config, dict):
            raise ValueError("Config is no dict")

        for cloud_id, account_data in config.items():
            if not isinstance(cloud_id, str):
                raise ValueError(f"Cloud ID {cloud_id} is no string")
            if not isinstance(account_data, dict):
                raise ValueError(f"Account Data {account_data} is no dict")

            for account_id, region_data in account_data.items():
                if not isinstance(account_id, str):
                    raise ValueError(f"Account ID {account_id} is no string")
                if not isinstance(region_data, dict):
                    raise ValueError(f"Region Data {region_data} is no dict")

                for region_id, resource_data in region_data.items():
                    if not isinstance(region_id, str):
                        raise ValueError(f"Region ID {region_id} is no string")
                    if not isinstance(resource_data, dict):
                        raise ValueError(f"Resource Data {resource_data} is no dict")

                    for kind, resource_list in resource_data.items():
                        if not isinstance(kind, str):
                            raise ValueError(f"Resource Kind {kind} is no string")
                        if not isinstance(resource_list, list):
                            raise ValueError(f"Resource List {resource_list} is no list")

                        for resource_id in resource_list:
                            if not isinstance(resource_id, str):
                                raise ValueError(f"Resource ID {resource_id} is no string")
        return True
