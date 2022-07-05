from attrs import define, field
from typing import ClassVar, Dict, Union, List
from resotolib.durations import parse_duration

default_config = {
    "default": {"age": "2h"},
    "tags": ["owner", "expiration"],
    "kinds": [
        "aws_ec2_instance",
        "aws_ec2_volume",
        "aws_vpc",
        "aws_cloudformation_stack",
        "aws_elb",
        "aws_alb",
        "aws_alb_target_group",
        "aws_eks_cluster",
        "aws_eks_nodegroup",
        "example_instance",
        "example_network",
    ],
    "accounts": {
        "aws": {
            "068564737731": {"name": "playground", "age": "7d"},
            "575584959047": {
                "name": "eng-sre",
            },
        },
        "example": {
            "Example Account": {
                "name": "Example Account",
            }
        },
    },
}


@define
class CleanupUntaggedConfig:
    kind: ClassVar[str] = "plugin_cleanup_untagged"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?", "restart_required": True},
    )
    config: Dict[str, Union[Dict, List]] = field(
        factory=lambda: default_config,
        metadata={
            "description": (
                "Configuration for the plugin\n"
                "See https://github.com/someengineering/resoto/tree/main/plugins/cleanup_untagged for syntax details"
            )
        },
    )

    @staticmethod
    def validate(cfg: "CleanupUntaggedConfig") -> bool:
        config = cfg.config
        required_sections = ["tags", "kinds", "accounts"]
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Section '{section}' not found in config")

        if not isinstance(config["tags"], list) or len(config["tags"]) == 0:
            raise ValueError("Error in 'tags' section")

        if not isinstance(config["kinds"], list) or len(config["kinds"]) == 0:
            raise ValueError("Error in 'kinds' section")

        if not isinstance(config["accounts"], dict) or len(config["accounts"]) == 0:
            raise ValueError("Error in 'accounts' section")

        default_age = config.get("default", {}).get("age")
        if default_age is not None:
            default_age = parse_duration(default_age)

        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                if "name" not in account_data:
                    raise ValueError(f"Missing 'name' for account '{cloud_id}/{account_id}")
                if "age" in account_data:
                    account_data["age"] = parse_duration(account_data["age"])
                else:
                    if default_age is None:
                        raise ValueError(
                            f"Missing 'age' for account '{cloud_id}/{account_id}' and no default age defined'"
                        )
                    account_data["age"] = default_age
        return True
