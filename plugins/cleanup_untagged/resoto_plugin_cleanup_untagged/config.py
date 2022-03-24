from dataclasses import dataclass, field
from typing import ClassVar, Dict, Union, List
from resotolib.utils import parse_delta

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


@dataclass
class CleanupUntaggedConfig:
    kind: ClassVar[str] = "plugin_cleanup_untagged"
    enabled: bool = field(
        default=False,
        metadata={"description": "Enable plugin?"},
    )
    config: Dict[str, Union[Dict, List]] = field(
        default_factory=lambda: default_config,
        metadata={"description": "Configuration for the plugin"},
    )

    @staticmethod
    def validate(config) -> bool:
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
            default_age = parse_delta(default_age)

        for cloud_id, account in config["accounts"].items():
            for account_id, account_data in account.items():
                if "name" not in account_data:
                    raise ValueError(
                        f"Missing 'name' for account '{cloud_id}/{account_id}"
                    )
                if "age" in account_data:
                    account_data["age"] = parse_delta(account_data["age"])
                else:
                    if default_age is None:
                        raise ValueError(
                            f"Missing 'age' for account '{cloud_id}/{account_id}' and no default age defined'"
                        )
                    account_data["age"] = default_age
        return True
