from dataclasses import dataclass, field
from typing import List, ClassVar


@dataclass
class DigitalOceanCollectorConfig:
    kind: ClassVar[str] = "digitalocean"
    api_tokens: List[str] = field(
        default_factory=list,
        metadata={
            "description": "DigitalOcean API tokens for the teams to be collected"
        },
    )
    spaces_access_keys: List[str] = field(
        default_factory=list,
        metadata={
            "description": "DigitalOcean Spaces access keys for the teams to be collected, separated by colons"
        },
    )
