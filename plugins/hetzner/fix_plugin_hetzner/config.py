from attrs import define, field
from typing import ClassVar, List


@define
class HetznerConfig:
    kind: ClassVar[str] = "hetzner"
    hcloud_project_names: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "Hetzner Cloud project names - Hetzner has no API to introspect a token, so you need to manually maintain"
                " the project name associated with an API token. Provide names in the same order as the corresponding API"
                " tokens."
            )
        },
    )
    hcloud_tokens: List[str] = field(factory=list, metadata={"description": "Hetzner Cloud project API tokens"})
