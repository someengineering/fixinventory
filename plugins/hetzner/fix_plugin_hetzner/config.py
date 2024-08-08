from attrs import define, field
from typing import ClassVar, List


@define
class HetznerConfig:
    kind: ClassVar[str] = "hetzner"
    hcloud_project_names: List[str] = field(factory=list, metadata={"description": "Hetzner Cloud project names"})
    hcloud_tokens: List[str] = field(factory=list, metadata={"description": "Hetzner Cloud project API tokens"})
