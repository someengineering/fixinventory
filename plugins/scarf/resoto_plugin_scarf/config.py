from attrs import define, field
from typing import List, ClassVar


@define
class ScarfConfig:
    kind: ClassVar[str] = "scarf"
    token: str = field(
        default="",
        metadata={"description": "Scarf API token."}
    )
    organizations: List[str] = field(
        factory=list,
        metadata={"description": "Scarf organizations to collect."},
    )
