from attrs import define, field
from typing import List, ClassVar


@define
class ScarfConfig:
    kind: ClassVar[str] = "scarf"
    email: str = field(default="", metadata={"description": "Scarf Email"})
    password: str = field(default="", metadata={"description": "Scarf Password"})
    organizations: List[str] = field(
        factory=list,
        metadata={"description": "Scarf organizations to collect."},
    )
