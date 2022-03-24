from dataclasses import dataclass, field
from typing import ClassVar, Optional


@dataclass
class OneloginConfig:
    kind: ClassVar[str] = "onelogin"
    region: str = field(default="us", metadata={"description": "Onelogin region"})
    client_id: Optional[str] = field(
        default=None, metadata={"description": "Onelogin Client ID"}
    )
    client_secret: Optional[str] = field(
        default=None, metadata={"description": "Onelogin Client Secret"}
    )
