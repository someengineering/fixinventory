from attrs import define, field
from typing import ClassVar, Optional


@define
class OneloginConfig:
    kind: ClassVar[str] = "onelogin"
    region: str = field(default="us", metadata={"description": "Onelogin region"})
    client_id: Optional[str] = field(default=None, metadata={"description": "Onelogin client ID"})
    client_secret: Optional[str] = field(default=None, metadata={"description": "Onelogin client secret"})
