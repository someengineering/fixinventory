from dataclasses import dataclass, field
from typing import ClassVar, Optional


@dataclass
class VSphereConfig:
    kind: ClassVar[str] = "vsphere"
    user: Optional[str] = field(
        default=None, metadata={"description": "vSphere user name"}
    )
    password: Optional[str] = field(
        default=None, metadata={"description": "vSphere user password"}
    )
    host: Optional[str] = field(
        default=None, metadata={"description": "vSphere host name/address"}
    )
    port: int = field(default=443, metadata={"description": "vSphere port"})
    insecure: bool = field(
        default=True,
        metadata={
            "description": "Allow insecure connection. Do not verify certificates."
        },
    )
