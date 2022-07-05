from attrs import define, field
from typing import ClassVar, Optional


@define
class VSphereConfig:
    kind: ClassVar[str] = "vsphere"
    user: Optional[str] = field(default=None, metadata={"description": "User name"})
    password: Optional[str] = field(default=None, metadata={"description": "Password"})
    host: Optional[str] = field(default=None, metadata={"description": "Host name/address"})
    port: int = field(default=443, metadata={"description": "TCP port"})
    insecure: bool = field(
        default=True,
        metadata={"description": "Allow insecure connection. Do not verify certificates."},
    )
