from dataclasses import dataclass, field
from typing import List, ClassVar, Optional


@dataclass
class OnpremConfig:
    kind: ClassVar[str] = "onprem"
    location: str = field(
        default="Default location", metadata={"description": "On-Prem default location"}
    )
    region: str = field(
        default="Default region", metadata={"description": "On-Prem default region"}
    )
    ssh_user: str = field(default="root", metadata={"description": "On-Prem ssh user"})
    ssh_key: Optional[str] = field(
        default=None, metadata={"description": "On-Prem SSH key"}
    )
    ssh_key_pass: Optional[str] = field(
        default=None, metadata={"description": "On-Prem SSH key passphrase"}
    )
    server: List[str] = field(
        default_factory=list, metadata={"description": "On-Prem server(s)"}
    )
    pool_size: int = field(
        default=5, metadata={"description": "On-Prem thread/process pool size"}
    )
    fork: bool = field(
        default=False,
        metadata={"description": "Fork collector process instead of using threads"},
    )
