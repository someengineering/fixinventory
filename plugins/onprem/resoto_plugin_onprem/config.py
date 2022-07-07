from attrs import define, field
from typing import List, ClassVar, Optional


@define
class OnpremConfig:
    kind: ClassVar[str] = "onprem"
    location: str = field(default="Default location", metadata={"description": "Default location"})
    region: str = field(default="Default region", metadata={"description": "Default region"})
    ssh_user: str = field(default="root", metadata={"description": "SSH user"})
    ssh_key: Optional[str] = field(default=None, metadata={"description": "SSH key"})
    ssh_key_pass: Optional[str] = field(default=None, metadata={"description": "SSH key passphrase"})
    server: List[str] = field(factory=list, metadata={"description": "Server(s)"})
    pool_size: int = field(default=5, metadata={"description": "Thread/process pool size"})
    fork_process: bool = field(
        default=True,
        metadata={"description": "Fork collector process instead of using threads"},
    )
