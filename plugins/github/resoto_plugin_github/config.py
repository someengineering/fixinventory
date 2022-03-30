from dataclasses import dataclass, field
from typing import List, ClassVar, Optional


@dataclass
class GithubConfig:
    kind: ClassVar[str] = "github"
    access_token: Optional[str] = field(
        default=None, metadata={"description": "Github collector access token"}
    )
    organizations: List[str] = field(
        default_factory=list, metadata={"description": "Github organizations"}
    )
    repos: List[str] = field(
        default_factory=list, metadata={"description": "Github repositories"}
    )
    users: List[str] = field(
        default_factory=list, metadata={"description": "Github users"}
    )
    pool_size: int = field(
        default=5, metadata={"description": "Github thread pool size"}
    )
