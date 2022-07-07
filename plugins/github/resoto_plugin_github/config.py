from attrs import define, field
from typing import List, ClassVar, Optional


@define
class GithubConfig:
    kind: ClassVar[str] = "github"
    access_token: Optional[str] = field(default=None, metadata={"description": "Github collector access token"})
    organizations: List[str] = field(factory=list, metadata={"description": "Github organizations"})
    repos: List[str] = field(factory=list, metadata={"description": "Github repositories"})
    users: List[str] = field(factory=list, metadata={"description": "Github users"})
    pool_size: int = field(default=5, metadata={"description": "Github thread pool size"})
