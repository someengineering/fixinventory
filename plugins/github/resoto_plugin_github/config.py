from enum import Enum
from attrs import define, field
from typing import List, ClassVar, Optional


class PullRequestState(Enum):
    open = "open"
    closed = "closed"
    all = "all"


@define
class GithubConfig:
    kind: ClassVar[str] = "github"
    access_token: Optional[str] = field(default=None, metadata={"description": "Github collector access token"})
    organizations: List[str] = field(factory=list, metadata={"description": "Github organizations"})
    repos: List[str] = field(factory=list, metadata={"description": "Github repositories"})
    users: List[str] = field(factory=list, metadata={"description": "Github users"})
    pool_size: int = field(default=5, metadata={"description": "Github thread pool size"})
    pull_request_state: PullRequestState = field(
        default=PullRequestState.open, metadata={"description": "Github pull request state"}
    )
