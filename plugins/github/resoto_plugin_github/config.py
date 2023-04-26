from enum import Enum
from attrs import define, field
from typing import List, ClassVar, Optional


class PullRequestState(Enum):
    open = "open"
    closed = "closed"
    all = "all"


class PullRequestSort(Enum):
    created = "created"
    updated = "updated"
    popularity = "popularity"
    long_running = "long-running"


class PullRequestDirection(Enum):
    asc = "asc"
    desc = "desc"


@define
class GithubConfig:
    kind: ClassVar[str] = "github"
    access_token: Optional[str] = field(default=None, metadata={"description": "Github collector access token"})
    organizations: List[str] = field(factory=list, metadata={"description": "Github organizations"})
    repos: List[str] = field(factory=list, metadata={"description": "Github repositories"})
    users: List[str] = field(factory=list, metadata={"description": "Github users"})
    pull_request_state: PullRequestState = field(
        default=PullRequestState.open, metadata={"description": "Github pull request state (open/closed/all)"}
    )
    pull_request_sort: PullRequestSort = field(
        default=PullRequestSort.created,
        metadata={"description": "Github pull request sorting (created/updated/popularity/long-running)"},
    )
    pull_request_direction: PullRequestDirection = field(
        default=PullRequestDirection.desc, metadata={"description": "Github pull request direction (asc/desc)"}
    )
    pull_request_limit: Optional[int] = field(default=None, metadata={"description": "How many pull requests to fetch"})
    pull_request_age: Optional[str] = field(
        default=None, metadata={"description": "Max age of pull requests to fetch (e.g. 7d, 2w, etc.)"}
    )
