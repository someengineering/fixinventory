from datetime import datetime
from attrs import define
from typing import Optional, ClassVar, List, Dict
from resotolib.graph import Graph
from resotolib.baseresources import (
    BaseAccount,
    BaseResource,
)


@define(eq=False, slots=False)
class DockerHubResource:
    kind: ClassVar[str] = "dockerhub_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class DockerHubNamespace(DockerHubResource, BaseAccount):
    kind: ClassVar[str] = "dockerhub_namespace"

    count: Optional[int] = None


@define(eq=False, slots=False)
class DockerHubRepository(DockerHubResource, BaseResource):
    kind: ClassVar[str] = "dockerhub_repository"

    repository_type: Optional[str] = None
    is_private: Optional[bool] = None
    star_count: Optional[int] = None
    pull_count: Optional[int] = None
    affiliation: Optional[str] = None
    media_types: Optional[List[str]] = None

    @staticmethod
    def new(data: Dict) -> BaseResource:
        # Docker Hub API returns [None] for media types
        # This removes all None values from the list
        media_types = list(filter((None).__ne__, data.get("media_types", [])))
        if len(media_types) == 0:
            media_types = None
        return DockerHubRepository(
            id=data.get("name"),
            repository_type=data.get("repository_type"),
            is_private=data.get("is_private"),
            star_count=data.get("star_count"),
            pull_count=data.get("pull_count"),
            mtime=convert_date(data.get("last_updated")),
            ctime=convert_date(data.get("date_registered")),
            affiliation=data.get("affiliation"),
            media_types=media_types,
        )


def convert_date(date_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
