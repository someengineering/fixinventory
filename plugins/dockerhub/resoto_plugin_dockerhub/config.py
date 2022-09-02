from attrs import define, field
from typing import List, ClassVar


@define
class DockerHubConfig:
    kind: ClassVar[str] = "dockerhub"
    namespaces: List[str] = field(
        factory=list,
        metadata={"description": "Docker Hub namespaces to collect."},
    )
