from attrs import define, field
from typing import List, ClassVar


@define
class PosthogConfig:
    kind: ClassVar[str] = "posthog"
    api_key: str = field(default="", metadata={"description": "Posthog API Key"})
    url: str = field(default="https://app.posthog.com", metadata={"description": "Posthog url"})
    projects: List[str] = field(
        factory=list,
        metadata={"description": "Posthog projects to collect."},
    )
