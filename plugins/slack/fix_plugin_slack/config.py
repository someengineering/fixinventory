from attrs import define, field
from typing import ClassVar, Optional


@define
class SlackConfig:
    kind: ClassVar[str] = "slack"
    bot_token: Optional[str] = field(default=None, metadata={"description": "Bot token"})
    include_archived: bool = field(default=False, metadata={"description": "Include archived channels"})
    do_not_verify_ssl: bool = field(
        default=False,
        metadata={"description": "Do not verify the Slack API server TLS certificate"},
    )
