from attrs import define, field
from typing import List, ClassVar, Optional


@define
class DigitalOceanSpacesKeys:
    kind: ClassVar[str] = "digitalocean_spaces_keys"
    access_key: str = field(metadata={"description": "DigitalOcean Spaces access key."})
    secret_key: str = field(metadata={"description": "DigitalOcean Spaces secret key."})


@define
class DigitalOceanTeamCredentials:
    kind: ClassVar[str] = "digitalocean_team_credentials"
    api_token: str = field(metadata={"description": "DigitalOcean API token for the team to be collected."})
    spaces_keys: Optional[DigitalOceanSpacesKeys] = field(
        default=None,
        metadata={"description": "DigitalOcean Spaces access and secret key pair to collect the team's Spaces."},
    )


@define
class DigitalOceanCollectorConfig:
    kind: ClassVar[str] = "digitalocean"
    api_tokens: List[str] = field(
        factory=list,
        metadata={
            "description": "Deprecated. Use credentials instead. DigitalOcean API tokens for the teams to be collected"
        },
    )
    spaces_access_keys: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "Deprecated. Use credentials instead. DigitalOcean Spaces access keys for "
                "the teams to be collected, separated by colons"
            )
        },
    )
    credentials: List[DigitalOceanTeamCredentials] = field(
        factory=list,
        metadata={
            "description": (
                "DigitalOcean credentials for the teams to be collected. "
                "Expected format: [{ 'api_token': 'foo', 'spaces_keys': {'access_key': 'bar', 'secret_key': 'baz'}}]. "
                "If provided, api_tokens and spaces_access_keys will be ignored"
            )
        },
    )
