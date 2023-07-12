import os
from typing import ClassVar, Optional, Dict, List

from attr import define, field
from azure.identity import DefaultAzureCredential


@define
class AzureAccountConfig:
    kind: ClassVar[str] = "azure_account"

    env_vars: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Environment variables to set"})
    subscriptions: Optional[List[str]] = field(
        default=None, metadata={"description": "If not defined, all subscriptions that are found will be collected."}
    )
    exclude_subscriptions: Optional[List[str]] = field(
        default=None, metadata={"description": "Subscriptions to exclude"}
    )

    def credentials(self) -> DefaultAzureCredential:
        # update env vars if defined
        if self.env_vars:
            os.environ.update(self.env_vars)
        return DefaultAzureCredential()


@define
class AzureConfig:
    kind: ClassVar[str] = "azure"

    resource_pool_size: int = field(
        default=10, metadata={"description": "Number of threads to use for resource collection"}
    )
    accounts: List[AzureAccountConfig] = field(
        factory=list, metadata={"description": "Configure accounts to collect subscriptions."}
    )
