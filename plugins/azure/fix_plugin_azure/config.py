from fnmatch import fnmatch
from typing import ClassVar, Optional, Dict, List, Union

from attr import define, field
from azure.identity import DefaultAzureCredential, ClientSecretCredential

AzureCredentials = Union[DefaultAzureCredential, ClientSecretCredential]


@define
class AzureClientSecretConfig:
    kind: ClassVar[str] = "azure_client_secret"
    tenant_id: str = field(metadata={"description": "Azure tenant ID"})
    client_id: str = field(metadata={"description": "Azure client ID"})
    client_secret: str = field(metadata={"description": "Azure client secret"})


@define
class AzureAccountConfig:
    kind: ClassVar[str] = "azure_account"

    client_secret: Optional[AzureClientSecretConfig] = field(
        default=None,
        metadata={
            "description": "If you can not provide access via the environment, define access with a client secret.\nIf no secret is provided the default credential chain will be used.\nSee https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-authenticate?tabs=cmd#environment-variables for more information."  # noqa: E501
        },
    )
    subscriptions: Optional[List[str]] = field(
        default=None, metadata={"description": "If not defined, all subscriptions that are found will be collected."}
    )
    exclude_subscriptions: Optional[List[str]] = field(
        default=None, metadata={"description": "Subscriptions to exclude"}
    )
    collect_microsoft_graph: Optional[bool] = field(
        default=True, metadata={"description": "Collect Microsoft Graph Organizations"}
    )

    def credentials(self) -> AzureCredentials:
        # update env vars if defined
        if cs := self.client_secret:
            return ClientSecretCredential(
                tenant_id=cs.tenant_id,
                client_id=cs.client_id,
                client_secret=cs.client_secret,
            )

        return DefaultAzureCredential(process_timeout=300)

    def allowed(self, subscription_id: str) -> bool:
        if self.subscriptions is not None:
            return subscription_id in self.subscriptions
        if self.exclude_subscriptions is not None:
            return subscription_id not in self.exclude_subscriptions
        return True


@define
class AzureConfig:
    kind: ClassVar[str] = "azure"

    subscription_pool_size: int = field(
        default=4, metadata={"description": "Number of concurrent subscriptions to collect."}
    )

    resource_pool_size: int = field(
        default=64,
        metadata={"description": "Number of shared threads available per subscription."},
    )

    accounts: Optional[Dict[str, AzureAccountConfig]] = field(
        factory=lambda: {"default": AzureAccountConfig()},
        metadata={"description": "Configure accounts to collect subscriptions. You can define multiple accounts here."},
    )

    discard_account_on_resource_error: bool = field(
        default=False,
        metadata={
            "description": "Fail the whole account if collecting a resource fails. "
            "If false, the error is logged and the resource is skipped."
        },
    )

    collect_usage_metrics: Optional[bool] = field(
        default=True,
        metadata={"description": "Collect resource usage metrics via Azure Metric, enabled by default"},
    )
    collect: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "List of Azure services to collect (default: all).\n"
                "You can use GLOB patterns like ? and * to match multiple services."
            )
        },
    )
    no_collect: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "List of Azure services to exclude (default: none).\n"
                "You can use GLOB patterns like ? and * to match multiple services."
            )
        },
    )

    def should_collect(self, name: str) -> bool:
        # no_collect has precedence over collect
        if self.no_collect and any(fnmatch(name, p) for p in self.no_collect):
            return False
        if self.collect:
            return any(fnmatch(name, p) for p in self.collect)
        return True
