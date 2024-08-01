import logging
import multiprocessing
from collections import namedtuple
from concurrent.futures import as_completed, ThreadPoolExecutor
from enum import Enum
from typing import Optional, Tuple, Any, List, TypeVar, Type

from fix_plugin_azure.azure_client import MicrosoftClient
from fix_plugin_azure.collector import (
    AzureSubscriptionCollector,
    MicrosoftGraphOrganizationCollector,
    MicrosoftBaseCollector,
)
from fix_plugin_azure.config import AzureConfig, AzureAccountConfig, AzureCredentials
from fix_plugin_azure.resource.base import AzureSubscription, MicrosoftResource
from fix_plugin_azure.resource.microsoft_graph import MicrosoftGraphOrganization
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import Cloud, BaseAccount
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.core.progress import ProgressTree, ProgressDone
from fixlib.graph import Graph, MaxNodesExceeded
from fixlib.proc import collector_initializer

log = logging.getLogger("fix.plugin.azure")
T = TypeVar("T", bound=MicrosoftResource)


class AzureCollectorKind(Enum):
    subscription = "subscription"
    microsoft_graph = "microsoft_graph"


AzureCollectorArg = namedtuple(
    "AzureCollectorArg",
    [
        "collector_kind",
        "config",
        "cloud",
        "account",
        "account_config",
        "core_feedback",
        "task_data",
        "max_resources_per_account",
    ],
)


class AzureCollectorPlugin(BaseCollectorPlugin):
    cloud = "azure"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.core_feedback: Optional[CoreFeedback] = None

    @staticmethod
    def add_config(cfg: Config) -> None:
        cfg.add_config(AzureConfig)

    @staticmethod
    def auto_enableable() -> bool:
        return False

    def collect(self) -> None:
        log.info("plugin: Azure collecting resources")
        config: AzureConfig = Config.azure
        assert self.core_feedback, "core_feedback is not set"
        cloud = Cloud(id=self.cloud)

        # In case no account is configured, fallback to default settings
        account_configs = config.accounts or {"default": AzureAccountConfig()}

        # Gather all subscriptions
        subscription_args = {
            subscription.subscription_id: AzureCollectorArg(
                AzureCollectorKind.subscription,
                config,
                cloud,
                subscription,
                ac,
                self.core_feedback.with_context(cloud.id, subscription.safe_name),
                self.task_data,
                self.max_resources_per_account,
            )
            for name, ac in account_configs.items()
            for subscription in list_all(AzureSubscription, config, ac.credentials())
            if ac.allowed(subscription.subscription_id)
        }
        # Gather all organizations
        microsoft_graph = Cloud(id="microsoft-graph")
        organization_args = {
            org.id: AzureCollectorArg(
                AzureCollectorKind.microsoft_graph,
                config,
                microsoft_graph,
                org,
                ac,
                self.core_feedback.with_context(cloud.id, org.safe_name),
                self.task_data,
                self.max_resources_per_account,
            )
            for name, ac in account_configs.items()
            for org in list_all(MicrosoftGraphOrganization, config, ac.credentials())
            if ac.collect_microsoft_graph
        }
        args = list(subscription_args.values()) + list(organization_args.values())

        # Send initial progress
        progress = ProgressTree(self.cloud)
        for sub in args:
            progress.add_progress(ProgressDone(sub.account.id, 0, 1))
            log.debug(f"Found {sub.account.id}")
        self.core_feedback.progress(progress)

        # Collect all subscriptions and organizations
        with ThreadPoolExecutor(max_workers=config.subscription_pool_size) as executor:
            wait_for = [executor.submit(collect_in_process, sub) for sub in args]
            for future in as_completed(wait_for):
                subscription, graph = future.result()
                progress.add_progress(ProgressDone(subscription.id, 1, 1, path=[cloud.id]))
                if not isinstance(graph, Graph):
                    log.debug(f"Skipping account graph of invalid type {type(graph)}")
                    continue
                try:
                    self.send_account_graph(graph)
                except MaxNodesExceeded as e:
                    self.core_feedback.error(f"Max resources exceeded: {e}", log)
                del graph


def list_all(resource: Type[T], config: AzureConfig, credentials: AzureCredentials) -> List[T]:
    if resource.api_spec is None:
        return []
    client = MicrosoftClient.create(config, credentials, "global")
    return [rs for js in client.list(resource.api_spec) if (rs := resource.from_api(js))]


def collect_account_proxy(collector_arg: AzureCollectorArg, queue: multiprocessing.Queue) -> None:  # type: ignore
    collector_initializer()
    kind, config, cloud, account, account_config, core_feedback, task_data, max_resources = collector_arg
    log.info(f"Start collecting {kind}: {account.id}")
    mbc: MicrosoftBaseCollector
    if kind == AzureCollectorKind.subscription:
        mbc = AzureSubscriptionCollector(
            config, cloud, account, account_config.credentials(), core_feedback, task_data, max_resources
        )
    elif kind == AzureCollectorKind.microsoft_graph:
        mbc = MicrosoftGraphOrganizationCollector(
            config, cloud, account, account_config.credentials(), core_feedback, task_data, max_resources
        )
    else:
        queue.put((collector_arg.account, None))  # signal done
        raise ValueError(f"Invalid collector kind {kind}")
    try:
        mbc.collect()
        queue.put((collector_arg.account, mbc.graph))
    except Exception as e:
        log.exception(f"Error collecting account {account.id}: {e}. Give up.")
        queue.put((collector_arg.account, None))  # signal done


def collect_in_process(collector_arg: AzureCollectorArg) -> Tuple[BaseAccount, Graph]:
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    process = ctx.Process(target=collect_account_proxy, kwargs={"collector_arg": collector_arg, "queue": queue})
    process.start()
    result = queue.get()
    process.join()
    return result  # type: ignore
