import logging
import multiprocessing
from collections import namedtuple
from concurrent.futures import as_completed, ProcessPoolExecutor
from typing import Optional, Tuple, Any

from attr import evolve

from fix_plugin_azure.collector import AzureSubscriptionCollector
from fix_plugin_azure.config import AzureConfig, AzureAccountConfig
from fix_plugin_azure.resource.base import AzureSubscription
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import Cloud
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.core.progress import ProgressTree, ProgressDone
from fixlib.graph import Graph, MaxNodesExceeded
from fixlib.proc import collector_initializer
from fixlib.types import Json

log = logging.getLogger("fix.plugin.azure")

AzureSubscriptionArg = namedtuple(
    "AzureSubscriptionArg", ["config", "cloud", "subscription", "account_config", "core_feedback", "task_data"]
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
        args_by_subscription_id = {
            subscription.subscription_id: AzureSubscriptionArg(
                config,
                cloud,
                evolve(subscription, account_name=name),
                ac,
                self.core_feedback.with_context(cloud.id, subscription.safe_name),
                self.task_data,
            )
            for name, ac in account_configs.items()
            for subscription in AzureSubscription.list_subscriptions(config, ac.credentials())
            if ac.allowed(subscription.subscription_id)
        }
        args = list(args_by_subscription_id.values())

        # Send initial progress
        progress = ProgressTree(self.cloud)
        for sub in args:
            progress.add_progress(ProgressDone(sub.subscription.subscription_id, 0, 1))
            log.debug(f"Found {sub.subscription.subscription_id}")
        self.core_feedback.progress(progress)

        # Collect all subscriptions
        with ProcessPoolExecutor(max_workers=config.subscription_pool_size) as executor:
            wait_for = [
                executor.submit(collect_in_process, sub, self.task_data, self.max_resources_per_account) for sub in args
            ]
            for future in as_completed(wait_for):
                subscription, graph = future.result()
                progress.add_progress(ProgressDone(subscription.subscription_id, 1, 1, path=[cloud.id]))
                if not isinstance(graph, Graph):
                    log.debug(f"Skipping subscription graph of invalid type {type(graph)}")
                    continue
                try:
                    self.send_account_graph(graph)
                except MaxNodesExceeded as e:
                    self.core_feedback.error(f"Max resources exceeded: {e}", log)
                del graph


def collect_account_proxy(subscription_collector_arg: AzureSubscriptionArg, queue: multiprocessing.Queue, max_resources_per_account: Optional[int] = None) -> None:  # type: ignore
    collector_initializer()
    config, cloud, subscription, account_config, core_feedback, task_data = subscription_collector_arg
    subscription_collector = AzureSubscriptionCollector(
        config, cloud, subscription, account_config.credentials(), core_feedback, task_data, max_resources_per_account
    )
    try:
        subscription_collector.collect()
        queue.put((subscription_collector_arg.subscription, subscription_collector.graph))
    except Exception as e:
        log.exception(f"Error collecting subscription {subscription.subscription_id}: {e}. Give up.")
        queue.put((subscription_collector_arg.subscription, None))  # signal done


def collect_in_process(
    subscription_collector_arg: AzureSubscriptionArg,
    task_data: Optional[Json],
    max_resources_per_account: Optional[int] = None,
) -> Tuple[AzureSubscription, Graph]:
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    process = ctx.Process(
        target=collect_account_proxy,
        kwargs={
            "subscription_collector_arg": subscription_collector_arg,
            "queue": queue,
            "max_resources_per_account": max_resources_per_account,
        },
    )
    process.start()
    result = queue.get()
    process.join()
    return result  # type: ignore
