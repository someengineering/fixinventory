import logging
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Any, Optional, Type, Set, List
from datetime import datetime, timezone

from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fix_plugin_azure.azure_client import AzureClient
from fix_plugin_azure.resource.compute import (
    AzureVirtualMachineSize,
    resources as compute_resources,
)
from fix_plugin_azure.resource.base import (
    AzureLocation,
    AzureSubscription,
    GraphBuilder,
    AzureResource,
    resources as base_resources,
)
from fix_plugin_azure.resource.network import resources as network_resources
from fix_plugin_azure.resource.containerservice import resources as aks_resources
from fixlib.baseresources import Cloud, GraphRoot
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph
from fixlib.json import value_in_path
from fixlib.threading import ExecutorQueue, GatherFutures
from fixlib.types import Json

log = logging.getLogger("fix.plugin.azure")


def resource_with_params(clazz: Type[AzureResource], params: Set[str], includes_all: bool = False) -> bool:
    if clazz.api_spec is None:
        return False
    cp = set(clazz.api_spec.path_parameters)
    return cp.issubset(params) and (not includes_all or params.issubset(cp))


all_resources: List[Type[AzureResource]] = base_resources + compute_resources + network_resources + aks_resources
global_resources = [r for r in all_resources if resource_with_params(r, {"subscriptionId"})]
regional_resources = [r for r in all_resources if resource_with_params(r, {"subscriptionId", "location"}, True)]


class AzureSubscriptionCollector:
    def __init__(
        self,
        config: AzureConfig,
        cloud: Cloud,
        subscription: AzureSubscription,
        credentials: AzureCredentials,
        core_feedback: CoreFeedback,
        task_data: Optional[Json] = None,
    ):
        self.config = config
        self.cloud = cloud
        self.subscription = subscription
        self.credentials = credentials
        self.core_feedback = core_feedback
        self.graph = Graph(root=subscription)
        self.task_data = task_data

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"azure_{self.subscription.subscription_id}",
            max_workers=self.config.resource_pool_size,
        ) as executor:
            self.core_feedback.progress_done(self.subscription.subscription_id, 0, 1, context=[self.cloud.id])
            queue = ExecutorQueue(executor, "azure_collector")
            client = AzureClient.create(self.credentials, self.subscription.subscription_id)

            def get_last_run() -> Optional[datetime]:
                td = self.task_data
                if not td:
                    return None
                if timestamp := value_in_path(self.task_data, ["timing", td.get("step", ""), "started_at"]):
                    return datetime.fromtimestamp(timestamp, timezone.utc)
                return None

            last_run = get_last_run()
            builder = GraphBuilder(
                self.graph,
                self.cloud,
                self.subscription,
                client,
                queue,
                self.core_feedback,
                config=self.config,
                last_run_started_at=last_run,
            )
            # collect all locations
            locations = builder.fetch_locations()
            # collect all global resources
            self.collect_resource_list("subscription", builder, global_resources)
            # collect all regional resources
            for location in locations:
                self.collect_resource_list(location.safe_name, builder.with_location(location), regional_resources)
            # wait for all work to finish
            queue.wait_for_submitted_work()
            # connect nodes
            log.info(f"[Azure:{self.subscription.safe_name}] Connect resources and create edges.")
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, AzureResource):
                    node.connect_in_graph(builder, data.get("source", {}))
                elif isinstance(node, (GraphRoot, Cloud)):
                    pass
                else:
                    raise Exception(f"Only Azure resources expected, but got {node}")
            # wait for all work to finish
            queue.wait_for_submitted_work()
            # filter nodes
            self.filter_nodes()
            self.core_feedback.progress_done(self.subscription.subscription_id, 1, 1, context=[self.cloud.id])
            log.info(f"[Azure:{self.subscription.safe_name}] Collecting resources done.")

    def collect_resource_list(
        self, name: str, builder: GraphBuilder, resources: List[Type[AzureResource]]
    ) -> Future[None]:
        def collect_resource(clazz: Type[AzureResource]) -> None:
            log.info(f"[Azure:{self.subscription.subscription_id}:{name}] start collecting: {clazz.kind}")
            clazz.collect_resources(builder)
            log.info(f"[Azure:{self.subscription.subscription_id}:{name}] finished collecting: {clazz.kind}")

        def work_done(_: Future[None]) -> None:
            self.core_feedback.progress_done(name, 1, 1, context=[self.cloud.id, self.subscription.subscription_id])

        group_futures = []
        self.core_feedback.progress_done(name, 0, 1, context=[self.cloud.id, self.subscription.subscription_id])
        for resource_type in resources:
            group_futures.append(builder.submit_work("azure_all", collect_resource, resource_type))
        all_done = GatherFutures.all(group_futures)
        all_done.add_done_callback(work_done)
        return all_done

    def filter_nodes(self) -> None:
        remove_nodes = []

        def rm_nodes(cls, ignore_kinds: Optional[Type[Any]] = None) -> None:  # type: ignore
            for node in self.graph.nodes:
                if not isinstance(node, cls):
                    continue
                pred = list(self.graph.predecessors(node))
                if ignore_kinds is not None:
                    pred = [p for p in pred if not isinstance(p, ignore_kinds)]
                if not pred:
                    remove_nodes.append(node)
            removed = set()
            for node in remove_nodes:
                if node in removed:
                    continue
                removed.add(node)
                self.graph.remove_node(node)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")
            remove_nodes.clear()

        rm_nodes(AzureVirtualMachineSize, AzureLocation)
