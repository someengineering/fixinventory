from concurrent.futures import ThreadPoolExecutor, Future
from typing import Type, Set, List

from azure.identity import DefaultAzureCredential

from resoto_plugin_azure import AzureConfig, log
from resoto_plugin_azure.azure_client import AzureClient
from resoto_plugin_azure.resource import compute
from resoto_plugin_azure.resource.base import (
    AzureSubscription,
    GraphBuilder,
    AzureResource,
    AzureResourceGroup,
)
from resotolib.baseresources import Cloud, GraphRoot
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.threading import ExecutorQueue, GatherFutures


def resource_with_params(clazz: Type[AzureResource], params: Set[str]) -> bool:
    return clazz.api_spec is not None and not (set(clazz.api_spec.path_parameters) - params)


all_resources: List[Type[AzureResource]] = compute.resources
subscription_resources = [r for r in all_resources if resource_with_params(r, {"subscriptionId"})]
group_resources = [r for r in all_resources if resource_with_params(r, {"subscriptionId", "resourceGroupName"})]


class AzureSubscriptionCollector:
    def __init__(self, config: AzureConfig, cloud: Cloud, subscription: AzureSubscription, core_feedback: CoreFeedback):
        self.config = config
        self.cloud = cloud
        self.subscription = subscription
        self.core_feedback = core_feedback
        self.credentials = DefaultAzureCredential()  # TODO: should be derived from config
        self.graph = Graph(root=cloud)

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"azure_{self.subscription.id}", max_workers=self.config.resource_pool_size
        ) as executor:
            self.core_feedback.progress_done(self.subscription.dname, 1, 1, context=[self.cloud.id])
            queue = ExecutorQueue(executor, "azure_collector")
            client = AzureClient(self.credentials, self.subscription.id)
            builder = GraphBuilder(self.graph, self.cloud, self.subscription, client, queue, self.core_feedback)
            # collect all locations
            builder.fetch_locations()
            # collect resource groups
            groups = AzureResourceGroup.collect_resources(builder)
            # collect all resources that are either global or need the subscription id
            self.collect_resources("subscription", builder, subscription_resources)
            # collect all resources inside resource groups
            for group in groups:
                self.collect_resources(group.safe_name, builder.with_resource_group(group), subscription_resources)
            # wait for all work to finish
            queue.wait_for_submitted_work()
            # connect nodes
            log.info(f"[Aws:{self.subscription.id}] Connect resources and create edges.")
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, AzureResource):
                    node.connect_in_graph(builder, data.get("source", {}))
                elif isinstance(node, (GraphRoot, Cloud)):
                    pass
                else:
                    raise Exception(f"Only Azure resources expected, but got {node}")
            # wait for all work to finish
            queue.wait_for_submitted_work()
            self.core_feedback.progress_done(self.subscription.dname, 1, 1, context=[self.cloud.id])
            log.info(f"[Azure:{self.subscription.id}] Collecting resources done.")

    def collect_resources(self, name: str, builder: GraphBuilder, resources: List[Type[AzureResource]]) -> Future[None]:
        def collect_resource(clazz: Type[AzureResource]) -> None:
            clazz.collect_resources(builder)
            log.info(f"[Azure:{self.subscription.id}:{name}] finished collecting: {clazz.kind}")

        def work_done(_: Future[None]) -> None:
            self.core_feedback.progress_done(name, 1, 1, context=[self.cloud.id, self.subscription.id])

        group_futures = []
        self.core_feedback.progress_done(name, 0, 1, context=[self.cloud.id, self.subscription.id])
        for resource_type in resources:
            group_futures.append(builder.submit_work(collect_resource, resource_type))
        all_done = GatherFutures.all(group_futures)
        all_done.add_done_callback(work_done)
        return all_done
