import logging
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from typing import Any, Optional, Type, List, Dict, Set

from azure.core.utils import CaseInsensitiveDict

from fix_plugin_azure.azure_client import MicrosoftClient, RestApiSpec
from fix_plugin_azure.config import AzureConfig, AzureCredentials
from fix_plugin_azure.resource.authorization import resources as authorization_resources
from fix_plugin_azure.resource.base import (
    AzureLocation,
    AzureSubscription,
    GraphBuilder,
    resources as base_resources,
    MicrosoftResource,
)
from fix_plugin_azure.resource.compute import (
    AzureComputeVirtualMachineSize,
    AzureComputeDiskType,
    AzureComputeDiskTypePricing,
    resources as compute_resources,
)
from fix_plugin_azure.resource.containerservice import resources as aks_resources
from fix_plugin_azure.resource.cosmosdb import (
    AzureCosmosDBLocation,
    resources as cosmosdb_resources,
)
from fix_plugin_azure.resource.keyvault import resources as keyvault_resources
from fix_plugin_azure.resource.machinelearning import (
    AzureMachineLearningUsage,
    AzureMachineLearningVirtualMachineSize,
    resources as ml_resources,
)
from fix_plugin_azure.resource.microsoft_graph import (
    MicrosoftGraphOrganization,
    resources as graph_resources,
    MicrosoftGraphOrganizationRoot,
)
from fix_plugin_azure.resource.monitor import resources as monitor_resources
from fix_plugin_azure.resource.mysql import AzureMysqlServerType, resources as mysql_resources
from fix_plugin_azure.resource.network import (
    AzureNetworkExpressRoutePortsLocation,
    AzureNetworkVirtualApplianceSku,
    AzureNetworkUsage,
    resources as network_resources,
)
from fix_plugin_azure.resource.postgresql import (
    AzurePostgresqlServerType,
    resources as postgresql_resources,
)
from fix_plugin_azure.resource.security import resources as security_resources
from fix_plugin_azure.resource.sql_server import resources as sql_resources
from fix_plugin_azure.resource.storage import AzureStorageAccountUsage, AzureStorageSku, resources as storage_resources
from fix_plugin_azure.resource.web import resources as web_resources
from fixlib.baseresources import Cloud, GraphRoot, BaseAccount, BaseRegion
from fixlib.core.actions import CoreFeedback, ErrorAccumulator
from fixlib.graph import Graph
from fixlib.json import value_in_path
from fixlib.threading import ExecutorQueue, GatherFutures
from fixlib.types import Json

log = logging.getLogger("fix.plugin.azure")


def resource_with_params(clazz: Type[MicrosoftResource], param: str) -> bool:
    if clazz.api_spec is None or isinstance(clazz.api_spec, RestApiSpec):
        return False
    return param in clazz.api_spec.path_parameters


subscription_resources: List[Type[MicrosoftResource]] = (
    base_resources
    + aks_resources
    + authorization_resources
    + compute_resources
    + cosmosdb_resources
    + keyvault_resources
    + monitor_resources
    + mysql_resources
    + network_resources
    + postgresql_resources
    + security_resources
    + sql_resources
    + storage_resources
    + web_resources
    + ml_resources
)
all_resources = subscription_resources + graph_resources  # defines all resource kinds. used in model check


class MicrosoftBaseCollector:
    def __init__(
        self,
        config: AzureConfig,
        cloud: Cloud,
        account: BaseAccount,
        credentials: AzureCredentials,
        core_feedback: CoreFeedback,
        task_data: Optional[Json] = None,
        max_resources_per_account: Optional[int] = None,
        filter_unused_resources: bool = True,
    ):
        self.config = config
        self.cloud = cloud
        self.account = account
        self.credentials = credentials
        self.core_feedback = core_feedback
        self.graph = Graph(root=account, max_nodes=max_resources_per_account)
        self.task_data = task_data
        self.filter_unused_resources = filter_unused_resources

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"azure_{self.account.id}",
            max_workers=self.config.resource_pool_size,
        ) as executor:
            self.core_feedback.progress_done(self.account.id, 0, 1, context=[self.cloud.id])
            queue = ExecutorQueue(executor, "azure_collector")
            error_accumulator = ErrorAccumulator()
            client = MicrosoftClient.create(
                self.config,
                self.credentials,
                self.account.id,
                core_feedback=self.core_feedback,
                error_accumulator=error_accumulator,
            )

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
                self.account,
                client,
                queue,
                self.core_feedback,
                config=self.config,
                last_run_started_at=last_run,
            )

            # collect all locations
            locations = self.locations(builder)
            builder.location_lookup = locations

            # collect all resources
            self.collect_with(builder, locations)
            queue.wait_for_submitted_work()

            # call all registered after collect hooks
            for after_collect in builder.after_collect_actions:
                after_collect()

            # connect nodes
            log.info(f"[Azure:{self.account.safe_name}] Connect resources and create edges.")
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, MicrosoftResource):
                    node.connect_in_graph(builder, data.get("source", {}))
                elif isinstance(node, (GraphRoot, Cloud)):
                    pass
                else:
                    raise Exception(f"Only Azure resources expected, but got {node}")
            queue.wait_for_submitted_work()

            # post-process nodes
            if self.filter_unused_resources:
                self.remove_unused(builder)
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, MicrosoftResource):
                    node.after_collect(builder, data.get("source", {}))

            # delete unnecessary nodes after all work is completed
            self.after_collect(builder)
            # report all accumulated errors
            error_accumulator.report_all(self.core_feedback)
            self.core_feedback.progress_done(self.account.id, 1, 1, context=[self.cloud.id])
            log.info(f"[Azure:{self.account.safe_name}] Collecting resources done.")

    def collect_resource_list(
        self, name: str, builder: GraphBuilder, resources: List[Type[MicrosoftResource]]
    ) -> Future[None]:
        def collect_resource(clazz: Type[MicrosoftResource]) -> None:
            log.info(f"[Azure:{self.account.id}:{name}] start collecting: {clazz.kind}")
            clazz.collect_resources(builder)
            log.info(f"[Azure:{self.account.id}:{name}] finished collecting: {clazz.kind}")

        def work_done(_: Future[None]) -> None:
            self.core_feedback.progress_done(name, 1, 1, context=[self.cloud.id, self.account.id])

        group_futures = []
        self.core_feedback.progress_done(name, 0, 1, context=[self.cloud.id, self.account.id])
        for resource_type in resources:
            if self.config.should_collect(resource_type.kind):
                group_futures.append(builder.submit_work("azure_all", collect_resource, resource_type))
        all_done = GatherFutures.all(group_futures)
        all_done.add_done_callback(work_done)
        return all_done

    @abstractmethod
    def collect_with(self, builder: GraphBuilder, locations: Dict[str, BaseRegion]) -> None:
        pass

    @abstractmethod
    def locations(self, builder: GraphBuilder) -> Dict[str, BaseRegion]:
        pass

    def remove_unused(self, builder: GraphBuilder) -> None:
        pass

    def after_collect(self, builder: GraphBuilder) -> None:
        pass


class AzureSubscriptionCollector(MicrosoftBaseCollector):
    def locations(self, builder: GraphBuilder) -> Dict[str, BaseRegion]:
        locations = AzureLocation.collect_resources(builder)
        # сreate a location lookup map with lowercase name and display name of the locations
        locations_map = CaseInsensitiveDict()
        locations_map.update({loc.safe_name: loc for loc in locations})
        locations_map.update({loc.display_name or loc.safe_name: loc for loc in locations})
        return locations_map  # type: ignore

    def collect_with(self, builder: GraphBuilder, locations: Dict[str, BaseRegion]) -> None:
        # add deferred edge to organization
        builder.submit_work("azure_all", MicrosoftGraphOrganization.deferred_edge_to_subscription, builder)
        # collect all global and regional resources
        regional_resources = [r for r in subscription_resources if resource_with_params(r, "location")]
        global_resources = list(set(subscription_resources) - set(regional_resources))
        self.collect_resource_list("subscription", builder, global_resources)
        processed_locations: Set[str] = set()
        for location in locations.values():
            if location.safe_name not in processed_locations:
                self.collect_resource_list(location.safe_name, builder.with_location(location), regional_resources)
                processed_locations.add(location.safe_name)

    def remove_unused(self, builder: GraphBuilder) -> None:
        remove_nodes = []

        def rm_leaf_nodes(cls: Any, ignore_kinds: Optional[Type[Any]] = None, check_pred: bool = True) -> None:
            for node in self.graph.nodes:
                if not isinstance(node, cls):
                    continue
                if check_pred:
                    nodes = list(self.graph.predecessors(node))
                else:
                    nodes = list(self.graph.successors(node))
                if ignore_kinds is not None:
                    nodes = [n for n in nodes if not isinstance(n, ignore_kinds)]
                if not nodes:
                    remove_nodes.append(node)
            self._delete_nodes(remove_nodes)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")

        def remove_usage_zero_value() -> None:
            for node in self.graph.nodes:
                if not isinstance(node, (AzureNetworkUsage, AzureStorageAccountUsage, AzureMachineLearningUsage)):
                    continue
                # Azure Usage just keep info about how many kind of resources on account exists
                # Check if the current usage value of the Azure Usage node is 0
                if node.current_value == 0:
                    # If the current usage value is 0, add the node to the list of nodes to remove
                    remove_nodes.append(node)
            self._delete_nodes(remove_nodes)

        rm_leaf_nodes(AzureComputeVirtualMachineSize, AzureLocation)
        rm_leaf_nodes(AzureNetworkExpressRoutePortsLocation, AzureSubscription)
        rm_leaf_nodes(AzureNetworkVirtualApplianceSku, AzureSubscription)
        rm_leaf_nodes(AzureComputeDiskType, (AzureSubscription, AzureLocation))  # type: ignore
        rm_leaf_nodes(AzureMachineLearningVirtualMachineSize, AzureLocation)
        rm_leaf_nodes(AzureStorageSku, AzureLocation)
        rm_leaf_nodes(AzureMysqlServerType, AzureLocation)
        rm_leaf_nodes(AzurePostgresqlServerType, AzureLocation)
        rm_leaf_nodes(AzureCosmosDBLocation, AzureLocation, check_pred=False)
        rm_leaf_nodes(AzureLocation, check_pred=False)
        rm_leaf_nodes(AzureComputeDiskTypePricing, AzureSubscription)
        remove_usage_zero_value()
        self.graph.remove_recursively(builder.nodes(AzureLocation, lambda r: r.compute_region_in_use(builder) is False))

    def _delete_nodes(self, nodes_to_delete: Any) -> None:
        removed = set()
        for node in nodes_to_delete:
            if node in removed:
                continue
            removed.add(node)
            self.graph.remove_node(node)
        nodes_to_delete.clear()


class MicrosoftGraphOrganizationCollector(MicrosoftBaseCollector):

    def locations(self, builder: GraphBuilder) -> Dict[str, BaseRegion]:
        root = MicrosoftGraphOrganizationRoot(id="organization_root")
        builder.add_node(root)
        return {"organization_root": root}

    def collect_with(self, builder: GraphBuilder, locations: Dict[str, BaseRegion]) -> None:
        for location in locations.values():  # all resources underneath the organization root
            self.collect_resource_list(location.safe_name, builder.with_location(location), graph_resources)
