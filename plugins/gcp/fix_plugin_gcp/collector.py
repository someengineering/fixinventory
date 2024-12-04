import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Type, List, Any, Optional, cast

from fix_plugin_gcp.config import GcpConfig
from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources import (
    compute,
    container,
    billing,
    scc,
    sqladmin,
    storage,
    aiplatform,
    firestore,
    filestore,
    cloudfunctions,
    monitoring,
    pubsub,
)
from fix_plugin_gcp.resources.base import GcpResource, GcpProject, ExecutorQueue, GraphBuilder, GcpRegion, GcpZone
from fix_plugin_gcp.utils import Credentials
from fixlib.baseresources import Cloud
from fixlib.core.actions import CoreFeedback, ErrorAccumulator
from fixlib.graph import Graph
from fixlib.json import value_in_path
from fixlib.types import Json

log = logging.getLogger("fix.plugins.gcp")
all_resources: List[Type[GcpResource]] = (
    compute.resources
    + container.resources
    + billing.resources
    + sqladmin.resources
    + storage.resources
    + aiplatform.resources
    + firestore.resources
    + filestore.resources
    + cloudfunctions.resources
    + pubsub.resources
    + scc.resources
)


def called_collect_apis() -> List[GcpApiSpec]:
    """
    Return a list of all the APIs that are called by the collector during the collect cycle.
    """
    specs = [spec for r in all_resources for spec in r.called_collect_apis()]
    return sorted(specs, key=lambda s: s.fqn)


def called_mutator_apis() -> List[GcpApiSpec]:
    """
    Return a list of all the APIs that are called to mutate resources.
    """
    specs = [spec for r in all_resources for spec in r.called_mutator_apis()]
    return sorted(specs, key=lambda s: s.fqn)


class GcpProjectCollector:
    def __init__(
        self,
        config: GcpConfig,
        cloud: Cloud,
        project: GcpProject,
        core_feedback: CoreFeedback,
        task_data: Json,
        max_resources_per_account: Optional[int] = None,
    ) -> None:
        self.config = config
        self.cloud = cloud
        self.project = project
        self.core_feedback = core_feedback
        self.error_accumulator = ErrorAccumulator()
        self.graph = Graph(root=self.project, max_nodes=max_resources_per_account)
        self.credentials = Credentials.get(self.project.id)
        self.task_data = task_data

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"gcp_{self.project.id}", max_workers=self.config.project_pool_size
        ) as executor:
            self.core_feedback.progress_done(self.project.id, 0, 1, context=[self.cloud.id])
            # The shared executor is used to parallelize the collection of resources "as fast as possible"
            # It should only be used in scenarios, where it is safe to do so.
            # This executor is shared between all regions.
            shared_queue = ExecutorQueue(executor, self.project.safe_name)

            def get_last_run() -> Optional[datetime]:
                td = self.task_data
                if not td:
                    return None
                timestamp = value_in_path(td, ["timing", td.get("step", ""), "started_at"])

                if timestamp is None:
                    return None

                return datetime.fromtimestamp(timestamp, timezone.utc)

            project_global_region = GcpRegion.fallback_global_region(self.project)
            last_run = get_last_run()
            global_builder = GraphBuilder(
                self.graph,
                self.cloud,
                self.project,
                self.credentials,
                shared_queue,
                self.core_feedback,
                self.error_accumulator,
                project_global_region,
                config=self.config,
                last_run_started_at=last_run,
            )
            global_builder.add_node(project_global_region, {})

            # fetch available regions and zones
            log.info(f"[Gcp:{self.project.id}] Collecting project wide resources.")
            GcpRegion.collect_resources(global_builder)
            global_builder.prepare_region_zone_lookup()
            GcpZone.collect_resources(global_builder)
            global_builder.prepare_region_zone_lookup()

            # fetch all project level resources
            for resource_class in all_resources:
                if not self.config.should_collect(resource_class.kind):
                    continue
                if resource_class.api_spec and resource_class.api_spec.is_project_level:
                    global_builder.submit_work(resource_class.collect_resources, global_builder)

            # fetch all region level resources
            for region in global_builder.resources_of(GcpRegion):
                if region.name == "global":
                    continue
                global_builder.submit_work(self.collect_region, global_builder.for_region(region))
            global_builder.executor.wait_for_submitted_work()

            # call all registered after collect hooks
            for after_collect in global_builder.after_collect_actions:
                after_collect()

            self.error_accumulator.report_all(global_builder.core_feedback)

            if global_builder.config.collect_usage_metrics:
                try:
                    log.info(f"[GCP:{self.project.id}] Collect usage metrics.")
                    self.collect_usage_metrics(global_builder)
                    global_builder.executor.wait_for_submitted_work()
                except Exception as e:
                    log.warning(f"Failed to collect usage metrics in project {self.project.id}: {e}")
            log.info(f"[GCP:{self.project.id}] Connect resources and create edges.")
            # connect nodes
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, GcpResource):
                    node.connect_in_graph(global_builder, data.get("source", {}))
            global_builder.executor.wait_for_submitted_work()

            # remove unconnected nodes
            self.remove_unconnected_nodes(global_builder)

            # post process nodes
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, GcpResource):
                    node.post_process_instance(global_builder, data.get("source", {}))

            global_builder.executor.wait_for_submitted_work()

            self.core_feedback.progress_done(self.project.id, 1, 1, context=[self.cloud.id])
            log.info(f"[GCP:{self.project.id}] Collecting resources done.")

    def collect_usage_metrics(self, builder: GraphBuilder) -> None:
        for resource in builder.graph.nodes:
            if isinstance(resource, GcpResource) and (mq := resource.collect_usage_metrics(builder)):
                start_at = builder.created_at - builder.metrics_delta
                region = cast(GcpRegion, resource.region())
                rb = builder.for_region(region)
                monitoring.GcpMonitoringMetricData.query_for(rb, resource, mq, start_at, builder.created_at)

    def remove_unconnected_nodes(self, builder: GraphBuilder) -> None:
        def rm_leaf_nodes(clazz: Any, ignore_kinds: Optional[Type[Any]] = None) -> None:
            remove_nodes = set()
            for node in self.graph.nodes:
                if not isinstance(node, clazz):
                    continue
                suc = list(self.graph.successors(node))
                filtered = [s for s in suc if not isinstance(s, ignore_kinds)] if ignore_kinds else suc
                if not filtered:
                    remove_nodes.update(suc)
                    remove_nodes.add(node)
            self.graph.remove_nodes_from(remove_nodes)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {clazz}")
            remove_nodes.clear()

        # nodes need to be removed in the correct order
        rm_leaf_nodes((compute.GcpNodeType, compute.GcpDiskType))
        rm_leaf_nodes(compute.GcpMachineType, compute.GcpAcceleratorType)  # ignore accelerator types
        rm_leaf_nodes(compute.GcpAcceleratorType)
        rm_leaf_nodes(billing.GcpSku)
        rm_leaf_nodes(billing.GcpService)
        # remove regions that are not in use
        self.graph.remove_recursively(builder.nodes(GcpRegion, lambda r: r.compute_region_in_use(builder) is False))

    def collect_region(self, regional_builder: GraphBuilder) -> None:
        # fetch all region level resources
        for resource_class in all_resources:
            if not self.config.should_collect(resource_class.kind):
                continue
            if resource_class.api_spec and not resource_class.api_spec.is_project_level:
                resource_class.collect_resources(regional_builder)
