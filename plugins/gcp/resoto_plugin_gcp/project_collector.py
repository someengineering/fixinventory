from concurrent.futures import ThreadPoolExecutor
import logging
from queue import Queue
from typing import Type, List

from resoto_plugin_gcp import GcpConfig, Credentials
from resoto_plugin_gcp.resources import compute, container, billing, sqladmin
from resoto_plugin_gcp.resources.base import GcpResource, GcpProject, ExecutorQueue, GraphBuilder, GcpRegion, GcpZone
from resotolib.baseresources import Cloud
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.gcp")
all_resources: List[Type[GcpResource]] = (
    compute.resources + container.resources + billing.resources + sqladmin.resources
)


class GcpProjectCollector:
    def __init__(self, config: GcpConfig, cloud: Cloud, project: GcpProject, core_feedback: CoreFeedback) -> None:
        self.config = config
        self.cloud = cloud
        self.project = project
        self.core_feedback = core_feedback
        self.graph = Graph(root=self.project)
        self.credentials = Credentials.get(self.project.id)

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"gcp_{self.project.id}", max_workers=self.config.project_pool_size
        ) as executor:
            # The shared executor is used to parallelize the collection of resources "as fast as possible"
            # It should only be used in scenarios, where it is safe to do so.
            # This executor is shared between all regions.
            shared_queue = ExecutorQueue(executor, self.project.safe_name)
            global_builder = GraphBuilder(
                self.graph, self.cloud, self.project, self.credentials, shared_queue, self.core_feedback
            )

            # fetch available regions and zones
            self.core_feedback.progress_done(self.project.dname, 0, 1, context=[self.cloud.id])
            log.info(f"[Gcp:{self.project.id}] Collecting project wide resources.")
            GcpRegion.collect_resources(global_builder)
            global_builder.prepare_region_zone_lookup()
            GcpZone.collect_resources(global_builder)
            global_builder.prepare_region_zone_lookup()

            # fetch all project level resources
            for resource_class in all_resources:
                if resource_class.api_spec and resource_class.api_spec.is_project_level:
                    global_builder.submit_work(resource_class.collect_resources, global_builder)

            # fetch all region level resources
            for region in global_builder.resources_of(GcpRegion):
                global_builder.submit_work(self.collect_region, region, global_builder.for_region(region))

            global_builder.executor.wait_for_submitted_work()
            # connect nodes
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, GcpResource):
                    node.connect_in_graph(global_builder, data.get("source", {}))

            self.core_feedback.progress_done(self.project.dname, 1, 1, context=[self.cloud.id])

            log.info(f"[GCP:{self.project.id}] Collecting resources done.")
            self.remove_unconnected_nodes()

    def remove_unconnected_nodes(self):
        remove_nodes = set()

        def rmnodes(cls) -> None:
            for node in self.graph.nodes:
                if isinstance(node, cls) and not any(True for _ in self.graph.successors(node)):
                    remove_nodes.add(node)
            for node in remove_nodes:
                self.graph.remove_node(node)
            log.debug(f"Removing {len(remove_nodes)} unreferenced nodes of type {cls}")
            remove_nodes.clear()

        # nodes need to be removed in the correct order
        rmnodes((compute.GcpMachineType, compute.GcpDiskType))
        rmnodes(billing.GcpSku)
        rmnodes(billing.GcpService)

    def collect_region(self, region: GcpRegion, regional_builder: GraphBuilder) -> None:
        # fetch all region level resources
        for resource_class in all_resources:
            if resource_class.api_spec and not resource_class.api_spec.is_project_level:
                log.info(
                    f"Collecting {resource_class.__name__} for project {self.project.id} in region {region.rtdname}"
                )
                resource_class.collect_resources(regional_builder)


if __name__ == "__main__":
    # TODO: remove this only here for local testing
    from google.oauth2.service_account import Credentials as OauthCredentials

    cloud = Cloud(id="Gcp", name="Gcp")
    project = GcpProject(id="vpc-host-nonprod-320811", name="vpc-host-nonprod-320811")
    feedback = CoreFeedback("test", "test", "test", Queue())
    Credentials._credentials[project.id] = OauthCredentials.from_service_account_file(
        "/Users/anja/.gcp/vpc_host_nonprod.json"
    )
    Credentials._initialized = True
    collector = GcpProjectCollector(GcpConfig(), cloud, project, feedback)
    collector.collect()
    for nd in collector.graph.nodes:
        print(nd)
