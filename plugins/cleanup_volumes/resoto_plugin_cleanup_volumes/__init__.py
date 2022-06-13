from resotolib.baseplugin import BaseActionPlugin
from resotolib.logger import log
from resotolib.core.search import CoreGraph
from resotolib.graph import Graph
from resotolib.baseresources import BaseVolume
from resotolib.config import Config
from resotolib.durations import parse_duration
from .config import CleanupVolumesConfig
from typing import Dict


class CleanupVolumesPlugin(BaseActionPlugin):
    action = "cleanup_plan"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.age = None
        if Config.plugin_cleanup_volumes.enabled:
            self.update_age()

    def bootstrap(self) -> bool:
        return Config.plugin_cleanup_volumes.enabled

    def do_action(self, data: Dict) -> None:
        self.update_age()
        cg = CoreGraph(tls_data=self.tls_data)
        query = "is(volume) and reported.volume_status == available <-[0:]->"
        graph = cg.graph(query)
        self.volumes_cleanup(graph)
        cg.patch_nodes(graph)

    def update_age(self) -> None:
        try:
            self.age = parse_duration(Config.plugin_cleanup_volumes.min_age)
            log.debug(f"Volume Cleanup Plugin Age {self.age}")
        except ValueError:
            log.error(f"Error while parsing Volume Cleanup Age {Config.plugin_cleanup_volumes.min_age}")
            raise

    def volumes_cleanup(self, graph: Graph):
        log.info("Volume Cleanup called")
        for node in graph.nodes:
            if (
                isinstance(node, BaseVolume)
                and node.volume_status == "available"
                and node.age > self.age
                and node.last_access is not None
                and node.last_update is not None
                and node.last_access > self.age
                and node.last_update > self.age
            ):
                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)
                log.debug(
                    (
                        f"Found available volume {node.dname} in cloud {cloud.name} account {account.dname} "
                        f"region {region.name} with age {node.age}. Last update was {node.last_update} ago "
                        f"and last access {node.last_access} ago both of which is longer than {self.age} "
                        f"- setting to be cleaned"
                    )
                )
                node.clean = True

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(CleanupVolumesConfig)
