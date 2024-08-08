import fixlib.logger
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.args import ArgumentParser
from fixlib.config import Config
from fixlib.core.actions import CoreFeedback
from fixlib.graph import Graph, MaxNodesExceeded
from fixlib.baseresources import Cloud
from fixlib.logger import log
from typing import Any, Optional
from .config import HetznerConfig
from .collector import HcloudCollector
from .resources import HcloudProject

log = fixlib.logger.getLogger("fix." + __name__)


class HetznerCollectorPlugin(BaseCollectorPlugin):
    cloud = "hetzner"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.core_feedback: Optional[CoreFeedback] = None

    def collect(self) -> None:
        assert self.core_feedback, "core_feedback is not set"
        if len(Config.hetzner.hcloud_tokens) != len(Config.hetzner.hcloud_project_names):
            log.error("The number of tokens and project names must be the same!")
            return
        self.collect_hcloud()

    def collect_hcloud(self) -> None:
        log.debug("plugin: collecting Hetzner Cloud resources")
        feedback = self.core_feedback.with_context("hetzner")
        cloud = Cloud(id=self.cloud, name="Hetzner")

        for i, api_token in enumerate(Config.hetzner.hcloud_tokens):
            project = HcloudProject(id=Config.hetzner.hcloud_project_names[i])
            self.core_feedback.progress_done(project.id, 0, 1)
            collector = HcloudCollector(cloud, project, api_token, feedback, self.max_resources_per_account)
            try:
                collector.collect()
                self.send_account_graph(collector.graph)
            except MaxNodesExceeded:
                log.error(f"Max nodes exceeded, stopping collection in {project.kdname}")
                continue
            except Exception as e:
                log.error(f"Error collecting resources in {project.kdname}: {e}")
                continue
            finally:
                self.core_feedback.progress_done(project.id, 1, 1)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def add_config(config: Config) -> None:
        """Add any plugin config to the global config store.

        Method called by the PluginLoader upon plugin initialization.
        Can be used to introduce plugin config arguments to the global config store.
        """
        config.add_config(HetznerConfig)
        pass
