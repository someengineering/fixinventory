import requests
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .config import PosthogConfig
from typing import Optional
from .resources import (
    PosthogProject,
    PosthogEvent,
)
from .posthog import PosthogAPI


class PosthogCollectorPlugin(BaseCollectorPlugin):
    cloud = "posthog"

    def collect(self) -> None:
        log.debug("plugin: collecting Posthog resources")

        posthog = PosthogAPI(Config.posthog.api_key, Config.posthog.url)

        for project in Config.posthog.projects:
            log.debug(f"Collecting Posthog resources in project {project}")

            p = posthog.project(project)
            self.graph.add_resource(self.graph_root, p)

            for e in posthog.events(p.id):
                self.graph.add_resource(p, e)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(PosthogConfig)
