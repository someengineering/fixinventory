import requests
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .config import DockerHubConfig
from typing import Optional
from .resources import (
    DockerHubNamespace,
    DockerHubRepository,
)


class DockerHubCollectorPlugin(BaseCollectorPlugin):
    cloud = "dockerhub"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.dockerhub_uri = "https://hub.docker.com/v2/repositories/"

    def collect(self) -> None:
        log.debug("plugin: collecting Docker Hub resources")

        for namespace in Config.dockerhub.namespaces:
            log.debug(f"Collecting Docker Hub resources in namespace {namespace}")

            next = f"{self.dockerhub_uri}{namespace}"
            ns = None
            while next is not None:
                r = fetch_uri(next)
                if r is None:
                    break
                count = r.get("count")
                results = r.get("results", [])
                next = r.get("next")

                if ns is None:
                    ns = DockerHubNamespace(id=namespace, count=count)
                    self.graph.add_resource(self.graph.root, ns)

                for repo in results:
                    r = DockerHubRepository.new(repo)
                    self.graph.add_resource(ns, r)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(DockerHubConfig)


def fetch_uri(uri: str) -> Optional[dict]:
    log.debug(f"Getting {uri}")
    r = requests.get(uri)
    if r.status_code != 200:
        log.error(f"Error collecting Docker Hub resources {uri}: {r.status_code} {r.text}")
        return None
    return r.json()
