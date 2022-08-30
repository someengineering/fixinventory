import requests
from resotolib.logger import log
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .config import DockerHubConfig
from .resources import (
    DockerHubNamespace,
    DockerHubRepo,
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
            r = requests.get(f"{self.dockerhub_uri}{namespace}")
            if r.status_code != 200:
                log.error(f"Error collecting Docker Hub resources in namespace {namespace}: {r.status_code} {r.text}")
                continue
            count = r.json()["count"]
            results = r.json()["results"]
            ns = DockerHubNamespace(id=namespace, count=count)
            self.graph.add_resource(self.graph.root, ns)
            for repo in results:
                r = DockerHubRepo.new(repo)
                self.graph.add_resource(ns, r)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(DockerHubConfig)
