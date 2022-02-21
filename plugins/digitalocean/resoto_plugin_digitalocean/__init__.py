from typing import Any, Dict, Optional
import resotolib.logging
from resotolib.logging import log, setup_logger
import resotolib.signal
import os
from datetime import datetime
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import EdgeType
from resotolib.args import ArgumentParser

from resoto_digitalocean_client.api import project_resources_api, projects_api, regions_api
from resoto_digitalocean_client import Configuration, ApiClient

from .resources import DigitalOceanProject
from .collector import DigitalOceanProjectCollector



class DigitalOceanCollectorPlugin(BaseCollectorPlugin):
    cloud = "digitalocean"

    # todo: add a proper config mechanism
    # todo: support multiple accounts
    config = Configuration(access_token=os.environ['DO_TOKEN'])
    client = ApiClient(config)

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        log.debug("plugin: collecting DigitalOcean resources")

        projects_api_instance = projects_api.ProjectsApi(self.client)

        projects = projects_api_instance.list_projects()

        for project in projects.get('projects', []):
            self.collect_project(project['id'])


    @staticmethod
    def collect_project(project: Dict[str, Any]) -> Optional[Dict]:
        """Collects an individual project.
        
        Is being called in collect() and either run within a thread or a spawned
        process. Depending on whether `--gcp-fork` was specified or not.

        Because the spawned process does not inherit any of our memory or file
        descriptors we are passing the already parsed `args` Namespace() to this
        method.
        """

        project = DigitalOceanProject(id=project['id'], tags={}, name=project['name'])
        
        try:
            dopc = DigitalOceanProjectCollector(project)
            dopc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting {project.rtdname}"
            )
        else:
            return dopc.graph


    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--digitalocean-region",
            help="DigitalOcean Region",
            dest="digitalocean_region",
            type=str,
            default=None,
            nargs="+",
        )
