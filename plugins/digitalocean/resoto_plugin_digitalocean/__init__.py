from typing import Any, Dict, Optional
from resoto_plugin_digitalocean.client import StreamingWrapper
from resotolib.logging import log, setup_logger
import os
from datetime import datetime
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import Graph
from resotolib.args import ArgumentParser
from functools import reduce


from resoto_digitalocean_openapi_client import Configuration, ApiClient

from .resources import DigitalOceanTeam
from .collector import DigitalOceanTeamCollector



class DigitalOceanCollectorPlugin(BaseCollectorPlugin):
    cloud = "digitalocean"
    # todo: add a proper config mechanism
    # todo: support multiple accounts
    config = Configuration(access_token=os.environ['DO_TOKEN'])
    client = StreamingWrapper(ApiClient(config))

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        log.debug("plugin: collecting DigitalOcean resources")

        team_graph = self.collect_team()

        self.graph.merge(team_graph)


    def collect_team(self) -> Optional[Dict]:
        """Collects an individual team.
        """
        projects = self.client.list_projects()
        team_id = str(projects[0]['owner_id'])
        team = DigitalOceanTeam(id = team_id, tags={})
        
        try:
            dopc = DigitalOceanTeamCollector(team, self.client)
            dopc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting team {team_id}"
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
