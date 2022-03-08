from typing import Dict, Optional

from resoto_plugin_digitalocean.client import StreamingWrapper
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.logging import log
from collector import DigitalOceanTeamCollector
from resources import DigitalOceanTeam


class DigitalOceanCollectorPlugin(BaseCollectorPlugin):
    cloud = "do"

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        tokens = ArgumentParser.args.digitalocean_api_tokens
        log.info(f"plugin: collecting DigitalOcean resources for {len(tokens)} teams")
        for token in tokens:
            client = StreamingWrapper(token)
            team_graph = self.collect_team(client)
            self.graph.merge(team_graph)

    def collect_team(self, client: StreamingWrapper) -> Optional[Dict]:
        """Collects an individual team."""
        projects = client.list_projects()
        team_id = str(projects[0]["owner_id"])
        team = DigitalOceanTeam(id=team_id, tags={})

        try:
            dopc = DigitalOceanTeamCollector(team, client)
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
            "--digitalocean-api-tokens",
            help="DigitalOcean API tokens for the teams to be collected",
            dest="digitalocean_api_tokens",
            type=str,
            default=[],
            nargs="+",
        )
