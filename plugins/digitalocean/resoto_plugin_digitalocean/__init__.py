from typing import Dict, Optional, List, Tuple

from resoto_plugin_digitalocean.client import StreamingWrapper
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
from resotolib.args import ArgumentParser
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.logging import log


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
        spaces_access_keys: List[
            str
        ] = ArgumentParser.args.digitalocean_spaces_access_keys
        spaces_keys: List[Tuple[Optional[str], Optional[str]]] = []

        if len(spaces_access_keys) % 2 == 0:
            log.warn(
                "DigitalOcean Spaces access keys must be provided in pairs of access_key and secret_key."
            )
        else:
            it = iter(spaces_access_keys)
            spaces_keys = list(zip(it, it))

        if len(tokens) != len(spaces_access_keys):
            log.warn(
                "The number of DigitalOcean API tokens and DigitalOcean Spaces access keys must be equal."
                + "Missing or extra spaces access keys will be ignored."
            )
            spaces_keys = spaces_keys[: len(tokens)]
            spaces_keys.extend([(None, None)] * (len(tokens) - len(spaces_keys)))

        log.info(f"plugin: collecting DigitalOcean resources for {len(tokens)} teams")
        for token, space_key_tuple in zip(tokens, spaces_keys):
            client = StreamingWrapper(token, space_key_tuple[0], space_key_tuple[1])
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
        arg_parser.add_argument(
            "--digitalocean-spaces-access-keys",
            help="DigitalOcean Spaces access keys for the teams to be collected",
            dest="digitalocean_spaces_access_keys",
            type=str,
            default=[],
            nargs="+",
        )
