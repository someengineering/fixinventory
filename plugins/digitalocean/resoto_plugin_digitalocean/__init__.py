from typing import Optional, List, Tuple

from resoto_plugin_digitalocean.client import StreamingWrapper
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanTeam
from resoto_plugin_digitalocean.config import DigitalOceanCollectorConfig
from resotolib.config import Config
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.logger import log
from resotolib.graph import Graph


class DigitalOceanCollectorPlugin(BaseCollectorPlugin):  # type: ignore
    cloud = "digitalocean"

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        tokens = Config.digitalocean.api_tokens
        spaces_access_keys: List[str] = Config.digitalocean.spaces_access_keys
        spaces_keys: List[Tuple[Optional[str], Optional[str]]] = []

        def spaces_keys_valid(keys: List[str]) -> bool:
            return all([len(key.split(":")) == 2 for key in keys])

        if not spaces_keys_valid(spaces_access_keys):
            log.warn(
                "DigitalOcean Spaces access keys must be provided in pairs of access_key:secret_key"
            )
        else:

            def key_to_tuple(key: str) -> Tuple[str, str]:
                splitted = key.split(":")
                return splitted[0], splitted[1]

            spaces_keys = [key_to_tuple(key) for key in spaces_access_keys]

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

    def collect_team(self, client: StreamingWrapper) -> Optional[Graph]:
        """Collects an individual team."""
        team_id = client.get_team_id()
        team = DigitalOceanTeam(id=team_id, tags={}, urn=f"do:team:{team_id}")

        try:
            dopc = DigitalOceanTeamCollector(team, client)
            dopc.collect()
        except Exception:
            log.exception(
                f"An unhandled error occurred while collecting team {team_id}"
            )
            return None
        else:
            return dopc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(DigitalOceanCollectorConfig)
