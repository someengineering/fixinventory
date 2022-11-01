from typing import Optional, List, Tuple

from resoto_plugin_digitalocean.client import StreamingWrapper, get_team_credentials
from resoto_plugin_digitalocean.collector import DigitalOceanTeamCollector
from resoto_plugin_digitalocean.resources import DigitalOceanResource, DigitalOceanTeam
from resoto_plugin_digitalocean.config import DigitalOceanCollectorConfig
from resoto_plugin_digitalocean.utils import dump_tag
from resotolib.config import Config
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.core.actions import CoreFeedback
from resotolib.logger import log
from resotolib.graph import Graph
from resotolib.baseresources import BaseResource
import time


class DigitalOceanCollectorPlugin(BaseCollectorPlugin):
    cloud = "digitalocean"

    def __init__(self) -> None:
        super().__init__()
        self.core_feedback: Optional[CoreFeedback] = None

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
        assert self.core_feedback, "core_feedback is not set"  # will be set by the outer collector plugin

        def spaces_keys_valid(keys: List[str]) -> bool:
            return all([len(key.split(":")) == 2 for key in keys])

        if not spaces_keys_valid(spaces_access_keys):
            log.warn("DigitalOcean Spaces access keys must be provided in pairs of access_key:secret_key")
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
            team_graph = self.collect_team(client, self.core_feedback.with_context("digitalocean"))
            if team_graph:
                self.graph.merge(team_graph)

    def collect_team(self, client: StreamingWrapper, feedback: CoreFeedback) -> Optional[Graph]:
        """Collects an individual team."""
        team_id = client.get_team_id()
        team = DigitalOceanTeam(id=team_id, tags={}, urn=f"do:team:{team_id}")

        try:
            feedback.progress_done(team_id, 0, 1)
            team_feedback = feedback.with_context("digitalocean", client.get_team_id())
            dopc = DigitalOceanTeamCollector(team, client.with_feedback(team_feedback))
            dopc.collect()
            feedback.progress_done(team_id, 1, 1)
        except Exception:
            log.exception(f"An unhandled error occurred while collecting team {team_id}")
            return None
        else:
            return dopc.graph

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(DigitalOceanCollectorConfig)

    @staticmethod
    def update_tag(config: Config, resource: BaseResource, key: str, value: str) -> bool:
        assert isinstance(resource, DigitalOceanResource)
        tag_resource_name = resource.tag_resource_name()
        if tag_resource_name:

            log.debug(f"Updating tag {key} on resource {resource.id}")
            team = resource.account()
            ten_minutes_bucket = int(time.time()) // 600
            credentials = get_team_credentials(team.id, ten_minutes_bucket)
            if credentials is None:
                raise RuntimeError(
                    f"Cannot update tag on resource {resource.id}, credentials not found for team {team.id}"
                )
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )

            if key in resource.tags:
                # resotocore knows about the tag. Therefore we need to clean it first
                tag_key = dump_tag(key, resource.tags.get(key))
                client.untag_resource(tag_key, tag_resource_name, resource.id)

            # we tag the resource using the key-value formatted tag
            tag_kv = dump_tag(key, value)
            tag_ready: bool = True
            tag_count = client.get_tag_count(tag_kv)
            # tag count call failed irrecoverably, we can't continue
            if isinstance(tag_count, str):
                raise RuntimeError(f"Tag update failed. Reason: {tag_count}")
            # tag does not exist, create it
            if tag_count is None:
                tag_ready = client.create_tag(tag_kv)

            return tag_ready and client.tag_resource(tag_kv, tag_resource_name, resource.id)
        else:
            raise NotImplementedError(f"resource {resource.kind} does not support tagging")

    @staticmethod
    def delete_tag(config: Config, resource: BaseResource, key: str) -> bool:
        assert isinstance(resource, DigitalOceanResource)
        tag_resource_name = resource.tag_resource_name()
        if tag_resource_name:
            log.debug(f"Deleting tag {key} on resource {resource.id}")
            team = resource.account()
            ten_minutes_bucket = int(time.time()) // 600
            credentials = get_team_credentials(team.id, ten_minutes_bucket)
            if credentials is None:
                raise RuntimeError(
                    f"Cannot update tag on resource {resource.id}, credentials not found for team {team.id}"
                )
            client = StreamingWrapper(
                credentials.api_token,
                credentials.spaces_access_key,
                credentials.spaces_secret_key,
            )

            if key not in resource.tags:
                # tag does not exist, nothing to do
                return False

            tag_key = dump_tag(key, resource.tags.get(key))
            untagged = client.untag_resource(tag_key, tag_resource_name, resource.id)
            if not untagged:
                return False
            tag_count = client.get_tag_count(tag_key)
            if tag_count == 0:
                return client.delete("/tags", tag_key)
            return True
        else:
            raise NotImplementedError(f"resource {resource.kind} does not support tagging")
