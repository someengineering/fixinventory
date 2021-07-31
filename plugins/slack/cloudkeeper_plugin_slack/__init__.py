import cloudkeeper.logging
import threading
import os
import time
import slack_sdk
from typing import List
from retrying import retry
from .resources import (
    SlackRegion,
    SlackTeam,
    SlackUser,
    SlackUsergroup,
    SlackConversation,
)
from cloudkeeper.baseplugin import BasePlugin, BaseCollectorPlugin
from cloudkeeper.baseresources import BaseCloud, BaseAccount, BaseRegion, BaseResource
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import (
    Event,
    EventType,
    add_event_listener,
    remove_event_listener,
)
from cloudkeeper.graph import Graph

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


def retry_on_request_limit_exceeded(e):
    if isinstance(e, slack_sdk.errors.SlackApiError):
        if (
            not e.response.data.get("ok", False)
            and e.response.data.get("error") == "ratelimited"
        ):
            retry_after = int(e.response.headers.get("Retry-After", 20))
            log.debug(
                f"Slack API request limit exceeded, retrying after {retry_after} seconds"
            )
            time.sleep(retry_after)
            return True
    return False


class SlackCollectorPlugin(BaseCollectorPlugin):
    cloud = "slack"

    def __init__(self):
        super().__init__()
        self.client = None

    def collect(self) -> None:
        if not ArgumentParser.args.slack_bot_token:
            log.info("Slack Collector Plugin: plugin loaded but no bot token provided")
            return

        log.info("Slack Collector Plugin: collecting Slack resources")
        self.client = slack_sdk.WebClient(token=ArgumentParser.args.slack_bot_token)

        response = self.client.team_info()
        if not response.data.get("ok", False):
            log.error("Failed to retrieve Slack Account information")
            return

        team = response.data.get("team", {})
        team_id = team.get("id")
        team = SlackTeam(team_id, {}, team)
        self.graph.add_resource(self.root, team)

        members = SlackRegion("members", {})
        self.graph.add_resource(team, members)
        usergroups = SlackRegion("usergroups", {})
        self.graph.add_resource(team, usergroups)
        conversations = SlackRegion("conversations", {})
        self.graph.add_resource(team, conversations)

        for member in self.list_members():
            u = SlackUser(member["id"], {}, member)
            log.debug(
                f"Found Slack User {u.name}: {u.real_name} ({u.email}) - {u.mtime}"
            )
            self.graph.add_resource(members, u)

        for usergroup in self.list_usergroups():
            ug = SlackUsergroup(usergroup["id"], {}, usergroup)
            log.debug(f"Found Slack Usergroup {ug.name}")
            self.graph.add_resource(usergroups, ug)
            for user_id in ug._users:
                u = self.graph.search_first("id", user_id)
                if u:
                    self.graph.add_edge(ug, u)

        for conversation in self.list_conversations():
            c = SlackConversation(conversation["id"], {}, conversation)
            conversation_type = "Conversation "
            if c.is_channel:
                conversation_type = "Channel #"
            log.debug(f"Found Slack {conversation_type}{c.name}")
            self.graph.add_resource(conversations, c)

            members = self.list_conversation_members(c)
            for member_id in members:
                m = self.graph.search_first_all(
                    {"resource_type": "slack_user", "id": member_id}
                )
                self.graph.add_edge(m, c)

    @retry(
        stop_max_attempt_number=10, retry_on_exception=retry_on_request_limit_exceeded
    )
    def list_conversations(self) -> List:
        log.debug("Fetching list of Slack Conversations")
        channel_types = "public_channel,private_channel"
        channel_limit = 100
        exclude_archived = not ArgumentParser.args.slack_include_archived
        response = self.client.conversations_list(
            exclude_archived=exclude_archived, types=channel_types, limit=channel_limit
        )
        conversations = response.data.get("channels", [])
        while response.data.get("response_metadata", {}).get("next_cursor", "") != "":
            response = self.client.conversations_list(
                cursor=response.data["response_metadata"]["next_cursor"],
                exclude_archived=exclude_archived,
                types=channel_types,
                limit=channel_limit,
            )
            log.debug("Fetching more Slack conversations")
            conversations.extend(response.data.get("channels", []))
        return conversations

    @retry(
        stop_max_attempt_number=10, retry_on_exception=retry_on_request_limit_exceeded
    )
    def list_conversation_members(self, conversation) -> List:
        log.debug(
            f"Fetching list of Slack Conversation members for {conversation.rtdname}"
        )
        members = []
        try:
            response = self.client.conversations_members(channel=conversation.id)
            members = response.data.get("members", [])
            while (
                response.data.get("response_metadata", {}).get("next_cursor", "") != ""
            ):
                response = self.client.conversations_list(
                    channel=conversation.id,
                    cursor=response.data["response_metadata"]["next_cursor"],
                )
                log.debug("Fetching more Slack conversation members")
                members.extend(response.data.get("members", []))
        except slack_sdk.errors.SlackApiError as e:
            if (
                not e.response.data.get("ok", False)
                and e.response.data.get("error") == "internal_error"
            ):
                log.error(
                    (
                        "Slack responded with an internal error - "
                        f"skipping members list for {conversation.rtdname}"
                    )
                )
                return []
            else:
                raise
        return members

    @retry(
        stop_max_attempt_number=10, retry_on_exception=retry_on_request_limit_exceeded
    )
    def list_usergroups(self) -> List:
        log.debug("Fetching list of Slack Usergroups")
        response = self.client.usergroups_list(
            include_users="true", include_count="true", include_disabled="false"
        )
        return response.data.get("usergroups", [])

    @retry(
        stop_max_attempt_number=10, retry_on_exception=retry_on_request_limit_exceeded
    )
    def list_members(self) -> List:
        log.debug("Fetching list of Slack Users")
        response = self.client.users_list()
        members = response.data.get("members", [])
        while response.data.get("response_metadata", {}).get("next_cursor", "") != "":
            response = self.client.users_list(
                cursor=response.data["response_metadata"]["next_cursor"]
            )
            log.debug("Fetching more Slack users")
            members.extend(response.data.get("members", []))
        return members

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        pass


class SlackBotPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "slack_bot"
        if not ArgumentParser.args.slack_bot_token:
            return

        self.client = slack_sdk.WebClient(token=ArgumentParser.args.slack_bot_token)
        self.exit = threading.Event()
        self.users2id = {}
        self.emails2id = {}
        self.usergroups2id = {}
        self.channels2id = {}

        add_event_listener(EventType.SHUTDOWN, self.shutdown)
        add_event_listener(
            EventType.CLEANUP_FINISH, self.process_cloudkeeper_events, blocking=False
        )

    def __del__(self):
        remove_event_listener(EventType.CLEANUP_FINISH, self.process_cloudkeeper_events)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        if not ArgumentParser.args.slack_bot_token:
            return

        self.exit.wait()

    def process_cloudkeeper_events(self, event: Event):
        graph = event.data
        log.info("Checking for outstanding Slack notifications")
        self.update_users_groups_channels(graph)

        with graph.lock.read_access:
            for node in graph.nodes:
                if (
                    isinstance(node, BaseResource)
                    and len(node.event_log) > 0
                    and "cloudkeeper:owner" in node.tags
                ):
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)
                    owner_tag = str(node.tags["cloudkeeper:owner"])

                    if (
                        not isinstance(cloud, BaseCloud)
                        or not isinstance(account, BaseAccount)
                        or not isinstance(region, BaseRegion)
                    ):
                        continue

                    destination = None
                    if owner_tag.startswith("slack:"):
                        owner = owner_tag[6:]
                        destination = self.users2id.get(owner)
                    elif owner_tag.startswith("email:"):
                        owner = owner_tag[6:]
                        destination = self.emails2id.get(owner)
                    else:
                        log.error(
                            (
                                f"Unknown owner tag format {owner_tag} for node {node.dname} in cloud {cloud.name} "
                                f"account {account.dname} region {region.name}"
                            )
                        )

                    if not isinstance(destination, SlackUser):
                        log.error(
                            f"Unable to determine Slack destination based on cloudkeeper:owner tag value {owner_tag}"
                        )
                        continue

                    event_log_text = ""
                    for event in node.event_log:
                        event_log_text += (
                            f"{event['timestamp'].isoformat()} {event['msg']}" + "\n"
                        )
                    slack_message = (
                        f"Hello {destination.first_name}, your cloud resource `{node.dname}` in "
                        f"cloud `{cloud.name}` account `{account.dname}` region `{region.name}`"
                        f" was modified during the current cloudkeeper run. Here is the "
                        f"event log:\n```\n{event_log_text}```"
                    )
                    self.send_slack_message(destination.id, slack_message)

    @retry(
        stop_max_attempt_number=10, retry_on_exception=retry_on_request_limit_exceeded
    )
    def send_slack_message(self, user_id, message):
        log.debug(f"Sending Slack message to ID {user_id}")
        response = self.client.conversations_open(users=[user_id])
        if response.data.get("ok", False):
            channel = response.data.get("channel", {}).get("id")
            self.client.chat_postMessage(channel=channel, text=message)

    def update_users_groups_channels(self, graph: Graph):
        log.debug("Updating Users Groups and Channels")
        with graph.lock.read_access:
            tmp_users = {}
            tmp_emails = {}
            tmp_usergroups = {}
            tmp_channels = {}
            for user in graph.search("resource_type", "slack_user"):
                tmp_users[user.name] = user
                if user.email:
                    tmp_emails[user.email] = user
            for usergroup in graph.search("resource_type", "slack_usergroup"):
                if usergroup.is_usergroup:
                    tmp_usergroups[usergroup.name] = usergroup
            for channel in graph.search("resource_type", "slack_conversation"):
                if channel.is_channel:
                    tmp_channels[channel.name] = channel
            self.users2id = tmp_users
            self.emails2id = tmp_emails
            self.usergroups2id = tmp_usergroups
            self.channels2id = tmp_channels

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--slack-bot-token",
            help="Slack Bot Token (default env $SLACK_BOT_TOKEN)",
            default=os.environ.get("SLACK_BOT_TOKEN"),
            dest="slack_bot_token",
            type=str,
        )
        arg_parser.add_argument(
            "--slack-include-archived",
            help="Include archived slack channels",
            dest="slack_include_archived",
            action="store_true",
            default=False,
        )

    def shutdown(self, event: Event):
        log.debug(f"Received event {event.event_type} - shutting down Slack plugin")
        self.exit.set()
