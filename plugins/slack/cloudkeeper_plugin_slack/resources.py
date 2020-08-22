import time
from typing import Dict
from datetime import datetime
from cloudkeeper.baseresources import BaseAccount, BaseRegion, BaseUser, BaseGroup, BaseResource


class SlackResource:
    def delete(self, graph) -> bool:
        return False


class SlackTeam(SlackResource, BaseAccount):
    resource_type = 'slack_team'

    def __init__(self, identifier, tags, team: Dict):
        super().__init__(identifier, tags)
        self.id = team.get('id')
        self.name = team.get('name')
        self.domain = team.get('domain')
        self.email_domain = team.get('email_domain')
        self.icon = team.get('icon', {}).get('image_original')


class SlackRegion(SlackResource, BaseRegion):
    resource_type = 'slack_region'


class SlackUser(SlackResource, BaseUser):
    resource_type = 'slack_user'

    def __init__(self, identifier, tags, member: Dict):
        super().__init__(identifier, tags)
        self.id = member.get('id')
        self.real_name = member.get('real_name')
        self.team_id = member.get('team_id')
        self.deleted = member.get('deleted')
        self.color = member.get('color')
        self.tz = member.get('tz')
        self.tz_label = member.get('tz_label')
        self.tz_offset = member.get('tz_offset')
        self.is_admin = member.get('is_admin')
        self.is_app_user = member.get('is_app_user')
        self.is_bot = member.get('is_bot')
        self.is_owner = member.get('is_owner')
        self.is_primary_owner = member.get('is_primary_owner')
        self.is_restricted = member.get('is_restricted')
        self.is_ultra_restricted = member.get('is_ultra_restricted')

        self.mtime = datetime.fromtimestamp(member.get('updated', time.time()))
        self.ctime = self.mtime

        profile = member.get('profile', {})
        self.email = profile.get('email')
        self.phone = profile.get('phone')
        self.status_emoji = profile.get('status_emoji')
        self.status_expiration = profile.get('status_expiration')
        self.status_text = profile.get('status_text')
        self.status_text_canonical = profile.get('status_text_canonical')
        self.title = profile.get('title')
        self.guest_invited_by = profile.get('guest_invited_by')
        self.first_name = profile.get('first_name')
        self.last_name = profile.get('last_name')
        self.skype = profile.get('skype')
        self.display_name = profile.get('display_name')
        self.name = self.display_name
        self.display_name_normalized = profile.get('display_name_normalized')
        self.image_24 = profile.get('image_24')
        self.image_32 = profile.get('image_32')
        self.image_48 = profile.get('image_48')
        self.image_72 = profile.get('image_72')
        self.image_192 = profile.get('image_192')
        self.image_512 = profile.get('image_512')
        self.real_name_normalized = profile.get('real_name_normalized')


class SlackUsergroup(SlackResource, BaseGroup):
    resource_type = 'slack_usergroup'

    def __init__(self, identifier, tags, usergroup: Dict):
        super().__init__(identifier, tags)
        self.id = usergroup.get('id')
        self.name = usergroup.get('name')
        self.auto_provision = usergroup.get('auto_provision')
        self.auto_type = usergroup.get('auto_type')
        self.created_by = usergroup.get('created_by')
        self.description = usergroup.get('description')
        self.enterprise_subteam_id = usergroup.get('enterprise_subteam_id')
        self.handle = usergroup.get('handle')
        self.is_external = usergroup.get('is_external')
        self.is_subteam = usergroup.get('is_subteam')
        self.is_usergroup = usergroup.get('is_usergroup')
        self.team_id = usergroup.get('team_id')
        self.updated_by = usergroup.get('updated_by')
        self.user_count = usergroup.get('user_count')
        self.ctime = datetime.fromtimestamp(usergroup.get('date_create', time.time()))
        self.mtime = datetime.fromtimestamp(usergroup.get('date_update', time.time()))
        self._users = usergroup.get('users', [])
        prefs = usergroup.get('prefs', {})
        self._channels = prefs.get('channels', [])
        self._groups = prefs.get('groups', [])


class SlackConversation(SlackResource, BaseResource):
    resource_type = 'slack_conversation'

    def __init__(self, identifier, tags, channel: Dict):
        super().__init__(identifier, tags)
        self.id = channel.get('id')
        self.name = channel.get('name')
        self.creator = channel.get('creator')
        self.is_archived = channel.get('is_archived')
        self.is_channel = channel.get('is_channel')
        self.is_ext_shared = channel.get('is_ext_shared')
        self.is_general = channel.get('is_general')
        self.is_group = channel.get('is_group')
        self.is_im = channel.get('is_im')
        self.is_member = channel.get('is_member')
        self.is_mpim = channel.get('is_mpim')
        self.is_org_shared = channel.get('is_org_shared')
        self.is_pending_ext_shared = channel.get('is_pending_ext_shared')
        self.is_private = channel.get('is_private')
        self.is_shared = channel.get('is_shared')
        self.name_normalized = channel.get('name_normalized')
        self.num_members = channel.get('num_members')
        self.parent_conversation = channel.get('parent_conversation')
        self.pending_connected_team_ids = channel.get('pending_connected_team_ids', [])
        self.pending_shared = channel.get('pending_shared', [])
        self.previous_names = channel.get('previous_names', [])
        self.shared_team_ids = channel.get('shared_team_ids', [])
        self.unlinked = channel.get('unlinked')
        topic = channel.get('topic', {})
        self.topic = topic.get('value', '')
        self.topic_creator = topic.get('creator')
        self.topic_last_set = topic.get('last_set')
        purpose = channel.get('purpose', {})
        self.purpose = purpose.get('value', '')
        self.purpose_creator = purpose.get('creator')
        self.purpose_last_set = purpose.get('last_set')
