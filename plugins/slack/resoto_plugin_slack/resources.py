import time
from typing import Dict, ClassVar, List, Optional
from datetime import datetime
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseUser,
    BaseGroup,
    BaseResource,
    ModelReference,
)
from attrs import define, field


@define(eq=False, slots=False)
class SlackResource:
    kind: ClassVar[str] = "slack_resource"

    def delete(self, graph) -> bool:
        return False


@define(eq=False, slots=False)
class SlackTeam(SlackResource, BaseAccount):
    kind: ClassVar[str] = "slack_team"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["slack_region"],
            "delete": [],
        }
    }
    domain: str = None
    email_domain: str = None
    icon: str = None

    @staticmethod
    def new(team: Dict) -> BaseAccount:
        return SlackTeam(
            id=team.get("id"),
            tags={},
            name=team.get("name"),
            domain=team.get("domain"),
            email_domain=team.get("email_domain"),
            icon=team.get("icon", {}).get("image_original"),
        )


@define(eq=False, slots=False)
class SlackRegion(SlackResource, BaseRegion):
    kind = "slack_region"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["slack_usergroup", "slack_user", "slack_conversation"],
            "delete": [],
        }
    }


@define(eq=False, slots=False)
class SlackUser(SlackResource, BaseUser):
    kind: ClassVar[str] = "slack_user"

    real_name: Optional[str] = None
    team_id: Optional[str] = None
    deleted: bool = None
    color: Optional[str] = None
    tz: Optional[str] = None
    tz_label: Optional[str] = None
    tz_offset: Optional[int] = None
    is_admin: bool = None
    is_app_user: bool = None
    is_bot: bool = None
    is_owner: bool = None
    is_primary_owner: bool = None
    is_restricted: bool = None
    is_ultra_restricted: bool = None
    email: Optional[str] = None
    phone: Optional[str] = None
    status_emoji: Optional[str] = None
    status_expiration: Optional[int] = None
    status_text: Optional[str] = None
    status_text_canonical: Optional[str] = None
    title: Optional[str] = None
    guest_invited_by: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    skype: Optional[str] = None
    display_name: Optional[str] = None
    display_name_normalized: Optional[str] = None
    image_24: Optional[str] = None
    image_32: Optional[str] = None
    image_48: Optional[str] = None
    image_72: Optional[str] = None
    image_192: Optional[str] = None
    image_512: Optional[str] = None
    real_name_normalized: Optional[str] = None

    @staticmethod
    def new(member: Dict) -> BaseUser:
        profile = member.get("profile", {})
        mtime = datetime.fromtimestamp(member.get("updated", time.time()))
        display_name = profile.get("display_name")
        return SlackUser(
            id=member.get("id"),
            tags={},
            real_name=member.get("real_name"),
            team_id=member.get("team_id"),
            deleted=member.get("deleted"),
            color=member.get("color"),
            tz=member.get("tz"),
            tz_label=member.get("tz_label"),
            tz_offset=member.get("tz_offset"),
            is_admin=member.get("is_admin", False),
            is_app_user=member.get("is_app_user", False),
            is_bot=member.get("is_bot", False),
            is_owner=member.get("is_owner", False),
            is_primary_owner=member.get("is_primary_owner", False),
            is_restricted=member.get("is_restricted", False),
            is_ultra_restricted=member.get("is_ultra_restricted", False),
            mtime=mtime,
            ctime=mtime,
            email=profile.get("email"),
            phone=profile.get("phone"),
            status_emoji=profile.get("status_emoji"),
            status_expiration=profile.get("status_expiration"),
            status_text=profile.get("status_text"),
            status_text_canonical=profile.get("status_text_canonical"),
            title=profile.get("title"),
            guest_invited_by=profile.get("guest_invited_by"),
            first_name=profile.get("first_name"),
            last_name=profile.get("last_name"),
            skype=profile.get("skype"),
            display_name=display_name,
            name=display_name,
            display_name_normalized=profile.get("display_name_normalized"),
            image_24=profile.get("image_24"),
            image_32=profile.get("image_32"),
            image_48=profile.get("image_48"),
            image_72=profile.get("image_72"),
            image_192=profile.get("image_192"),
            image_512=profile.get("image_512"),
            real_name_normalized=profile.get("real_name_normalized"),
        )


@define(eq=False, slots=False)
class SlackUsergroup(SlackResource, BaseGroup):
    kind: ClassVar[str] = "slack_usergroup"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["slack_user"],
            "delete": [],
        }
    }

    auto_provision: bool = None
    auto_type: Optional[str] = None
    created_by: Optional[str] = None
    description: Optional[str] = None
    enterprise_subteam_id: Optional[str] = None
    handle: Optional[str] = None
    is_external: bool = None
    is_subteam: bool = None
    is_usergroup: bool = None
    team_id: Optional[str] = None
    updated_by: Optional[str] = None
    user_count: Optional[int] = None
    _users: List = field(factory=list, repr=False)
    _channels: List = field(factory=list, repr=False)
    _groups: List = field(factory=list, repr=False)

    @staticmethod
    def new(usergroup: Dict) -> BaseGroup:
        prefs = usergroup.get("prefs", {})
        return SlackUsergroup(
            id=usergroup.get("id"),
            name=usergroup.get("name"),
            auto_provision=usergroup.get("auto_provision", False),
            auto_type=usergroup.get("auto_type"),
            created_by=usergroup.get("created_by"),
            description=usergroup.get("description"),
            enterprise_subteam_id=usergroup.get("enterprise_subteam_id"),
            handle=usergroup.get("handle"),
            is_external=usergroup.get("is_external", False),
            is_subteam=usergroup.get("is_subteam", False),
            is_usergroup=usergroup.get("is_usergroup", False),
            team_id=usergroup.get("team_id"),
            updated_by=usergroup.get("updated_by"),
            user_count=usergroup.get("user_count"),
            ctime=datetime.fromtimestamp(usergroup.get("date_create", time.time())),
            mtime=datetime.fromtimestamp(usergroup.get("date_update", time.time())),
            _users=usergroup.get("users", []),
            _channels=prefs.get("channels", []),
            _groups=prefs.get("groups", []),
        )


@define(eq=False, slots=False)
class SlackConversation(SlackResource, BaseResource):
    kind: ClassVar[str] = "slack_conversation"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["slack_user"],
            "delete": [],
        }
    }

    creator: Optional[str] = None
    is_archived: bool = None
    is_channel: bool = None
    is_ext_shared: bool = None
    is_general: bool = None
    is_group: bool = None
    is_im: bool = None
    is_member: bool = None
    is_mpim: bool = None
    is_org_shared: bool = None
    is_pending_ext_shared: bool = None
    is_private: bool = None
    is_shared: bool = None
    name_normalized: Optional[str] = None
    num_members: Optional[int] = None
    parent_conversation: Optional[str] = None
    pending_connected_team_ids: List[str] = None
    pending_shared: List[str] = field(factory=list)
    previous_names: List[str] = field(factory=list)
    shared_team_ids: List[str] = field(factory=list)
    unlinked: Optional[int] = None
    topic: Optional[str] = None
    topic_creator: Optional[str] = None
    topic_last_set: Optional[int] = None
    purpose: Optional[str] = None
    purpose_creator: Optional[str] = None
    purpose_last_set: Optional[int] = None

    @staticmethod
    def new(channel: Dict) -> BaseResource:
        topic = channel.get("topic", {})
        purpose = channel.get("purpose", {})
        return SlackConversation(
            id=channel.get("id"),
            name=channel.get("name"),
            creator=channel.get("creator"),
            is_archived=channel.get("is_archived", False),
            is_channel=channel.get("is_channel", False),
            is_ext_shared=channel.get("is_ext_shared", False),
            is_general=channel.get("is_general", False),
            is_group=channel.get("is_group", False),
            is_im=channel.get("is_im", False),
            is_member=channel.get("is_member", False),
            is_mpim=channel.get("is_mpim", False),
            is_org_shared=channel.get("is_org_shared", False),
            is_pending_ext_shared=channel.get("is_pending_ext_shared", False),
            is_private=channel.get("is_private", False),
            is_shared=channel.get("is_shared", False),
            name_normalized=channel.get("name_normalized"),
            num_members=channel.get("num_members"),
            parent_conversation=channel.get("parent_conversation"),
            pending_connected_team_ids=channel.get("pending_connected_team_ids", []),
            pending_shared=channel.get("pending_shared", []),
            previous_names=channel.get("previous_names", []),
            shared_team_ids=channel.get("shared_team_ids", []),
            unlinked=channel.get("unlinked"),
            topic=topic.get("value", ""),
            topic_creator=topic.get("creator"),
            topic_last_set=topic.get("last_set"),
            purpose=purpose.get("value", ""),
            purpose_creator=purpose.get("creator"),
            purpose_last_set=purpose.get("last_set"),
        )
