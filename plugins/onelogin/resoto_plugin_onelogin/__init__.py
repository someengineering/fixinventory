import resotolib.logger
from datetime import datetime, timedelta, timezone
from onelogin.api.client import OneLoginClient
from onelogin.api.models.user import User
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from resotolib.utils import make_valid_timestamp
from resotolib.baseresources import BaseAccount, BaseRegion, BaseUser
from resotolib.graph import Graph
from attrs import define, field
from typing import ClassVar, Optional, Dict, List
from .config import OneloginConfig

log = resotolib.logger.getLogger("resoto." + __name__)


@define(eq=False, slots=False)
class OneLoginResource:
    kind: ClassVar[str] = "onelogin_resource"

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class OneLoginAccount(OneLoginResource, BaseAccount):
    kind: ClassVar[str] = "onelogin_account"


@define(eq=False, slots=False)
class OneLoginRegion(OneLoginResource, BaseRegion):
    kind: ClassVar[str] = "onelogin_region"


@define(eq=False, slots=False)
class OneLoginUser(OneLoginResource, BaseUser):
    kind: ClassVar[str] = "onelogin_user"
    user_id: Optional[int] = field(default=None, metadata={"description": "User ID"})
    external_id: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    distinguished_name: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    status_code: Optional[int] = None
    member_of: Optional[str] = None
    samaccountname: Optional[str] = None
    userprincipalname: Optional[str] = None
    group_id: Optional[int] = None
    role_ids: Optional[List[int]] = None
    custom_attributes: Optional[Dict[str, str]] = None
    openid_name: Optional[str] = None
    locale_code: Optional[str] = None
    comment: Optional[str] = None
    directory_id: Optional[int] = None
    manager_ad_id: Optional[int] = None
    trusted_idp_id: Optional[int] = None
    manager_user_id: Optional[str] = None
    activated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    invitation_sent_at: Optional[datetime] = None
    invalid_login_attempts: Optional[int] = None
    last_login: Optional[datetime] = None
    locked_until: Optional[datetime] = None
    state: Optional[int] = None
    password_age: Optional[timedelta] = None

    @staticmethod
    def new(user: User) -> BaseUser:
        if user.password_changed_at is not None:
            password_age = datetime.utcnow().replace(tzinfo=timezone.utc) - make_valid_timestamp(
                user.password_changed_at
            )
        else:
            password_age = None

        return OneLoginUser(
            id=str(user.id),
            tags={},
            name=user.username,
            user_id=user.id,
            external_id=user.external_id,
            email=user.email,
            username=user.username,
            firstname=user.firstname,
            lastname=user.lastname,
            distinguished_name=user.distinguished_name,
            phone=user.phone,
            company=user.company,
            department=user.department,
            title=user.title,
            status_code=user.status,
            member_of=user.member_of,
            samaccountname=user.samaccountname,
            userprincipalname=user.userprincipalname,
            group_id=user.group_id,
            role_ids=user.role_ids,
            custom_attributes=user.custom_attributes,
            openid_name=user.openid_name,
            locale_code=user.locale_code,
            comment=user.comment,
            directory_id=user.directory_id,
            manager_ad_id=user.manager_ad_id,
            trusted_idp_id=user.trusted_idp_id,
            manager_user_id=user.manager_user_id,
            activated_at=user.activated_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            password_changed_at=user.password_changed_at,
            invitation_sent_at=user.invitation_sent_at,
            invalid_login_attempts=user.invalid_login_attempts,
            last_login=user.last_login,
            locked_until=user.locked_until,
            state=user.state,
            ctime=user.created_at,
            atime=user.last_login,
            mtime=user.updated_at,
            password_age=password_age,
        )


class OneLoginPlugin(BaseCollectorPlugin):
    cloud = "onelogin"

    def collect(self) -> None:
        log.debug("plugin: OneLogin collecting resources")

        if not Config.onelogin.client_id or not Config.onelogin.client_secret:
            log.debug("OneLogin: no credentials given, skipping collection")
            return

        account = OneLoginAccount(Config.onelogin.client_id, {})
        self.graph.add_resource(self.root, account)

        region = OneLoginRegion(Config.onelogin.region, {})
        self.graph.add_resource(account, region)

        self.collect_users(region)

    def collect_users(self, region: OneLoginRegion):
        log.info(f"Collecting OneLogin users in region {region.id}")
        client = onelogin_client()

        users = client.get_users(max_results=1000000)
        if not users or len(users) == 0:
            log.error("OneLogin returned empty list of users, check auth credentials")
            return

        for user in users:
            log.debug(f"OneLogin: found user {user.email} ({user.id})")
            user = OneLoginUser.new(user)
            self.graph.add_resource(region, user)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(OneloginConfig)


def onelogin_client() -> OneLoginClient:
    client = OneLoginClient(
        Config.onelogin.client_id,
        Config.onelogin.client_secret,
        Config.onelogin.region,
    )
    return client
