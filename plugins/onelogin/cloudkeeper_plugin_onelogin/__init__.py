import cloudkeeper.logging
import os
from datetime import datetime, timezone
from onelogin.api.client import OneLoginClient
from onelogin.api.models.user import User
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import make_valid_timestamp
from cloudkeeper.baseresources import BaseAccount, BaseRegion, BaseUser

log = cloudkeeper.logging.getLogger('cloudkeeper.' + __name__)


class OneLoginResource:
    def delete(self, graph) -> bool:
        return False


class OneLoginAccount(OneLoginResource, BaseAccount):
    resource_type = 'onelogin_account'


class OneLoginRegion(OneLoginResource, BaseRegion):
    resource_type = 'onelogin_region'


class OneLoginUser(OneLoginResource, BaseUser):
    resource_type = 'onelogin_user'

    def __init__(self, identifier, tags, user: User):
        super().__init__(identifier, tags)
        self.user_id = user.id
        self.external_id = user.external_id
        self.email = user.email
        self.username = user.username
        self.firstname = user.firstname
        self.lastname = user.lastname
        self.distinguished_name = user.distinguished_name
        self.phone = user.phone
        self.company = user.company
        self.department = user.department
        self.title = user.title
        self.status = user.status
        self.member_of = user.member_of
        self.samaccountname = user.samaccountname
        self.userprincipalname = user.userprincipalname
        self.group_id = user.group_id
        self.role_ids = user.role_ids
        self.custom_attributes = user.custom_attributes
        self.openid_name = user.openid_name
        self.locale_code = user.locale_code
        self.comment = user.comment
        self.directory_id = user.directory_id
        self.manager_ad_id = user.manager_ad_id
        self.trusted_idp_id = user.trusted_idp_id
        self.manager_user_id = user.manager_user_id
        self.activated_at = user.activated_at
        self.created_at = user.created_at
        self.updated_at = user.updated_at
        self.password_changed_at = user.password_changed_at
        self.invitation_sent_at = user.invitation_sent_at
        self.invalid_login_attempts = user.invalid_login_attempts
        self.last_login = user.last_login
        self.locked_until = user.locked_until
        self.state = user.state
        self.ctime = self.created_at
        self.atime = self.last_login
        self.mtime = self.updated_at
        self.password_age = datetime.utcnow().replace(tzinfo=timezone.utc) - make_valid_timestamp(self.password_changed_at)

    def delete(self, graph) -> bool:
        return NotImplemented


class OneLoginPlugin(BaseCollectorPlugin):
    cloud = 'onelogin'

    def collect(self) -> None:
        log.debug("plugin: OneLogin collecting resources")

        if not ArgumentParser.args.onelogin_client_id or not ArgumentParser.args.onelogin_client_secret:
            log.debug("OneLogin: no credentials given, skipping collection")
            return

        account = OneLoginAccount(ArgumentParser.args.onelogin_client_id, {})
        self.graph.add_resource(self.root, account)

        region = OneLoginRegion(ArgumentParser.args.onelogin_region, {})
        self.graph.add_resource(account, region)

        self.collect_users(region)

    def collect_users(self, region: OneLoginRegion):
        log.info(f"Collecting OneLogin users in region {region.id}")
        client = onelogin_client()

        users = client.get_users()
        if not users or len(users) == 0:
            log.error('OneLogin returned empty list of users, check auth credentials')
            return

        for user in users:
            log.debug(f'OneLogin: found user {user.email} ({user.id})')
            user = OneLoginUser(user.id, {}, user=user)
            self.graph.add_resource(region, user)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--onelogin-region', help='OneLogin Region', dest='onelogin_region', type=str, default=os.environ.get('ONELOGIN_REGION', 'us'))
        arg_parser.add_argument('--onelogin-client-id', help='OneLogin Client ID', dest='onelogin_client_id', type=str, default=os.environ.get('ONELOGIN_CLIENT_ID'))
        arg_parser.add_argument('--onelogin-client-secret', help='OneLogin Client Secret', dest='onelogin_client_secret', type=str, default=os.environ.get('ONELOGIN_CLIENT_SECRET'))


def onelogin_client() -> OneLoginClient:
    client = OneLoginClient(
        ArgumentParser.args.onelogin_client_id,
        ArgumentParser.args.onelogin_client_secret,
        ArgumentParser.args.onelogin_region
    )
    return client
