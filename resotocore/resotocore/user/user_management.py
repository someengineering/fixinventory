import hashlib
from typing import Optional, Dict

from resotocore.analytics import AnalyticsEventSender, CoreEvent
from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.model.typed_model import from_js
from resotocore.types import Json
from resotocore.user import UserManagement, UsersConfigId, ResotoUser, UsersConfigRoot
from resotocore.util import value_in_path_get, value_in_path


class UserManagementService(UserManagement):
    def __init__(self, config_handler: ConfigHandler, event_sender: AnalyticsEventSender):
        self.config_handler = config_handler
        self.event_sender = event_sender

    @staticmethod
    def hash_password(password: str) -> str:
        sha = hashlib.sha256()
        sha.update(password.encode("utf-8"))
        return sha.hexdigest()

    async def has_users(self) -> bool:
        user_config = await self.config_handler.get_config(UsersConfigId)
        return bool(value_in_path(user_config.config, [UsersConfigRoot, "users"])) if user_config else False

    async def create_first_user(self, company: str, fullname: str, email: str, password: str) -> ResotoUser:
        assert not await self.has_users()  # only allowed if no users exist
        # TODO: store company name
        hashed = self.hash_password(password)
        await self.config_handler.put_config(
            ConfigEntity(
                UsersConfigId,
                {UsersConfigRoot: {"users": {email: {"fullname": fullname, "password_hash": hashed}}}},
            )
        )
        await self.event_sender.core_event(
            CoreEvent.FirstUserCreated, {"company": company, "fullname": fullname, "email": email}
        )
        return ResotoUser(fullname=fullname, password_hash=hashed)

    async def login(self, email: str, password: str) -> Optional[ResotoUser]:
        user_config = await self.config_handler.get_config(UsersConfigId)
        if user_config:
            users: Dict[str, Json] = value_in_path_get(user_config.config, [UsersConfigRoot, "users"], {})
            if (user := users.get(email)) and user.get("password_hash") == self.hash_password(password):
                return from_js(user, ResotoUser)
        return None
