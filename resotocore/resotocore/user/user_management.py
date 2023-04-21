import hashlib
from typing import Optional, Dict

from resotocore.config import ConfigHandler
from resotocore.model.typed_model import from_js
from resotocore.types import Json
from resotocore.user import UserManagement, UsersConfigId, ResotoUser, UsersConfigRoot
from resotocore.util import value_in_path_get


class UserManagementService(UserManagement):
    def __init__(self, config_handler: ConfigHandler):
        self.config_handler = config_handler

    @staticmethod
    def hash_password(password: str) -> str:
        sha = hashlib.sha256()
        sha.update(password.encode("utf-8"))
        return sha.hexdigest()

    async def login(self, email: str, password: str) -> Optional[ResotoUser]:
        user_config = await self.config_handler.get_config(UsersConfigId)
        if user_config:
            users: Dict[str, Json] = value_in_path_get(user_config.config, [UsersConfigRoot, "users"], {})
            if (user := users.get(email)) and user.get("password_hash") == self.hash_password(password):
                return from_js(user, ResotoUser)
        return None
