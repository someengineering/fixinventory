import base64
import hashlib
import secrets
from typing import Optional, Dict

from resotocore.analytics import AnalyticsEventSender, CoreEvent
from resotocore.config import ConfigHandler, ConfigEntity
from resotocore.db.db_access import DbAccess
from resotocore.model.typed_model import from_js, to_js
from resotocore.types import Json
from resotocore.user import UserManagement, UsersConfigId, ResotoUser, UsersConfigRoot
from resotocore.util import value_in_path_get, value_in_path

ALGORITHM = "pbkdf2_sha512"
DELIMITER = "$"
ITERATIONS = 210000  # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2


class UserManagementService(UserManagement):
    def __init__(self, db_access: DbAccess, config_handler: ConfigHandler, event_sender: AnalyticsEventSender):
        self.db_access = db_access
        self.config_handler = config_handler
        self.event_sender = event_sender

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> str:
        if salt is None:
            salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS)
        b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
        return f"{DELIMITER}{ALGORITHM}{DELIMITER}{salt}{DELIMITER}{b64_hash}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        if (password_hash or "").count(DELIMITER) != 3:
            return False
        _, algorithm, salt, _ = password_hash.split(DELIMITER)
        assert algorithm == ALGORITHM
        compare_hash = UserManagementService.hash_password(password, salt)
        return secrets.compare_digest(password_hash, compare_hash)

    async def has_users(self) -> bool:
        user_config = await self.config_handler.get_config(UsersConfigId)
        return bool(value_in_path(user_config.config, [UsersConfigRoot, "users"])) if user_config else False

    async def create_first_user(self, company: str, fullname: str, email: str, password: str) -> ResotoUser:
        assert not await self.has_users()  # only allowed if no users exist
        await self.db_access.system_data_db.update_info(company=company)
        hashed = self.hash_password(password)
        user = ResotoUser(fullname=fullname, password_hash=hashed, roles={"admin"})
        await self.config_handler.put_config(
            ConfigEntity(UsersConfigId, {UsersConfigRoot: {"users": {email: to_js(user)}}})
        )
        await self.event_sender.core_event(
            CoreEvent.FirstUserCreated, {"company": company, "fullname": fullname, "email": email}
        )
        return user

    async def login(self, email: str, password: str) -> Optional[ResotoUser]:
        user_config = await self.config_handler.get_config(UsersConfigId)
        if user_config:
            users: Dict[str, Json] = value_in_path_get(user_config.config, [UsersConfigRoot, "users"], {})
            if (user := users.get(email)) and self.verify_password(password, user.get("password_hash", "")):
                return from_js(user, ResotoUser)
        return None
