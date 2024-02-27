import base64
import hashlib
import secrets
from typing import Optional, Dict, List, Callable, TypeVar, Awaitable

from fixcore.analytics import AnalyticsEventSender, CoreEvent
from fixcore.config import ConfigHandler, ConfigEntity
from fixcore.db.db_access import DbAccess
from fixcore.ids import Email, Password
from fixcore.model.typed_model import from_js, to_js
from fixcore.types import Json
from fixcore.user import UserManagement, UsersConfigId, FixInventoryUser, UsersConfigRoot
from fixcore.util import value_in_path_get, value_in_path

ALGORITHM = "pbkdf2_sha512"
DELIMITER = "$"
ITERATIONS = 210000  # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2

T = TypeVar("T")


class UserManagementService(UserManagement):
    def __init__(self, db_access: DbAccess, config_handler: ConfigHandler, event_sender: AnalyticsEventSender):
        super().__init__()
        self.db_access = db_access
        self.config_handler = config_handler
        self.event_sender = event_sender

    @staticmethod
    def hash_password(password: Password, salt: Optional[str] = None) -> str:
        if salt is None:
            salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS)
        b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
        return f"{DELIMITER}{ALGORITHM}{DELIMITER}{salt}{DELIMITER}{b64_hash}"

    @staticmethod
    def verify_password(password: Password, password_hash: str) -> bool:
        if (password_hash or "").count(DELIMITER) != 3:
            return False
        _, algorithm, salt, _ = password_hash.split(DELIMITER)
        assert algorithm == ALGORITHM
        compare_hash = UserManagementService.hash_password(password, salt)
        return secrets.compare_digest(password_hash, compare_hash)

    async def has_users(self) -> bool:
        user_config = await self.config_handler.get_config(UsersConfigId)
        return bool(value_in_path(user_config.config, [UsersConfigRoot, "users"])) if user_config else False

    async def create_first_user(
        self, company: str, fullname: str, email: Email, password: Password
    ) -> FixInventoryUser:
        assert not await self.has_users()  # only allowed if no users exist
        await self.db_access.system_data_db.update_info(company=company)
        hashed = self.hash_password(password)
        user = FixInventoryUser(fullname=fullname, password_hash=hashed, roles={"admin"})
        await self.config_handler.put_config(
            ConfigEntity(UsersConfigId, {UsersConfigRoot: {"users": {email: to_js(user)}}})
        )
        await self.event_sender.core_event(
            CoreEvent.FirstUserCreated, {"company": company, "fullname": fullname, "email": email}
        )
        return user

    async def login(self, email: Email, password: Password) -> Optional[FixInventoryUser]:
        user_config = await self.config_handler.get_config(UsersConfigId)
        if user_config:
            users: Dict[Email, Json] = value_in_path_get(user_config.config, [UsersConfigRoot, "users"], {})
            if (user := users.get(email)) and self.verify_password(password, user.get("password_hash", "")):
                return from_js(user, FixInventoryUser)
        return None

    async def create_user(self, email: Email, fullname: str, password: Password, roles: List[str]) -> FixInventoryUser:
        async def fn(users: Dict[Email, FixInventoryUser]) -> FixInventoryUser:
            if email in users:
                raise ValueError(f"User with email {email} already exists")
            if not email or email.startswith("@") or email.endswith("@") or email.count("@") != 1:
                raise ValueError(f"Invalid email address {email}")
            hashed = self.hash_password(password)
            user = FixInventoryUser(fullname, password_hash=hashed, roles=set(roles))
            users[email] = user
            await self.event_sender.core_event(CoreEvent.UserCreated, {"fullname": fullname, "email": email})
            return user

        return await self.__change_users(fn)

    async def delete_user(self, email: Email) -> Optional[FixInventoryUser]:
        async def fn(users: Dict[Email, FixInventoryUser]) -> Optional[FixInventoryUser]:
            return users.pop(email, None)

        return await self.__change_users(fn)

    async def update_user(
        self, email: Email, *, password: Optional[Password] = None, roles: Optional[List[str]] = None
    ) -> FixInventoryUser:
        async def fn(users: Dict[Email, FixInventoryUser]) -> FixInventoryUser:
            if email not in users:
                raise ValueError(f"User with email {email} does not exist")
            user = users[email]
            if password is not None:
                user.password_hash = self.hash_password(password)
            if roles is not None:
                user.roles = set(roles)
            users[email] = user
            return user

        return await self.__change_users(fn)

    async def __change_users(self, fn: Callable[[Dict[Email, FixInventoryUser]], Awaitable[T]]) -> T:
        users = await self.users()
        result = await fn(users)
        users_raw = {email: to_js(user) for email, user in users.items()}
        await self.config_handler.put_config(ConfigEntity(UsersConfigId, {UsersConfigRoot: {"users": users_raw}}))
        return result

    async def user(self, email: Email) -> Optional[FixInventoryUser]:
        users = await self.users()
        return users.get(email)

    async def users(self) -> Dict[Email, FixInventoryUser]:
        user_config = await self.config_handler.get_config(UsersConfigId)
        users_raw: Json = value_in_path_get(user_config.config, [UsersConfigRoot, "users"], {}) if user_config else {}
        return {Email(email): from_js(data, FixInventoryUser) for email, data in users_raw.items()}
