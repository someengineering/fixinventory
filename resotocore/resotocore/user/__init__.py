from abc import ABC, abstractmethod
from typing import Dict, List, ClassVar, Optional, Type, Set, Any

from attr import define, field

from resotocore.ids import ConfigId
from resotocore.model.typed_model import to_js
from resotocore.types import Json
from resotocore.web.service import Service
from resotolib.core.model_export import dataclasses_to_resotocore_model

UsersConfigRoot = "resoto_users"
UsersConfigId = ConfigId("resoto.users")


@define
class ResotoUser:
    kind: ClassVar[str] = "resoto_user"
    fullname: str = field(metadata={"description": "The full name of the user."})
    password_hash: str = field(metadata={"description": "The sha256 hash of the user's password."})


@define
class ResotoUsersConfig:
    kind: ClassVar[str] = UsersConfigRoot
    users: Dict[str, ResotoUser] = field(factory=lambda: {}, metadata={"description": "A map of email to user data."})

    def json(self) -> Json:
        return {UsersConfigRoot: to_js(self, strip_attr="kind")}


class UserManagement(Service, ABC):
    @abstractmethod
    async def has_users(self) -> bool:
        """
        Indicates if users exist in the system.
        """

    @abstractmethod
    async def create_first_user(self, company: str, fullname: str, email: str, password: str) -> ResotoUser:
        """
        Create the first user in the system.
        Precondition: has_users() == False
        :param company: the name of the company
        :param fullname: the full name of the user
        :param email: the email address of the user
        :param password: the password of the user
        :return: the created user
        :throws: AssertionError if there are already users in the system.
        """

    @abstractmethod
    async def login(self, email: str, password: str) -> Optional[ResotoUser]:
        """
        Login with the given credentials.
        :param email: the email address of the user
        :param password: the password of the user
        :return: The user if the credentials are valid, None otherwise.
        """


def config_model() -> List[Json]:
    config_classes: Set[Type[Any]] = {ResotoUsersConfig}
    return dataclasses_to_resotocore_model(config_classes, allow_unknown_props=False)