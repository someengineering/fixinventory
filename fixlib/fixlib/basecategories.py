from dataclasses import dataclass
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class BaseCategory:
    name: str = "category"

    def __str__(self) -> str:
        return self.name

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, BaseCategory):
            return str(self) < str(other)
        return False

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, BaseCategory):
            return str(self) == str(other)
        return False

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, BaseCategory):
            return str(self) > str(other)
        return False


@dataclass(frozen=True)
class Compute(BaseCategory):
    name: str = "compute"
    description: str = "Compute"


@dataclass(frozen=True)
class Storage(BaseCategory):
    name: str = "storage"
    description: str = "Storage"


@dataclass(frozen=True)
class Database(BaseCategory):
    name: str = "database"
    description: str = "Database"


@dataclass(frozen=True)
class Security(BaseCategory):
    name: str = "security"
    description: str = "Security"


@dataclass(frozen=True)
class Networking(BaseCategory):
    name: str = "networking"
    description: str = "Networking"


@dataclass(frozen=True)
class AccessControl(BaseCategory):
    name: str = "access_control"
    description: str = "Access Control"


@dataclass(frozen=True)
class Management(BaseCategory):
    name: str = "management"
    description: str = "Management Tools"


@dataclass(frozen=True)
class Monitoring(BaseCategory):
    name: str = "monitoring"
    description: str = "Monitoring & Logging"


@dataclass(frozen=True)
class Analytics(BaseCategory):
    name: str = "analytics"
    description: str = "Analytics & BI"


@dataclass(frozen=True)
class Ai(BaseCategory):
    name: str = "ai"
    description: str = "AI & Machine Learning"


@dataclass(frozen=True)
class DevOps(BaseCategory):
    name: str = "devops"
    description: str = "DevOps and Development"


@dataclass(frozen=True)
class Dns(BaseCategory):
    name: str = "dns"
    description: str = "DNS"


@dataclass(frozen=True)
class ManagedKubernetes(BaseCategory):
    name: str = "managed_kubernetes"
    description: str = "Managed Kubernetes"


@dataclass(frozen=True)
class Misc(BaseCategory):
    name: str = "misc"
    description: str = "Miscellaneous"


class Category(Enum):
    ai = Ai()
    analytics = Analytics()
    compute = Compute()
    database = Database()
    devops = DevOps()
    dns = Dns()
    access_control = AccessControl()
    managed_kubernetes = ManagedKubernetes()
    management = Management()
    misc = Misc()
    monitoring = Monitoring()
    networking = Networking()
    security = Security()
    storage = Storage()
