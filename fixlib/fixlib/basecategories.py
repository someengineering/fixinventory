from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class BaseCategory:
    name: str = "category"

    def __str__(self) -> str:
        return self.name

    def __lt__(self, other):
        if isinstance(other, BaseCategory):
            return self.name < other.name
        return NotImplemented

    def __eq__(self, other):
        if isinstance(other, BaseCategory):
            return self.name == other.name
        return NotImplemented


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
class Iam(BaseCategory):
    name: str = "iam"
    description: str = "Identity & Access Management"


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


class Category(Enum):
    compute = Compute()
    storage = Storage()
    database = Database()
    security = Security()
    networking = Networking()
    iam = Iam()
    management = Management()
    monitoring = Monitoring()
    analytics = Analytics()
    ai = Ai()
    devops = DevOps()
    dns = Dns()
