from datetime import datetime
from attrs import define
from typing import Optional, ClassVar, Dict
from resotolib.graph import Graph
from resotolib.baseresources import (
    BaseAccount,
    BaseResource,
)


@define(eq=False, slots=False)
class ScarfResource:
    kind: ClassVar[str] = "scarf_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class ScarfOrganization(ScarfResource, BaseAccount):
    kind: ClassVar[str] = "scarf_organization"
    description: Optional[str] = None
    billing_email: Optional[str] = None
    website: Optional[str] = None

    @staticmethod
    def new(data: Dict) -> BaseResource:
        return ScarfOrganization(
            id=data.get("name"),
            description=data.get("description"),
            website=data.get("website"),
            billing_email=data.get("billingEmail"),
            ctime=convert_date(data.get("createdAt")),
            mtime=convert_date(data.get("updatedAt")),
        )


@define(eq=False, slots=False)
class ScarfPackage(ScarfResource, BaseResource):
    kind: ClassVar[str] = "scarf_package"

    short_description: Optional[str] = None
    long_description: Optional[str] = None
    website: Optional[str] = None
    library_type: Optional[str] = None
    owner: Optional[str] = None
    pull_count: int = 0

    @staticmethod
    def new(data: Dict) -> BaseResource:
        owner = data.get("owner", "")
        name = data.get("name", "")
        owner_prefix = f"{owner}/" if owner else ""
        if name.startswith(owner_prefix):
            name = name[len(owner_prefix) :]
        return ScarfPackage(
            id=data.get("uuid"),
            name=name,
            short_description=data.get("shortDescription"),
            long_description=data.get("longDescription"),
            website=data.get("website"),
            library_type=data.get("libraryType"),
            owner=owner,
            ctime=convert_date(data.get("createdAt")),
        )


def convert_date(date_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
