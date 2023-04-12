from attrs import frozen
from typing import Union
from resotocore.infra_apps.manifest import AppManifest
from resotocore.ids import InfraAppName
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb


@frozen
class FromHttp:
    http_url: str


@frozen
class FromGit:
    git_url: str


InstallationSource = Union[FromHttp, FromGit]


@frozen
class InfraAppPackage:
    manifest: AppManifest
    source: InstallationSource


PackageEntityDb = EntityDb[InfraAppName, InfraAppPackage]


def app_package_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[InfraAppName, InfraAppPackage]:
    return ArangoEntityDb(db, collection, InfraAppPackage, lambda k: InfraAppName(k.manifest.name))
