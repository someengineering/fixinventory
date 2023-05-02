from attrs import frozen
from resotocore.infra_apps.manifest import AppManifest
from resotocore.ids import InfraAppName
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.db.entitydb import EntityDb, ArangoEntityDb


@frozen
class InfraAppPackage:
    manifest: AppManifest
    source_url: str


PackageEntityDb = EntityDb[InfraAppName, InfraAppPackage]


def app_package_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[InfraAppName, InfraAppPackage]:
    return ArangoEntityDb(db, collection, InfraAppPackage, lambda k: InfraAppName(k.manifest.name))
