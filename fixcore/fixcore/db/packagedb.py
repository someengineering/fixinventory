from attrs import frozen
from fixcore.infra_apps.manifest import AppManifest
from fixcore.ids import InfraAppName
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.entitydb import EntityDb, ArangoEntityDb


@frozen
class InfraAppPackage:
    manifest: AppManifest
    source_url: str


PackageEntityDb = EntityDb[InfraAppName, InfraAppPackage]


def app_package_entity_db(db: AsyncArangoDB, collection: str) -> ArangoEntityDb[InfraAppName, InfraAppPackage]:
    return ArangoEntityDb(db, collection, InfraAppPackage, lambda k: InfraAppName(k.manifest.name))
