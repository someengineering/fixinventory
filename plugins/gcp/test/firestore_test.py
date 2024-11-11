import json
import os

from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.firestore import GcpFirestoreDatabase, GcpFirestoreDocument, GcpFirestoreBackup


def test_gcp_firestore_database(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/firestore_database.json") as f:
        GcpFirestoreDatabase.collect(raw=json.load(f)["databases"], builder=random_builder)

    databases = random_builder.nodes(clazz=GcpFirestoreDatabase)
    assert len(databases) == 1


def test_gcp_firestore_document(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/firestore_document.json") as f:
        GcpFirestoreDocument.collect(raw=json.load(f)["documents"], builder=random_builder)

    documents = random_builder.nodes(clazz=GcpFirestoreDocument)
    assert len(documents) == 1


def test_gcp_firestore_backup(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/firestore_backup.json") as f:
        GcpFirestoreBackup.collect(raw=json.load(f)["backups"], builder=random_builder)

    backups = random_builder.nodes(clazz=GcpFirestoreBackup)
    assert len(backups) == 1
