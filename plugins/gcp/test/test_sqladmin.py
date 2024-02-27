import json
import os

from .random_client import connect_resource, roundtrip
from fix_plugin_gcp.resources.sqladmin import *
from fix_plugin_gcp.resources.base import GraphBuilder
from fix_plugin_gcp.resources.compute import GcpSslCertificate


def test_gcp_sql_database_instance(random_builder: GraphBuilder) -> None:
    db = roundtrip(GcpSqlDatabaseInstance, random_builder)
    connect_resource(random_builder, db, GcpSslCertificate, selfLink=db.server_ca_cert.self_link)  # type: ignore
    assert len(random_builder.edges_of(GcpSslCertificate, GcpSqlDatabaseInstance)) == 1
    assert len(random_builder.resources_of(GcpSqlBackupRun)) > 0
    assert len(random_builder.edges_of(GcpSqlDatabaseInstance, GcpSqlBackupRun)) > 0
    assert len(random_builder.resources_of(GcpSqlDatabase)) > 0
    assert len(random_builder.resources_of(GcpSqlUser)) > 0
    assert len(random_builder.resources_of(GcpSqlOperation)) > 0


def test_instance_with_settings(random_builder: GraphBuilder) -> None:
    with open(os.path.dirname(__file__) + "/files/database_instance.json") as f:
        GcpSqlDatabaseInstance.collect(raw=json.load(f)["items"], builder=random_builder)

    db = random_builder.resources_of(GcpSqlDatabaseInstance)
    assert db
