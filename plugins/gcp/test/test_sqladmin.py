from .random_client import connect_resource, roundtrip
from resoto_plugin_gcp.resources.sqladmin import *
from resoto_plugin_gcp.resources.base import GraphBuilder
from resoto_plugin_gcp.resources.compute import GcpSslCertificate


def test_gcp_sql_flag(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSqlFlag, random_builder)


def test_gcp_sql_database_instance(random_builder: GraphBuilder) -> None:
    db = roundtrip(GcpSqlDatabaseInstance, random_builder)
    connect_resource(random_builder, db, GcpSslCertificate, selfLink=db.server_ca_cert.self_link)  # type: ignore
    assert len(random_builder.edges_of(GcpSslCertificate, GcpSqlDatabaseInstance)) == 1
    assert len(random_builder.resources_of(GcpSqlBackupRun)) > 0
    assert len(random_builder.edges_of(GcpSqlDatabaseInstance, GcpSqlBackupRun)) > 0
    assert len(random_builder.resources_of(GcpSqlDatabase)) > 0
    assert len(random_builder.resources_of(GcpSqlUser)) > 0
    assert len(random_builder.resources_of(GcpSqlOperation)) > 0
