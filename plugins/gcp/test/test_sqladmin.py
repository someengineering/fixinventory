from .random_client import connect_resource, roundtrip
from resoto_plugin_gcp.resources.base import GraphBuilder
from resoto_plugin_gcp.resources.sqladmin import *


def test_gcp_sql_flag(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSqlFlag, random_builder)


def test_gcp_sql_database_instance(random_builder: GraphBuilder) -> None:
    db = roundtrip(GcpSqlDatabaseInstance, random_builder)
    connect_resource(random_builder, db, GcpSslCertificate, selfLink=db.instance_server_ca_cert.self_link)
    assert len(random_builder.edges_of(GcpSslCertificate, GcpSqlDatabaseInstance)) == 1


def test_gcp_sql_operation(random_builder: GraphBuilder) -> None:
    op = roundtrip(GcpSqlOperation, random_builder)
    connect_resource(random_builder, op, GcpSqlDatabaseInstance, name=op.operation_target_id)
    assert len(random_builder.edges_of(GcpSqlDatabaseInstance, GcpSqlOperation)) == 1
