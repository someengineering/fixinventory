from .random_client import roundtrip
from resoto_plugin_gcp.resources.base import GraphBuilder
from resoto_plugin_gcp.resources.sqladmin import *


def test_gcp_sql_flag(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSqlFlag, random_builder)


def test_gcp_sql_database_instance(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSqlDatabaseInstance, random_builder)


def test_gcp_sql_operation(random_builder: GraphBuilder) -> None:
    roundtrip(GcpSqlOperation, random_builder)
