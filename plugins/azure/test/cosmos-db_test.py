from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.cosmosdb import (
    AzureCosmosDBCassandraCluster,
    AzureCosmosDBAccount,
    AzureCosmosDBRestorableAccount,
    AzureCosmosDBLocation,
    AzureCosmosDBMongoDBCluster,
    AzureCosmosDBPostgresqlCluster,
)


def test_cassandra_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBCassandraCluster, builder)
    assert len(collected) == 1


def test_cosmos_db_account(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBAccount, builder)
    assert len(collected) == 1


def test_restorable_cosmos_db_account(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBRestorableAccount, builder)
    assert len(collected) == 2


def test_cosmos_db_location(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBLocation, builder)
    assert len(collected) == 2


def test_mongo_db_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBMongoDBCluster, builder)
    assert len(collected) == 1


def test_postgres_cluster(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCosmosDBPostgresqlCluster, builder)
    assert len(collected) == 1
