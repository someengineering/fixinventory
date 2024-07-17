from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.storage import AzureStorageAccount, AzureStorageAccountDeleted


def test_deleted_account(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureStorageAccountDeleted, builder)
    assert len(collected) == 2


def test_storage_account(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureStorageAccount, builder)
    assert len(collected) == 6
