from typing import ClassVar, Dict, List, Optional, Type, cast
from attrs import define, field
from resoto_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder
from resotolib.json_bender import S, Bender
from resotolib.types import Json

@define(eq=False, slots=False)
class AwsGlacierVault(AwsResource):
    kind: ClassVar[str] = "aws_glacier_vault"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("glacier", "list-vaults", "VaultList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("VaultName"),
        "name": S("VaultName"),
        "ctime": S("CreationDate"),
        "arn": S("VaultARN"),
        "glacier_last_inventory_date": S("LastInventoryDate"),
        "glacier_number_of_archives": S("NumberOfArchives"),
        "glacier_size_in_bytes": S("SizeInBytes")
    }
    glacier_last_inventory_date: Optional[str] = field(default=None)
    glacier_number_of_archives: Optional[int] = field(default=None)
    glacier_size_in_bytes: Optional[int] = field(default=None)

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(vault: AwsGlacierVault) -> None:
            tags = builder.client.list("glacier", "list-tags-for-vault", "Tags", vaultName=vault.name)
            if tags:
                vault.tags = cast(Dict[str, Optional[str]], tags)

        for js in json:
            vault = cls.from_api(js)
            builder.add_node(vault, js)
            builder.submit_work_shared_pool(add_tags, vault)

resources: List[AwsResource] = [AwsGlacierVault]
