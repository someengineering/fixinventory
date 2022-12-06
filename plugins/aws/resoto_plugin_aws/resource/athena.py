from typing import ClassVar, Dict, Optional, List
from typing import Type

from attrs import define

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from resoto_plugin_aws.resource.kms import AwsKmsKey
from resoto_plugin_aws.utils import ToDict
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, bend
from resotolib.types import Json


@define(eq=False, slots=False)
class AwsAthenaEncryptionConfiguration:
    kind: ClassVar[str] = "aws_athena_encryption_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {"encryption_option": S("EncryptionOption"), "kms_key": S("KmsKey")}
    encryption_option: Optional[str] = None
    kms_key: Optional[str] = None


@define(eq=False, slots=False)
class AwsAthenaResultConfiguration:
    kind: ClassVar[str] = "aws_athena_result_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "output_location": S("OutputLocation"),
        "encryption_configuration": S("EncryptionConfiguration") >> Bend(AwsAthenaEncryptionConfiguration.mapping),
        "expected_bucket_owner": S("ExpectedBucketOwner"),
    }
    output_location: Optional[str] = None
    encryption_configuration: Optional[AwsAthenaEncryptionConfiguration] = None
    expected_bucket_owner: Optional[str] = None


@define(eq=False, slots=False)
class AwsAthenaEngineVersion:
    kind: ClassVar[str] = "aws_athena_engine_version"
    mapping: ClassVar[Dict[str, Bender]] = {
        "selected_engine_version": S("SelectedEngineVersion"),
        "effective_engine_version": S("EffectiveEngineVersion"),
    }
    selected_engine_version: Optional[str] = None
    effective_engine_version: Optional[str] = None


@define(eq=False, slots=False)
class AwsAthenaWorkGroupConfiguration:
    kind: ClassVar[str] = "aws_athena_work_group_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "result_configuration": S("ResultConfiguration") >> Bend(AwsAthenaResultConfiguration.mapping),
        "enforce_work_group_configuration": S("EnforceWorkGroupConfiguration"),
        "publish_cloud_watch_metrics_enabled": S("PublishCloudWatchMetricsEnabled"),
        "bytes_scanned_cutoff_per_query": S("BytesScannedCutoffPerQuery"),
        "requester_pays_enabled": S("RequesterPaysEnabled"),
        "engine_version": S("EngineVersion") >> Bend(AwsAthenaEngineVersion.mapping),
    }
    result_configuration: Optional[AwsAthenaResultConfiguration] = None
    enforce_work_group_configuration: Optional[bool] = None
    publish_cloud_watch_metrics_enabled: Optional[bool] = None
    bytes_scanned_cutoff_per_query: Optional[int] = None
    requester_pays_enabled: Optional[bool] = None
    engine_version: Optional[AwsAthenaEngineVersion] = None


@define(eq=False, slots=False)
class AwsAthenaWorkGroup(AwsResource):
    kind: ClassVar[str] = "aws_athena_work_group"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("athena", "list-work-groups", "WorkGroups")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "ctime": S("CreationTime"),
        "name": S("Name"),
        "workgroup_state": S("State"),
        "workgroup_configuration": S("Configuration") >> Bend(AwsAthenaWorkGroupConfiguration.mapping),
        "description": S("Description"),
    }
    workgroup_state: Optional[str] = None
    workgroup_configuration: Optional[AwsAthenaWorkGroupConfiguration] = None
    description: Optional[str] = None

    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"delete": ["aws_kms_key"]},
        "successors": {"default": ["aws_kms_key"]},
    }

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec("athena", "get-work-group"), AwsApiSpec("athena", "list-tags-for-resource")]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("athena", "tag-resource"),
            AwsApiSpec("athena", "untag-resource"),
            AwsApiSpec("athena", "delete-work-group"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_workgroup(name: str) -> Optional[AwsAthenaWorkGroup]:
            result = builder.client.get(
                aws_service="athena", action="get-work-group", result_name="WorkGroup", WorkGroup=name
            )
            if result is None:
                return None

            workgroup = AwsAthenaWorkGroup.from_api(result)
            workgroup.set_arn(
                builder=builder,
                resource=f"workgroup/{workgroup.name}",
            )

            return workgroup

        def add_tags(data_catalog: AwsAthenaWorkGroup) -> None:
            tags = builder.client.list(
                "athena",
                "list-tags-for-resource",
                "Tags",
                ResourceARN=data_catalog.arn,
            )
            if tags:
                data_catalog.tags = bend(ToDict(), tags)

        for js in json:
            if (name := js.get("Name")) is not None and isinstance(name, str):
                wg = fetch_workgroup(name)
                if wg is not None:
                    builder.add_node(wg)
                    builder.submit_work(add_tags, wg)

    # noinspection PyUnboundLocalVariable
    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (wc := self.workgroup_configuration)
            and (rc := wc.result_configuration)
            and (ec := rc.encryption_configuration)
        ):
            if ec.kms_key:
                builder.dependant_node(from_node=self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(ec.kms_key))

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="tag-resource",
            result_name=None,
            ResourceARN=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="untag-resource",
            result_name=None,
            ResourceARN=self.arn,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="delete-work-group",
            result_name=None,
            WorkGroup=self.name,
            RecursiveDeleteOption=True,
        )
        return True


@define(eq=False, slots=False)
class AwsAthenaDataCatalog(AwsResource):
    kind: ClassVar[str] = "aws_athena_data_catalog"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("athena", "list-data-catalogs", "DataCatalogsSummary")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "name": S("Name"),
        "description": S("Description"),
        "datacatalog_type": S("Type"),
        "datacatalog_parameters": S("Parameters"),
    }
    description: Optional[str] = None
    datacatalog_type: Optional[str] = None
    datacatalog_parameters: Optional[Dict[str, str]] = None

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [cls.api_spec, AwsApiSpec("athena", "get-data-catalog"), AwsApiSpec("athena", "list-tags-for-resource")]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("athena", "tag-resource"),
            AwsApiSpec("athena", "untag-resource"),
            AwsApiSpec("athena", "delete-data-catalog"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_data_catalog(data_catalog_name: str) -> Optional[AwsAthenaDataCatalog]:
            result = builder.client.get(
                aws_service="athena",
                action="get-data-catalog",
                result_name="DataCatalog",
                Name=data_catalog_name,
            )
            if result is None:
                return None
            catalog = AwsAthenaDataCatalog.from_api(result)
            catalog.set_arn(builder=builder, resource=f"datacatalog/{catalog.name}")
            return catalog

        def add_tags(data_catalog: AwsAthenaDataCatalog) -> None:
            tags = builder.client.list(
                "athena",
                "list-tags-for-resource",
                None,
                ResourceARN=data_catalog.arn,
            )
            if tags:
                data_catalog.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])

        for js in json:
            # we filter out the default data catalog as it is not possible to do much with it
            if (name := js.get("CatalogName")) is not None and isinstance(name, str) and name != "AwsDataCatalog":
                catalog = fetch_data_catalog(name)
                if catalog is not None:
                    builder.add_node(catalog)
                    builder.submit_work(add_tags, catalog)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="tag-resource",
            result_name=None,
            ResourceARN=self.arn,
            Tags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=self.api_spec.service,
            action="untag-resource",
            result_name=None,
            ResourceARN=self.arn,
            TagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="athena", action="delete-data-catalog", result_name=None, Name=self.name)
        return True


resources: List[Type[AwsResource]] = [
    AwsAthenaWorkGroup,
    AwsAthenaDataCatalog,
]
