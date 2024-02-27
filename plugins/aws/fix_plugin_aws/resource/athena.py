from typing import ClassVar, Dict, Optional, List, Any
from typing import Type

from attrs import define

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from fix_plugin_aws.resource.kms import AwsKmsKey
from fix_plugin_aws.resource.s3 import AwsS3Bucket
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, bend
from fixlib.types import Json

service_name = "athena"


@define(eq=False, slots=False)
class AwsAthenaEncryptionConfiguration:
    kind: ClassVar[str] = "aws_athena_encryption_configuration"
    kind_display: ClassVar[str] = "AWS Athena Encryption Configuration"
    kind_description: ClassVar[str] = (
        "Athena Encryption Configuration is a feature in AWS Athena that allows users"
        " to configure encryption settings for their query results."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"encryption_option": S("EncryptionOption"), "kms_key": S("KmsKey")}
    encryption_option: Optional[str] = None
    kms_key: Optional[str] = None


@define(eq=False, slots=False)
class AwsAthenaResultConfiguration:
    kind: ClassVar[str] = "aws_athena_result_configuration"
    kind_display: ClassVar[str] = "AWS Athena Result Configuration"
    kind_description: ClassVar[str] = (
        "AWS Athena Result Configuration allows users to specify where query results"
        " should be stored in Amazon S3 and how they should be encrypted."
    )
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
    kind_display: ClassVar[str] = "AWS Athena Engine Version"
    kind_description: ClassVar[str] = (
        "AWS Athena Engine Version refers to the underlying query engine version, based on Presto,"
        " that Amazon Athena uses to process SQL queries against datasets."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "selected_engine_version": S("SelectedEngineVersion"),
        "effective_engine_version": S("EffectiveEngineVersion"),
    }
    selected_engine_version: Optional[str] = None
    effective_engine_version: Optional[str] = None


@define(eq=False, slots=False)
class AwsAthenaWorkGroupConfiguration:
    kind: ClassVar[str] = "aws_athena_work_group_configuration"
    kind_display: ClassVar[str] = "AWS Athena Work Group Configuration"
    kind_description: ClassVar[str] = (
        "Athena work group configuration allows users to configure settings"
        " for managing and executing queries in Athena."
    )
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
    kind_display: ClassVar[str] = "AWS Athena Work Group"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/athena/home?region={region}#/workgroups/details/{name}", "arn_tpl": "arn:{partition}:athena:{region}:{account}:workgroup/{id}"}  # fmt: skip

    kind_description: ClassVar[str] = (
        "Amazon Athena Work Groups are a resource type for isolating query execution and history among different"
        " users, teams, or applications within the same AWS account, with features for access control, cost"
        " management, and integration with AWS CloudWatch for metrics monitoring."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-work-groups", "WorkGroups")
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
        "successors": {"default": ["aws_kms_key", "aws_s3_bucket"]},
    }

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-work-group"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-work-group"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_workgroup(name: str) -> Optional[AwsAthenaWorkGroup]:
            result = builder.client.get(
                aws_service=service_name, action="get-work-group", result_name="WorkGroup", WorkGroup=name
            )
            if result is None:
                return None

            if workgroup := AwsAthenaWorkGroup.from_api(result, builder):
                workgroup.set_arn(
                    builder=builder,
                    resource=f"workgroup/{workgroup.name}",
                )
                builder.add_node(workgroup, result)
                builder.submit_work(service_name, add_tags, workgroup)
                return workgroup
            else:
                return None

        def add_tags(data_catalog: AwsAthenaWorkGroup) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags-for-resource",
                "Tags",
                ResourceARN=data_catalog.arn,
            )
            if tags:
                data_catalog.tags = bend(ToDict(), tags)

        for js in json:
            if (name := js.get("Name")) is not None and isinstance(name, str):
                fetch_workgroup(name)

    # noinspection PyUnboundLocalVariable
    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if (
            (wc := self.workgroup_configuration)
            and (rc := wc.result_configuration)
            and (ec := rc.encryption_configuration)
        ):
            if ec.kms_key:
                builder.dependant_node(from_node=self, clazz=AwsKmsKey, id=AwsKmsKey.normalise_id(ec.kms_key))
            if rc.output_location:
                builder.add_edge(self, clazz=AwsS3Bucket, name=AwsS3Bucket.name_from_path(rc.output_location))

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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
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
    kind_display: ClassVar[str] = "AWS Athena Data Catalog"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/athena/home?region={region}#datacatalog/detail/{name}", "arn_tpl": "arn:{partition}:athena:{region}:{account}:catalog/{name}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Athena Data Catalog is a managed metadata repository in AWS that allows you"
        " to store and organize metadata about your data sources, such as databases,"
        " tables, and partitions."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-data-catalogs", "DataCatalogsSummary")
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
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "get-data-catalog"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-data-catalog"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def fetch_data_catalog(data_catalog_name: str) -> Optional[AwsAthenaDataCatalog]:
            result = builder.client.get(
                aws_service=service_name,
                action="get-data-catalog",
                result_name="DataCatalog",
                Name=data_catalog_name,
            )
            if result is None:
                return None
            if catalog := AwsAthenaDataCatalog.from_api(result, builder):
                catalog.set_arn(builder=builder, resource=f"datacatalog/{catalog.name}")
                builder.add_node(catalog, result)
                builder.submit_work(service_name, add_tags, catalog)
                return catalog
            return None

        def add_tags(data_catalog: AwsAthenaDataCatalog) -> None:
            tags = builder.client.list(
                service_name,
                "list-tags-for-resource",
                None,
                ResourceARN=data_catalog.arn,
            )
            if tags:
                data_catalog.tags = bend(S("Tags", default=[]) >> ToDict(), tags[0])

        for js in json:
            # we filter out the default data catalog as it is not possible to do much with it
            if (name := js.get("CatalogName")) is not None and isinstance(name, str) and name != "AwsDataCatalog":
                fetch_data_catalog(name)

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

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(aws_service=service_name, action="delete-data-catalog", result_name=None, Name=self.name)
        return True


resources: List[Type[AwsResource]] = [
    AwsAthenaWorkGroup,
    AwsAthenaDataCatalog,
]
