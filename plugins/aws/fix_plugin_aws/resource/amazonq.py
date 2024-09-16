from datetime import datetime
from typing import ClassVar, Dict, Optional, Type, List, Any

from attrs import define, field

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.utils import TagsValue, ToDict
from fixlib.baseresources import ModelReference
from fixlib.graph import Graph
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json

service_name = "qbusiness"


class AmazonQTaggable:
    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="tag-resource",
                result_name=None,
                resourceARN=self.arn,
                tags=[{"key": key, "value": value}],
            )
            return True
        return False

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        if isinstance(self, AwsResource):
            client.call(
                aws_service=service_name,
                action="untag-resource",
                result_name=None,
                resourceARN=self.arn,
                tagKeys=[key],
            )
            return True
        return False

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsQBusinessApplication(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_application"
    kind_display: ClassVar[str] = "AWS QBusiness Application"
    kind_description: ClassVar[str] = (
        "Represents a QBusiness application within the AWS QBusiness service. Applications"
        " define a set of tasks and configuration for processing data within the QBusiness ecosystem."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "application", "group": "generative_ai"}
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "provider_link_tpl": "https://{region_id}.console.aws.amazon.com/amazonq/business/applications/{id}/details?region={region}",  # fmt: skip
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{id}",
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [
                "aws_q_business_conversation",
                "aws_q_business_data_source",
                "aws_q_business_data_source_sync_job",
                "aws_q_business_document",
                "aws_q_business_indice",
                "aws_q_business_message",
                "aws_q_business_plugin",
                "aws_q_business_retriever",
                "aws_q_business_web_experience",
                "aws_q_apps_library_item",
                "aws_q_apps",
            ]
        },
    }
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("qbusiness", "list-applications", "applications")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("applicationId"),
        "name": S("displayName"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "display_name": S("displayName"),
        "application_id": S("applicationId"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "status": S("status"),
    }
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon Q Business application."})  # fmt: skip
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier for the Amazon Q Business application."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business application was created."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business application was last updated."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the Amazon Q Business application. The application is ready to use when the status is ACTIVE."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-application"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-application",
            result_name=None,
            applicationId=self.id,
        )
        return True

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(tag_resource: AwsResource) -> None:
            # Filter resources that have tags
            if not isinstance(
                tag_resource,
                (
                    AwsQBusinessApplication,
                    AwsQBusinessDataSource,
                    AwsQBusinessIndice,
                    AwsQBusinessPlugin,
                    AwsQBusinessRetriever,
                    AwsQBusinessWebExperience,
                    AwsQApps,
                ),
            ):
                return
            if isinstance(tag_resource, AwsQApps):
                tags = builder.client.list(
                    "qapps",
                    "list-tags-for-resource",
                    "tags",
                    expected_errors=["ResourceNotFoundException"],
                    resourceARN=tag_resource.arn,
                )
                if tags:
                    tag_resource.tags.update(tags[0])
            else:
                tags = builder.client.list(
                    service_name,
                    "list-tags-for-resource",
                    "tags",
                    expected_errors=["ResourceNotFoundException"],
                    resourceARN=tag_resource.arn,
                )
                if tags:
                    for tag in tags:
                        tag_resource.tags.update({tag.get("key"): tag.get("value")})

        def collect_application_resources(
            application: AwsQBusinessApplication,
            resource_class: AwsResource,
            action: str,
            result_name: str,
            param_name: str = "applicationId",
            service: Optional[str] = None,
        ) -> None:
            param_map = {param_name: application.id}
            q_resources = builder.client.list(
                service or service_name,
                action,
                result_name,
                expected_errors=[],
                **param_map,
            )
            for q_resource in q_resources:
                if resource := resource_class.from_api(q_resource, builder):
                    if isinstance(resource, (AwsQBusinessPlugin, AwsQBusinessWebExperience, AwsQBusinessIndice)):
                        resource.application_id = application.id
                    if isinstance(resource, (AwsQApps, AwsQAppsLibraryItem)):
                        resource.instance_id = application.id
                    builder.add_node(resource, q_resource)
                    builder.add_edge(application, node=resource)
                    builder.submit_work(service_name, add_tags, resource)
                    if isinstance(resource, AwsQBusinessConversation):
                        m_resources = builder.client.list(
                            service_name,
                            "list-messages",
                            "messages",
                            applicationId=application.id,
                            conversationId=resource.id,
                        )
                        for message in m_resources:
                            if message_resource := AwsQBusinessMessage.from_api(message, builder):
                                builder.add_node(message_resource, message)
                                builder.add_edge(resource, node=message_resource)

        def collect_indice_resources(application: AwsQBusinessApplication) -> None:
            def collect_index_resources(
                indice: "AwsQBusinessIndice", resource_class: AwsResource, action: str, result_name: str
            ) -> None:
                i_resources = builder.client.list(
                    service_name,
                    action,
                    result_name,
                    applicationId=application.id,
                    indexId=indice.id,
                )
                for i_resource in i_resources:
                    if resource := resource_class.from_api(i_resource, builder):
                        if isinstance(resource, AwsQBusinessDataSource):
                            resource.application_id = application.id
                            resource.indice_id = indice.id
                        builder.add_node(resource, i_resource)
                        builder.add_edge(indice, node=resource)
                        builder.submit_work(service_name, add_tags, resource)
                        if isinstance(resource, AwsQBusinessDataSource):
                            data_source_job_resources = builder.client.list(
                                service_name,
                                "list-data-source-sync-jobs",
                                "history",
                                applicationId=application.id,
                                indexId=indice.id,
                                dataSourceId=resource.id,
                            )
                            for data_source_job in data_source_job_resources:
                                if sync_job := AwsQBusinessDataSourceSyncJob.from_api(data_source_job, builder):
                                    builder.add_node(sync_job, data_source_job)
                                    builder.add_edge(resource, node=sync_job)

            index_resources = builder.client.list(
                service_name,
                "list-indices",
                "indices",
                applicationId=application.id,
            )
            for index_resource in index_resources:
                if indice_instance := AwsQBusinessIndice.from_api(index_resource, builder):
                    indice_instance.application_id = application.id
                    builder.add_node(indice_instance, index_resource)
                    builder.add_edge(application, node=indice_instance)
                    builder.submit_work(service_name, add_tags, indice_instance)
                    builder.submit_work(
                        service_name,
                        collect_index_resources,
                        indice_instance,
                        AwsQBusinessDataSource,
                        "list-data-sources",
                        "dataSources",
                    )
                    builder.submit_work(
                        service_name,
                        collect_index_resources,
                        indice_instance,
                        AwsQBusinessDocument,
                        "list-documents",
                        "documentDetailList",
                    )

        for js in json:
            if instance := cls.from_api(js, builder):
                builder.add_node(instance, js)
                builder.submit_work(service_name, add_tags, instance)
                builder.submit_work(
                    service_name,
                    collect_application_resources,
                    instance,
                    AwsQBusinessConversation,
                    "list-conversations",
                    "conversations",
                )
                builder.submit_work(service_name, collect_indice_resources, instance)
                builder.submit_work(
                    service_name, collect_application_resources, instance, AwsQBusinessPlugin, "list-plugins", "plugins"
                )
                builder.submit_work(
                    service_name,
                    collect_application_resources,
                    instance,
                    AwsQBusinessRetriever,
                    "list-retrievers",
                    "retrievers",
                )
                builder.submit_work(
                    service_name,
                    collect_application_resources,
                    instance,
                    AwsQBusinessWebExperience,
                    "list-web-experiences",
                    "webExperiences",
                )
                builder.submit_work(
                    service_name,
                    collect_application_resources,
                    instance,
                    AwsQAppsLibraryItem,
                    "list-library-items",
                    "libraryItems",
                    "instanceId",
                    "qapps",
                )
                builder.submit_work(
                    service_name,
                    collect_application_resources,
                    instance,
                    AwsQApps,
                    "list-q-apps",
                    "apps",
                    "instanceId",
                    "qapps",
                )


@define(eq=False, slots=False)
class AwsQBusinessConversation(AwsResource):
    kind: ClassVar[str] = "aws_q_business_conversation"
    kind_display: ClassVar[str] = "AWS QBusiness Conversation"
    kind_description: ClassVar[str] = (
        "Represents a conversation within the AWS QBusiness service. Conversations are"
        " interactions that involve a series of messages or data exchanges."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("conversationId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "conversation_id": S("conversationId"),
        "title": S("title"),
        "start_time": S("startTime"),
    }
    conversation_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business conversation."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the conversation."})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={"description": "The start time of the conversation."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-conversations", "conversations"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsQBusinessDataSource(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_data_source"
    kind_display: ClassVar[str] = "AWS QBusiness Data Source"
    kind_description: ClassVar[str] = (
        "Represents a data source in the AWS QBusiness service. Data sources are the origins"
        " from which data is ingested for processing or analysis within the QBusiness framework."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "bucket", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "provider_link_tpl": "https://{region_id}.console.aws.amazon.com/amazonq/business/applications/{application_id}/indices/{indice_id}/datasources/{id}/details?region={region}",  # fmt: skip
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{application_id}/index/{indice_id}/data-source/{id}",
        "extra_args_for_arn": ["application_id", "indice_id"],
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("dataSourceId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("displayName"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "display_name": S("displayName"),
        "data_source_id": S("dataSourceId"),
        "type": S("type"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "status": S("status"),
    }
    indice_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business indice."})  # fmt: skip
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business application."})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of the Amazon Q Business data source."})  # fmt: skip
    data_source_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business data source."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the Amazon Q Business data source."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business data source was created."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business data source was last updated."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the Amazon Q Business data source."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-data-sources", "dataSources"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-data-source"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-data-source",
            result_name=None,
            applicationId=self.application_id,
            indexId=self.indice_id,
            dataSourceId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsQBusinessErrorDetail:
    kind: ClassVar[str] = "aws_q_business_error_detail"
    mapping: ClassVar[Dict[str, Bender]] = {"error_message": S("errorMessage"), "error_code": S("errorCode")}
    error_message: Optional[str] = field(default=None, metadata={"description": "The message explaining the data source sync error."})  # fmt: skip
    error_code: Optional[str] = field(default=None, metadata={"description": "The code associated with the data source sync error."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessDataSourceSyncJobMetrics:
    kind: ClassVar[str] = "aws_q_business_data_source_sync_job_metrics"
    mapping: ClassVar[Dict[str, Bender]] = {
        "documents_added": S("documentsAdded"),
        "documents_modified": S("documentsModified"),
        "documents_deleted": S("documentsDeleted"),
        "documents_failed": S("documentsFailed"),
        "documents_scanned": S("documentsScanned"),
    }
    documents_added: Optional[str] = field(default=None, metadata={"description": "The current count of documents added from the data source during the data source sync."})  # fmt: skip
    documents_modified: Optional[str] = field(default=None, metadata={"description": "The current count of documents modified in the data source during the data source sync."})  # fmt: skip
    documents_deleted: Optional[str] = field(default=None, metadata={"description": "The current count of documents deleted from the data source during the data source sync."})  # fmt: skip
    documents_failed: Optional[str] = field(default=None, metadata={"description": "The current count of documents that failed to sync from the data source during the data source sync."})  # fmt: skip
    documents_scanned: Optional[str] = field(default=None, metadata={"description": "The current count of documents crawled by the ongoing sync job in the data source."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessDataSourceSyncJob(AwsResource):
    kind: ClassVar[str] = "aws_q_business_data_source_sync_job"
    kind_display: ClassVar[str] = "AWS QBusiness Data Source Sync Job"
    kind_description: ClassVar[str] = (
        "Represents a data source synchronization job in the AWS QBusiness service. Sync jobs"
        " ensure that data from data sources is up-to-date and correctly integrated into the system."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "job", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("executionId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "execution_id": S("executionId"),
        "start_time": S("startTime"),
        "end_time": S("endTime"),
        "status": S("status"),
        "sync_job_error": S("error") >> Bend(AwsQBusinessErrorDetail.mapping),
        "data_source_error_code": S("dataSourceErrorCode"),
        "sync_job_metrics": S("metrics") >> Bend(AwsQBusinessDataSourceSyncJobMetrics.mapping),
    }
    execution_id: Optional[str] = field(default=None, metadata={"description": "The identifier of a data source synchronization job."})  # fmt: skip
    start_time: Optional[datetime] = field(default=None, metadata={"description": "The Unix time stamp when the data source synchronization job started."})  # fmt: skip
    end_time: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the synchronization job completed."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the synchronization job. When the Status field is set to SUCCEEDED, the synchronization job is done. If the status code is FAILED, the ErrorCode and ErrorMessage fields give you the reason for the failure."})  # fmt: skip
    sync_job_error: Optional[AwsQBusinessErrorDetail] = field(default=None, metadata={"description": "If the Status field is set to FAILED, the ErrorCode field indicates the reason the synchronization failed."})  # fmt: skip
    data_source_error_code: Optional[str] = field(default=None, metadata={"description": "If the reason that the synchronization failed is due to an error with the underlying data source, this field contains a code that identifies the error."})  # fmt: skip
    sync_job_metrics: Optional[AwsQBusinessDataSourceSyncJobMetrics] = field(default=None, metadata={"description": "Maps a batch delete document request to a specific data source sync job. This is optional and should only be supplied when documents are deleted by a data source connector."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-data-source-sync-jobs", "history"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsQBusinessDocument(AwsResource):
    kind: ClassVar[str] = "aws_q_business_document"
    kind_display: ClassVar[str] = "AWS QBusiness Document"
    kind_description: ClassVar[str] = (
        "Represents a document within the AWS QBusiness service. Documents are structured pieces"
        " of information that can be used for various purposes within the QBusiness ecosystem."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("documentId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "document_id": S("documentId"),
        "status": S("status"),
        "document_error": S("error") >> Bend(AwsQBusinessErrorDetail.mapping),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
    }
    document_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the document."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The current status of the document."})  # fmt: skip
    document_error: Optional[AwsQBusinessErrorDetail] = field(default=None, metadata={"description": "An error message associated with the document."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp for when the document was created."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp for when the document was last updated."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-documents", "documentDetailList"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsQBusinessIndice(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_indice"
    kind_display: ClassVar[str] = "AWS QBusiness Indice"
    kind_description: ClassVar[str] = (
        "Represents an index in the AWS QBusiness service. Indices are used to organize and"
        " facilitate efficient searching and retrieval of data within the QBusiness framework."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "generative_ai"}
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{application_id}/index/{id}",
        "extra_args_for_arn": ["application_id"],
    }
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("indexId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("displayName"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "display_name": S("displayName"),
        "index_id": S("indexId"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "status": S("status"),
    }
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business application."})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of the index."})  # fmt: skip
    index_id: Optional[str] = field(default=None, metadata={"description": "The identifier for the index."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the index was created."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the index was last updated."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The current status of the index. When the status is ACTIVE, the index is ready."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-indices", "indices"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-index"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-index",
            result_name=None,
            applicationId=self.application_id,
            indexId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsQBusinessAttachmentOutput:
    kind: ClassVar[str] = "aws_q_business_attachment_output"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("name"),
        "status": S("status"),
        "error": S("error") >> Bend(AwsQBusinessErrorDetail.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of a file uploaded during chat."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of a file uploaded during chat."})  # fmt: skip
    error: Optional[AwsQBusinessErrorDetail] = field(default=None, metadata={"description": "An error associated with a file uploaded during chat."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessTextSegment:
    kind: ClassVar[str] = "aws_q_business_text_segment"
    mapping: ClassVar[Dict[str, Bender]] = {
        "begin_offset": S("beginOffset"),
        "end_offset": S("endOffset"),
        "snippet_excerpt": S("snippetExcerpt", "text"),
    }
    begin_offset: Optional[int] = field(default=None, metadata={"description": "The zero-based location in the response string where the source attribution starts."})  # fmt: skip
    end_offset: Optional[int] = field(default=None, metadata={"description": "The zero-based location in the response string where the source attribution ends."})  # fmt: skip
    snippet_excerpt: Optional[str] = field(default=None, metadata={"description": "The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q Business chat response."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessSourceAttribution:
    kind: ClassVar[str] = "aws_q_business_source_attribution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "title": S("title"),
        "snippet": S("snippet"),
        "url": S("url"),
        "citation_number": S("citationNumber"),
        "updated_at": S("updatedAt"),
        "text_message_segments": S("textMessageSegments", default=[]) >> ForallBend(AwsQBusinessTextSegment.mapping),
    }
    title: Optional[str] = field(default=None, metadata={"description": "The title of the document which is the source for the Amazon Q Business generated response."})  # fmt: skip
    snippet: Optional[str] = field(default=None, metadata={"description": "The content extract from the document on which the generated response is based."})  # fmt: skip
    url: Optional[str] = field(default=None, metadata={"description": "The URL of the document which is the source for the Amazon Q Business generated response."})  # fmt: skip
    citation_number: Optional[int] = field(default=None, metadata={"description": "The number attached to a citation in an Amazon Q Business generated response."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business application was last updated."})  # fmt: skip
    text_message_segments: Optional[List[AwsQBusinessTextSegment]] = field(factory=list, metadata={"description": "A text extract from a source document that is used for source attribution."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessActionPayloadFieldValue:
    kind: ClassVar[str] = "aws_q_business_action_payload_field_value"
    mapping: ClassVar[Dict[str, Bender]] = {}


@define(eq=False, slots=False)
class AwsQBusinessActionReviewPayloadFieldAllowedValue:
    kind: ClassVar[str] = "aws_q_business_action_review_payload_field_allowed_value"
    mapping: ClassVar[Dict[str, Bender]] = {
        "value": S("value") >> Bend(AwsQBusinessActionPayloadFieldValue.mapping),
        "display_value": S("displayValue") >> Bend(AwsQBusinessActionPayloadFieldValue.mapping),
    }
    value: Optional[AwsQBusinessActionPayloadFieldValue] = field(default=None, metadata={"description": "The field value."})  # fmt: skip
    display_value: Optional[AwsQBusinessActionPayloadFieldValue] = field(default=None, metadata={"description": "The name of the field."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessActionReviewPayloadField:
    kind: ClassVar[str] = "aws_q_business_action_review_payload_field"
    mapping: ClassVar[Dict[str, Bender]] = {
        "display_name": S("displayName"),
        "display_order": S("displayOrder"),
        "display_description": S("displayDescription"),
        "type": S("type"),
        "value": S("value") >> Bend(AwsQBusinessActionPayloadFieldValue.mapping),
        "allowed_values": S("allowedValues", default=[])
        >> ForallBend(AwsQBusinessActionReviewPayloadFieldAllowedValue.mapping),
        "allowed_format": S("allowedFormat"),
        "required": S("required"),
    }
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of the field."})  # fmt: skip
    display_order: Optional[int] = field(default=None, metadata={"description": "The display order of fields in a payload."})  # fmt: skip
    display_description: Optional[str] = field(default=None, metadata={"description": "The field level description of each action review input field. This could be an explanation of the field. In the Amazon Q Business web experience, these descriptions could be used to display as tool tips to help users understand the field."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of field."})  # fmt: skip
    value: Optional[AwsQBusinessActionPayloadFieldValue] = field(default=None, metadata={"description": "The field value."})  # fmt: skip
    allowed_values: Optional[List[AwsQBusinessActionReviewPayloadFieldAllowedValue]] = field(factory=list, metadata={"description": "Information about the field values that an end user can use to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action."})  # fmt: skip
    allowed_format: Optional[str] = field(default=None, metadata={"description": "The expected data format for the action review input field value. For example, in PTO request, from and to would be of datetime allowed format."})  # fmt: skip
    required: Optional[bool] = field(default=None, metadata={"description": "Information about whether the field is required."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessActionReview:
    kind: ClassVar[str] = "aws_q_business_action_review"
    mapping: ClassVar[Dict[str, Bender]] = {
        "plugin_id": S("pluginId"),
        "plugin_type": S("pluginType"),
        "payload": S("payload"),
        "payload_field_name_separator": S("payloadFieldNameSeparator"),
    }
    plugin_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the plugin associated with the action review."})  # fmt: skip
    plugin_type: Optional[str] = field(default=None, metadata={"description": "The type of plugin."})  # fmt: skip
    payload: Optional[Dict[str, AwsQBusinessActionReviewPayloadField]] = field(default=None, metadata={"description": "Field values that an end user needs to provide to Amazon Q Business for Amazon Q Business to perform the requested plugin action."})  # fmt: skip
    payload_field_name_separator: Optional[str] = field(default=None, metadata={"description": "A string used to retain information about the hierarchical contexts within an action review payload."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessActionExecutionPayloadField:
    kind: ClassVar[str] = "aws_q_business_action_execution_payload_field"
    mapping: ClassVar[Dict[str, Bender]] = {"value": S("value") >> Bend(AwsQBusinessActionPayloadFieldValue.mapping)}
    value: Optional[AwsQBusinessActionPayloadFieldValue] = field(default=None, metadata={"description": "The content of a user input field in an plugin action execution payload."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessActionExecution:
    kind: ClassVar[str] = "aws_q_business_action_execution"
    mapping: ClassVar[Dict[str, Bender]] = {
        "plugin_id": S("pluginId"),
        "payload": S("payload"),
        "payload_field_name_separator": S("payloadFieldNameSeparator"),
    }
    plugin_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the plugin the action is attached to."})  # fmt: skip
    payload: Optional[Dict[str, AwsQBusinessActionExecutionPayloadField]] = field(default=None, metadata={"description": "A mapping of field names to the field values in input that an end user provides to Amazon Q Business requests to perform their plugin action."})  # fmt: skip
    payload_field_name_separator: Optional[str] = field(default=None, metadata={"description": "A string used to retain information about the hierarchical contexts within an action execution event payload."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQBusinessMessage(AwsResource):
    kind: ClassVar[str] = "aws_q_business_message"
    kind_display: ClassVar[str] = "AWS QBusiness Message"
    kind_description: ClassVar[str] = (
        "Represents a message within the AWS QBusiness service. Messages are used for communication"
        " or data exchange between various components or users within the QBusiness ecosystem."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "config", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("messageId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "message_id": S("messageId"),
        "body": S("body"),
        "time": S("time"),
        "type": S("type"),
        "message_attachments": S("attachments", default=[]) >> ForallBend(AwsQBusinessAttachmentOutput.mapping),
        "source_attribution": S("sourceAttribution", default=[]) >> ForallBend(AwsQBusinessSourceAttribution.mapping),
        "action_review": S("actionReview") >> Bend(AwsQBusinessActionReview.mapping),
        "action_execution": S("actionExecution") >> Bend(AwsQBusinessActionExecution.mapping),
    }
    message_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business web experience message."})  # fmt: skip
    body: Optional[str] = field(default=None, metadata={"description": "The content of the Amazon Q Business web experience message."})  # fmt: skip
    time: Optional[datetime] = field(default=None, metadata={"description": "The timestamp of the first Amazon Q Business web experience message."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of Amazon Q Business message, whether HUMAN or AI generated."})  # fmt: skip
    message_attachments: Optional[List[AwsQBusinessAttachmentOutput]] = field(factory=list, metadata={"description": "A file directly uploaded into an Amazon Q Business web experience chat."})  # fmt: skip
    source_attribution: Optional[List[AwsQBusinessSourceAttribution]] = field(factory=list, metadata={"description": "The source documents used to generate Amazon Q Business web experience message."})  # fmt: skip
    action_review: Optional[AwsQBusinessActionReview] = field(default=None, metadata={"description": "An output event that Amazon Q Business returns to an user who wants to perform a plugin action during a non-streaming chat conversation. It contains information about the selected action with a list of possible user input fields, some pre-populated by Amazon Q Business."})  # fmt: skip
    action_execution: Optional[AwsQBusinessActionExecution] = field(default=None, metadata={"description": "Performs an Amazon Q Business plugin action during a non-streaming chat conversation."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-messages", "messages"),
        ]

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsQBusinessPlugin(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_plugin"
    kind_display: ClassVar[str] = "AWS QBusiness Plugin"
    kind_description: ClassVar[str] = (
        "Represents a plugin in the AWS QBusiness service. Plugins extend the functionality of"
        " the QBusiness framework by adding new features or capabilities."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "generative_ai"}
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{application_id}/plugin/{id}",
        "extra_args_for_arn": ["application_id"],
    }
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("pluginId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("displayName"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "plugin_id": S("pluginId"),
        "display_name": S("displayName"),
        "type": S("type"),
        "server_url": S("serverUrl"),
        "state": S("state"),
        "build_status": S("buildStatus"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
    }
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business application."})  # fmt: skip
    plugin_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the plugin."})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of the plugin."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of the plugin."})  # fmt: skip
    server_url: Optional[str] = field(default=None, metadata={"description": "The plugin server URL used for configuration."})  # fmt: skip
    state: Optional[str] = field(default=None, metadata={"description": "The current status of the plugin."})  # fmt: skip
    build_status: Optional[str] = field(default=None, metadata={"description": "The status of the plugin."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp for when the plugin was created."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The timestamp for when the plugin was last updated."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-plugins", "plugins"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-plugin"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-plugin",
            result_name=None,
            applicationId=self.application_id,
            pluginId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsQBusinessRetriever(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_retriever"
    kind_display: ClassVar[str] = "AWS Q Business Retriever"
    kind_description: ClassVar[str] = (
        "Represents a retriever in the AWS QBusiness service. Retrievers are used to fetch and"
        " process data from various sources within the QBusiness ecosystem."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "application", "group": "generative_ai"}
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{application_id}/retriever/{id}",
        "extra_args_for_arn": ["application_id"],
    }
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("retrieverId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("displayName"),
        "application_id": S("applicationId"),
        "retriever_id": S("retrieverId"),
        "type": S("type"),
        "status": S("status"),
        "display_name": S("displayName"),
    }
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business application using the retriever."})  # fmt: skip
    retriever_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the retriever used by your Amazon Q Business application."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of your retriever."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of your retriever."})  # fmt: skip
    display_name: Optional[str] = field(default=None, metadata={"description": "The name of your retriever."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-retrievers", "retrievers"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-retriever"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-retriever",
            result_name=None,
            applicationId=self.application_id,
            retrieverId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsQBusinessWebExperience(AmazonQTaggable, AwsResource):
    kind: ClassVar[str] = "aws_q_business_web_experience"
    kind_display: ClassVar[str] = "AWS Q Business Web Experience"
    kind_description: ClassVar[str] = (
        "Represents a web experience in the AWS QBusiness service. Web experiences define"
        " interactive web-based applications or interfaces within the QBusiness ecosystem."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "application", "group": "generative_ai"}
    aws_metadata: ClassVar[Dict[str, Any]] = {
        "arn_tpl": "arn:{partition}:qbusiness:{region}:{account}:application/{application_id}/web-experience/{id}",
        "extra_args_for_arn": ["application_id"],
    }
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("webExperienceId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "web_experience_id": S("webExperienceId"),
        "created_at": S("createdAt"),
        "updated_at": S("updatedAt"),
        "default_endpoint": S("defaultEndpoint"),
        "status": S("status"),
    }
    application_id: Optional[str] = field(default=None, metadata={"description": "The identifier of the Amazon Q Business application."})  # fmt: skip
    web_experience_id: Optional[str] = field(default=None, metadata={"description": "The identifier of your Amazon Q Business web experience."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when the Amazon Q Business application was last updated."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The Unix timestamp when your Amazon Q Business web experience was updated."})  # fmt: skip
    default_endpoint: Optional[str] = field(default=None, metadata={"description": "The endpoint URLs for your Amazon Q Business web experience. The URLs are unique and fully hosted by Amazon Web Services."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of your Amazon Q Business web experience."})  # fmt: skip

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-web-experiences", "webExperiences"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "tag-resource"),
            AwsApiSpec(service_name, "untag-resource"),
            AwsApiSpec(service_name, "delete-web-experience"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qbusiness",
            action="delete-web-experience",
            result_name=None,
            applicationId=self.application_id,
            webExperienceId=self.id,
        )
        return True


@define(eq=False, slots=False)
class AwsQAppsCategory:
    kind: ClassVar[str] = "aws_q_apps_category"
    mapping: ClassVar[Dict[str, Bender]] = {"id": S("id"), "title": S("title")}
    id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the category."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title or name of the category."})  # fmt: skip


@define(eq=False, slots=False)
class AwsQAppsLibraryItem(AwsResource):
    kind: ClassVar[str] = "aws_q_apps_library_item"
    kind_display: ClassVar[str] = "AWS QApps Library Item"
    kind_description: ClassVar[str] = (
        "Represents a library item in the AWS QApps service. Library items include resources"
        " such as scripts, templates, or other components that can be used in QApps applications."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "image", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    reference_kinds: ClassVar[ModelReference] = {
        "predecessors": {"default": ["aws_q_apps"]},
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("libraryItemId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "ctime": S("createdAt"),
        "mtime": S("updatedAt"),
        "library_item_id": S("libraryItemId"),
        "app_id": S("appId"),
        "app_version": S("appVersion"),
        "library_categories": S("categories", default=[]) >> ForallBend(AwsQAppsCategory.mapping),
        "status": S("status"),
        "created_at": S("createdAt"),
        "created_by": S("createdBy"),
        "updated_at": S("updatedAt"),
        "updated_by": S("updatedBy"),
        "rating_count": S("ratingCount"),
        "is_rated_by_user": S("isRatedByUser"),
        "user_count": S("userCount"),
    }
    instance_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the environment app."})  # fmt: skip
    library_item_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the library item."})  # fmt: skip
    app_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the Q App associated with the library item."})  # fmt: skip
    app_version: Optional[int] = field(default=None, metadata={"description": "The version of the Q App associated with the library item."})  # fmt: skip
    library_categories: Optional[List[AwsQAppsCategory]] = field(factory=list, metadata={"description": "The categories associated with the library item."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the library item."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the library item was created."})  # fmt: skip
    created_by: Optional[str] = field(default=None, metadata={"description": "The user who created the library item."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the library item was last updated."})  # fmt: skip
    updated_by: Optional[str] = field(default=None, metadata={"description": "The user who last updated the library item."})  # fmt: skip
    rating_count: Optional[int] = field(default=None, metadata={"description": "The number of ratings the library item has received."})  # fmt: skip
    is_rated_by_user: Optional[bool] = field(default=None, metadata={"description": "Whether the current user has rated the library item."})  # fmt: skip
    user_count: Optional[int] = field(default=None, metadata={"description": "The number of users who have the associated Q App."})  # fmt: skip

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if app_id := self.app_id:
            builder.add_edge(self, reverse=True, clazz=AwsQApps, id=app_id)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("qapps", "list-library-items", "libraryItems"),
            AwsApiSpec("qapps", "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("qapps", "tag-resource"),
            AwsApiSpec("qapps", "untag-resource"),
            AwsApiSpec("qapps", "delete-library-item"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qapps",
            action="delete-library-item",
            result_name=None,
            instanceId=self.instance_id,
            libraryItemId=self.id,
        )
        return True

    @classmethod
    def service_name(cls) -> str:
        return "qapps"


@define(eq=False, slots=False)
class AwsQApps(AwsResource):
    kind: ClassVar[str] = "aws_q_apps"
    kind_display: ClassVar[str] = "AWS QApps"
    kind_description: ClassVar[str] = (
        "Represents an application within the AWS QApps service. QApps applications include"
        " various components and configurations for developing and deploying apps within the AWS environment."
    )
    kind_service: ClassVar[Optional[str]] = service_name
    metadata: ClassVar[Dict[str, Any]] = {"icon": "application", "group": "generative_ai"}
    # Collected via AwsQBusinessApplication()
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("appId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("Tags", default=[]) >> TagsValue("Name"),
        "app_id": S("appId"),
        "app_arn": S("appArn"),
        "title": S("title"),
        "description": S("description"),
        "created_at": S("createdAt"),
        "can_edit": S("canEdit"),
        "status": S("status"),
        "arn": S("appArn"),
    }
    instance_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the environment app."})  # fmt: skip
    app_id: Optional[str] = field(default=None, metadata={"description": "The unique identifier of the Q App."})  # fmt: skip
    app_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the Q App."})  # fmt: skip
    title: Optional[str] = field(default=None, metadata={"description": "The title of the Q App."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "The description of the Q App."})  # fmt: skip
    created_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time the user's association with the Q App was created."})  # fmt: skip
    can_edit: Optional[bool] = field(default=None, metadata={"description": "A flag indicating whether the user can edit the Q App."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the user's association with the Q App."})  # fmt: skip

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="qapps",
            action="tag-resource",
            result_name=None,
            resourceARN=self.arn,
            tags={key: value},
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="qapps",
            action="untag-resource",
            result_name=None,
            resourceARN=self.arn,
            tagKeys=[key],
        )
        return True

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("qapps", "list-q-apps", "apps"),
            AwsApiSpec("qapps", "list-tags-for-resource"),
        ]

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("qapps", "tag-resource"),
            AwsApiSpec("qapps", "untag-resource"),
            AwsApiSpec("qapps", "delete-q-app"),
        ]

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service="qapps",
            action="delete-q-app",
            result_name=None,
            instanceId=self.instance_id,
            appId=self.id,
        )
        return True

    @classmethod
    def service_name(cls) -> str:
        return "qapps"


resources: List[Type[AwsResource]] = [
    AwsQBusinessApplication,
    AwsQBusinessConversation,
    AwsQBusinessDataSource,
    AwsQBusinessDataSourceSyncJob,
    AwsQBusinessDocument,
    AwsQBusinessIndice,
    AwsQBusinessMessage,
    AwsQBusinessPlugin,
    AwsQBusinessRetriever,
    AwsQBusinessWebExperience,
    AwsQAppsLibraryItem,
    AwsQApps,
]
