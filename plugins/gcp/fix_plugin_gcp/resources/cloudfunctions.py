from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder, GcpMonitoringQuery
from fix_plugin_gcp.resources.monitoring import normalizer_factory, STANDART_STAT_MAP, PERCENTILE_STAT_MAP
from fixlib.baseresources import BaseServerlessFunction, MetricName
from fixlib.json_bender import Bender, S, Bend, ForallBend


@define(eq=False, slots=False)
class GcpRepoSource:
    kind: ClassVar[str] = "gcp_repo_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "branch_name": S("branchName"),
        "commit_sha": S("commitSha"),
        "dir": S("dir"),
        "project_id": S("projectId"),
        "repo_name": S("repoName"),
        "tag_name": S("tagName"),
    }
    branch_name: Optional[str] = field(default=None)
    commit_sha: Optional[str] = field(default=None)
    dir: Optional[str] = field(default=None)
    project_id: Optional[str] = field(default=None)
    repo_name: Optional[str] = field(default=None)
    tag_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpStorageSource:
    kind: ClassVar[str] = "gcp_storage_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "bucket": S("bucket"),
        "generation": S("generation"),
        "object": S("object"),
        "source_upload_url": S("sourceUploadUrl"),
    }
    bucket: Optional[str] = field(default=None)
    generation: Optional[str] = field(default=None)
    object: Optional[str] = field(default=None)
    source_upload_url: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSource:
    kind: ClassVar[str] = "gcp_source"
    mapping: ClassVar[Dict[str, Bender]] = {
        "git_uri": S("gitUri"),
        "repo_source": S("repoSource", default={}) >> Bend(GcpRepoSource.mapping),
        "storage_source": S("storageSource", default={}) >> Bend(GcpStorageSource.mapping),
    }
    git_uri: Optional[str] = field(default=None)
    repo_source: Optional[GcpRepoSource] = field(default=None)
    storage_source: Optional[GcpStorageSource] = field(default=None)


@define(eq=False, slots=False)
class GcpSourceProvenance:
    kind: ClassVar[str] = "gcp_source_provenance"
    mapping: ClassVar[Dict[str, Bender]] = {
        "git_uri": S("gitUri"),
        "resolved_repo_source": S("resolvedRepoSource", default={}) >> Bend(GcpRepoSource.mapping),
        "resolved_storage_source": S("resolvedStorageSource", default={}) >> Bend(GcpStorageSource.mapping),
    }
    git_uri: Optional[str] = field(default=None)
    resolved_repo_source: Optional[GcpRepoSource] = field(default=None)
    resolved_storage_source: Optional[GcpStorageSource] = field(default=None)


@define(eq=False, slots=False)
class GcpBuildConfig:
    kind: ClassVar[str] = "gcp_build_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "automatic_update_policy": S("automaticUpdatePolicy", default={}),
        "build": S("build"),
        "docker_registry": S("dockerRegistry"),
        "docker_repository": S("dockerRepository"),
        "entry_point": S("entryPoint"),
        "environment_variables": S("environmentVariables"),
        "on_deploy_update_policy": S("onDeployUpdatePolicy", "runtimeVersion"),
        "runtime": S("runtime"),
        "service_account": S("serviceAccount"),
        "source": S("source", default={}) >> Bend(GcpSource.mapping),
        "source_provenance": S("sourceProvenance", default={}) >> Bend(GcpSourceProvenance.mapping),
        "source_token": S("sourceToken"),
        "worker_pool": S("workerPool"),
    }
    automatic_update_policy: Optional[Dict[str, Any]] = field(default=None)
    build: Optional[str] = field(default=None)
    docker_registry: Optional[str] = field(default=None)
    docker_repository: Optional[str] = field(default=None)
    entry_point: Optional[str] = field(default=None)
    environment_variables: Optional[Dict[str, str]] = field(default=None)
    on_deploy_update_policy: Optional[str] = field(default=None)
    runtime: Optional[str] = field(default=None)
    service_account: Optional[str] = field(default=None)
    source: Optional[GcpSource] = field(default=None)
    source_provenance: Optional[GcpSourceProvenance] = field(default=None)
    source_token: Optional[str] = field(default=None)
    worker_pool: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpEventFilter:
    kind: ClassVar[str] = "gcp_event_filter"
    mapping: ClassVar[Dict[str, Bender]] = {"attribute": S("attribute"), "operator": S("operator"), "value": S("value")}
    attribute: Optional[str] = field(default=None)
    operator: Optional[str] = field(default=None)
    value: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpEventTrigger:
    kind: ClassVar[str] = "gcp_event_trigger"
    mapping: ClassVar[Dict[str, Bender]] = {
        "channel": S("channel"),
        "event_filters": S("eventFilters", default=[]) >> ForallBend(GcpEventFilter.mapping),
        "event_type": S("eventType"),
        "pubsub_topic": S("pubsubTopic"),
        "retry_policy": S("retryPolicy"),
        "service": S("service"),
        "service_account_email": S("serviceAccountEmail"),
        "trigger": S("trigger"),
        "trigger_region": S("triggerRegion"),
    }
    channel: Optional[str] = field(default=None)
    event_filters: Optional[List[GcpEventFilter]] = field(default=None)
    event_type: Optional[str] = field(default=None)
    pubsub_topic: Optional[str] = field(default=None)
    retry_policy: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    service_account_email: Optional[str] = field(default=None)
    trigger: Optional[str] = field(default=None)
    trigger_region: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecretEnvVar:
    kind: ClassVar[str] = "gcp_secret_env_var"
    mapping: ClassVar[Dict[str, Bender]] = {
        "key": S("key"),
        "project_id": S("projectId"),
        "secret": S("secret"),
        "version": S("version"),
    }
    key: Optional[str] = field(default=None)
    project_id: Optional[str] = field(default=None)
    secret: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecretVersion:
    kind: ClassVar[str] = "gcp_secret_version"
    mapping: ClassVar[Dict[str, Bender]] = {"path": S("path"), "version": S("version")}
    path: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSecretVolume:
    kind: ClassVar[str] = "gcp_secret_volume"
    mapping: ClassVar[Dict[str, Bender]] = {
        "mount_path": S("mountPath"),
        "project_id": S("projectId"),
        "secret": S("secret"),
        "versions": S("versions", default=[]) >> ForallBend(GcpSecretVersion.mapping),
    }
    mount_path: Optional[str] = field(default=None)
    project_id: Optional[str] = field(default=None)
    secret: Optional[str] = field(default=None)
    versions: Optional[List[GcpSecretVersion]] = field(default=None)


@define(eq=False, slots=False)
class GcpServiceConfig:
    kind: ClassVar[str] = "gcp_service_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "all_traffic_on_latest_revision": S("allTrafficOnLatestRevision"),
        "available_cpu": S("availableCpu"),
        "available_memory": S("availableMemory"),
        "binary_authorization_policy": S("binaryAuthorizationPolicy"),
        "environment_variables": S("environmentVariables"),
        "ingress_settings": S("ingressSettings"),
        "max_instance_count": S("maxInstanceCount"),
        "max_instance_request_concurrency": S("maxInstanceRequestConcurrency"),
        "min_instance_count": S("minInstanceCount"),
        "revision": S("revision"),
        "secret_environment_variables": S("secretEnvironmentVariables", default=[])
        >> ForallBend(GcpSecretEnvVar.mapping),
        "secret_volumes": S("secretVolumes", default=[]) >> ForallBend(GcpSecretVolume.mapping),
        "security_level": S("securityLevel"),
        "service": S("service"),
        "service_account_email": S("serviceAccountEmail"),
        "timeout_seconds": S("timeoutSeconds"),
        "uri": S("uri"),
        "vpc_connector": S("vpcConnector"),
        "vpc_connector_egress_settings": S("vpcConnectorEgressSettings"),
    }
    all_traffic_on_latest_revision: Optional[bool] = field(default=None)
    available_cpu: Optional[str] = field(default=None)
    available_memory: Optional[str] = field(default=None)
    binary_authorization_policy: Optional[str] = field(default=None)
    environment_variables: Optional[Dict[str, str]] = field(default=None)
    ingress_settings: Optional[str] = field(default=None)
    max_instance_count: Optional[int] = field(default=None)
    max_instance_request_concurrency: Optional[int] = field(default=None)
    min_instance_count: Optional[int] = field(default=None)
    revision: Optional[str] = field(default=None)
    secret_environment_variables: Optional[List[GcpSecretEnvVar]] = field(default=None)
    secret_volumes: Optional[List[GcpSecretVolume]] = field(default=None)
    security_level: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)
    service_account_email: Optional[str] = field(default=None)
    timeout_seconds: Optional[int] = field(default=None)
    uri: Optional[str] = field(default=None)
    vpc_connector: Optional[str] = field(default=None)
    vpc_connector_egress_settings: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudFunctionsStateMessage:
    kind: ClassVar[str] = "gcp_cloud_functions_state_message"
    mapping: ClassVar[Dict[str, Bender]] = {"message": S("message"), "severity": S("severity"), "type": S("type")}
    message: Optional[str] = field(default=None)
    severity: Optional[str] = field(default=None)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpUpgradeInfo:
    kind: ClassVar[str] = "gcp_upgrade_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "build_config": S("buildConfig", default={}) >> Bend(GcpBuildConfig.mapping),
        "event_trigger": S("eventTrigger", default={}) >> Bend(GcpEventTrigger.mapping),
        "service_config": S("serviceConfig", default={}) >> Bend(GcpServiceConfig.mapping),
        "upgrade_state": S("upgradeState"),
    }
    build_config: Optional[GcpBuildConfig] = field(default=None)
    event_trigger: Optional[GcpEventTrigger] = field(default=None)
    service_config: Optional[GcpServiceConfig] = field(default=None)
    upgrade_state: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpCloudFunction(GcpResource, BaseServerlessFunction):
    kind: ClassVar[str] = "gcp_cloud_function"
    _kind_display: ClassVar[str] = "GCP Cloud Function"
    _kind_description: ClassVar[str] = (
        "GCP Cloud Function is a serverless execution environment for building and connecting cloud services."
        " It allows you to run your code in response to events without provisioning or managing servers."
    )
    _docs_url: ClassVar[str] = "https://cloud.google.com/functions/docs"
    _kind_service: ClassVar[Optional[str]] = "cloudfunctions"
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "function", "group": "compute"}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudfunctions",
        version="v2",
        accessors=["projects", "locations", "functions"],
        action="list",
        request_parameter={"parent": "projects/{project}/locations/-"},
        request_parameter_in={"project"},
        response_path="functions",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("name").or_else(S("id")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "build_config": S("buildConfig", default={}) >> Bend(GcpBuildConfig.mapping),
        "create_time": S("createTime"),
        "environment": S("environment"),
        "event_trigger": S("eventTrigger", default={}) >> Bend(GcpEventTrigger.mapping),
        "kms_key_name": S("kmsKeyName"),
        "satisfies_pzs": S("satisfiesPzs"),
        "service_config": S("serviceConfig", default={}) >> Bend(GcpServiceConfig.mapping),
        "state": S("state"),
        "state_messages": S("stateMessages", default=[]) >> ForallBend(GcpCloudFunctionsStateMessage.mapping),
        "update_time": S("updateTime"),
        "upgrade_info": S("upgradeInfo", default={}) >> Bend(GcpUpgradeInfo.mapping),
        "url": S("url"),
    }
    build_config: Optional[GcpBuildConfig] = field(default=None)
    create_time: Optional[datetime] = field(default=None)
    environment: Optional[str] = field(default=None)
    event_trigger: Optional[GcpEventTrigger] = field(default=None)
    kms_key_name: Optional[str] = field(default=None)
    satisfies_pzs: Optional[bool] = field(default=None)
    service_config: Optional[GcpServiceConfig] = field(default=None)
    state: Optional[str] = field(default=None)
    state_messages: Optional[List[GcpCloudFunctionsStateMessage]] = field(default=None)
    update_time: Optional[datetime] = field(default=None)
    upgrade_info: Optional[GcpUpgradeInfo] = field(default=None)
    url: Optional[str] = field(default=None)

    def collect_usage_metrics(self, builder: GraphBuilder) -> List[GcpMonitoringQuery]:
        queries: List[GcpMonitoringQuery] = []
        delta = builder.metrics_delta
        queries.extend(
            [
                GcpMonitoringQuery.create(
                    query_name="cloudfunctions.googleapis.com/function/execution_count",
                    period=delta,
                    ref_id=f"{self.kind}/{self.id}/{self.region().id}",
                    metric_name=MetricName.Invocations,
                    normalization=normalizer_factory.count,
                    stat=stat,
                    project_id=builder.project.id,
                    metric_filters={
                        "metric.labels.status": "ok",
                        "resource.labels.function_name": self.resource_raw_name,
                        "resource.labels.region": self.region().id,
                        "resource.type": "cloud_function",
                    },
                )
                for stat in STANDART_STAT_MAP
            ]
        )
        queries.extend(
            [
                GcpMonitoringQuery.create(
                    query_name="cloudfunctions.googleapis.com/function/execution_count",
                    period=delta,
                    ref_id=f"{self.kind}/{self.id}/{self.region().id}",
                    metric_name=MetricName.Errors,
                    normalization=normalizer_factory.count,
                    stat=stat,
                    project_id=builder.project.id,
                    metric_filters={
                        "metric.labels.status": "error",
                        "resource.labels.function_name": self.resource_raw_name,
                        "resource.labels.region": self.region().id,
                        "resource.type": "cloud_function",
                    },
                )
                for stat in STANDART_STAT_MAP
            ]
        )
        queries.extend(
            [
                GcpMonitoringQuery.create(
                    query_name="cloudfunctions.googleapis.com/function/execution_times",
                    period=delta,
                    ref_id=f"{self.kind}/{self.id}/{self.region().id}",
                    metric_name=MetricName.Duration,
                    # convert nanoseconds to milliseconds
                    normalization=normalizer_factory.milliseconds(lambda x: round(x / 1_000_000, ndigits=4)),
                    stat=stat,
                    project_id=builder.project.id,
                    metric_filters={
                        "resource.labels.function_name": self.resource_raw_name,
                        "resource.labels.region": self.region().id,
                        "resource.type": "cloud_function",
                    },
                )
                for stat in PERCENTILE_STAT_MAP
            ]
        )
        return queries


resources: List[Type[GcpResource]] = [GcpCloudFunction]
