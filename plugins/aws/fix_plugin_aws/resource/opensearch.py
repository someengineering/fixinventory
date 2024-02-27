import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, GraphBuilder, AwsApiSpec
from fix_plugin_aws.resource.cognito import AwsCognitoUserPool
from fix_plugin_aws.resource.ec2 import AwsEc2Subnet, AwsEc2SecurityGroup, AwsEc2Vpc, AwsEc2InstanceType
from fix_plugin_aws.utils import ToDict
from fixlib.json_bender import Bender, S, Bend, ParseJson, Sorted
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")

service_name = "opensearch"


@define(eq=False, slots=False)
class AwsOpenSearchClusterConfig:
    kind: ClassVar[str] = "aws_opensearch_cluster_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "instance_type": S("InstanceType"),
        "instance_count": S("InstanceCount"),
        "dedicated_master_enabled": S("DedicatedMasterEnabled"),
        "zone_awareness_enabled": S("ZoneAwarenessEnabled"),
        "zone_awareness_config": S("ZoneAwarenessConfig", "AvailabilityZoneCount"),
        "dedicated_master_type": S("DedicatedMasterType"),
        "dedicated_master_count": S("DedicatedMasterCount"),
        "warm_enabled": S("WarmEnabled"),
        "warm_type": S("WarmType"),
        "warm_count": S("WarmCount"),
        "cold_storage_options": S("ColdStorageOptions", "Enabled"),
        "multi_az_with_standby_enabled": S("MultiAZWithStandbyEnabled"),
    }
    instance_type: Optional[str] = field(default=None, metadata={"description": "Instance type of data nodes in the cluster."})  # fmt: skip
    instance_count: Optional[int] = field(default=None, metadata={"description": "Number of data nodes in the cluster. This number must be greater than 1, otherwise you receive a validation exception."})  # fmt: skip
    dedicated_master_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether dedicated master nodes are enabled for the cluster.True if the cluster will use a dedicated master node.False if the cluster will not."})  # fmt: skip
    zone_awareness_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether multiple Availability Zones are enabled. For more information, see Configuring a multi-AZ domain in Amazon OpenSearch Service."})  # fmt: skip
    zone_awareness_config: Optional[int] = field(default=None, metadata={"description": "Container for zone awareness configuration options. Only required if ZoneAwarenessEnabled is true."})  # fmt: skip
    dedicated_master_type: Optional[str] = field(default=None, metadata={"description": "OpenSearch Service instance type of the dedicated master nodes in the cluster."})  # fmt: skip
    dedicated_master_count: Optional[int] = field(default=None, metadata={"description": "Number of dedicated master nodes in the cluster. This number must be greater than 2 and not 4, otherwise you receive a validation exception."})  # fmt: skip
    warm_enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable warm storage for the cluster."})  # fmt: skip
    warm_type: Optional[str] = field(default=None, metadata={"description": "The instance type for the cluster's warm nodes."})  # fmt: skip
    warm_count: Optional[int] = field(default=None, metadata={"description": "The number of warm nodes in the cluster."})  # fmt: skip
    cold_storage_options: Optional[bool] = field(default=None, metadata={"description": "Container for cold storage configuration options."})  # fmt: skip
    multi_az_with_standby_enabled: Optional[bool] = field(default=None, metadata={"description": "A boolean that indicates whether a multi-AZ domain is turned on with a standby AZ. For more information, see Configuring a multi-AZ domain in Amazon OpenSearch Service."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchEBSOptions:
    kind: ClassVar[str] = "aws_opensearch_ebs_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "ebs_enabled": S("EBSEnabled"),
        "volume_type": S("VolumeType"),
        "volume_size": S("VolumeSize"),
        "iops": S("Iops"),
        "throughput": S("Throughput"),
    }
    ebs_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether EBS volumes are attached to data nodes in an OpenSearch Service domain."})  # fmt: skip
    volume_type: Optional[str] = field(default=None, metadata={"description": "Specifies the type of EBS volumes attached to data nodes."})  # fmt: skip
    volume_size: Optional[int] = field(default=None, metadata={"description": "Specifies the size (in GiB) of EBS volumes attached to data nodes."})  # fmt: skip
    iops: Optional[int] = field(default=None, metadata={"description": "Specifies the baseline input/output (I/O) performance of EBS volumes attached to data nodes. Applicable only for the gp3 and provisioned IOPS EBS volume types."})  # fmt: skip
    throughput: Optional[int] = field(default=None, metadata={"description": "Specifies the throughput (in MiB/s) of the EBS volumes attached to data nodes. Applicable only for the gp3 volume type."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchVPCDerivedInfo:
    kind: ClassVar[str] = "aws_opensearch_vpc_derived_info"
    mapping: ClassVar[Dict[str, Bender]] = {
        "vpc_id": S("VPCId"),
        "subnet_ids": S("SubnetIds", default=[]),
        "availability_zones": S("AvailabilityZones", default=[]),
        "security_group_ids": S("SecurityGroupIds", default=[]),
    }
    vpc_id: Optional[str] = field(default=None, metadata={"description": "The ID for your VPC. Amazon VPC generates this value when you create a VPC."})  # fmt: skip
    subnet_ids: Optional[List[str]] = field(factory=list, metadata={"description": "A list of subnet IDs associated with the VPC endpoints for the domain."})  # fmt: skip
    availability_zones: Optional[List[str]] = field(factory=list, metadata={"description": "The list of Availability Zones associated with the VPC subnets."})  # fmt: skip
    security_group_ids: Optional[List[str]] = field(factory=list, metadata={"description": "The list of security group IDs associated with the VPC endpoints for the domain."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchCognitoOptions:
    kind: ClassVar[str] = "aws_opensearch_cognito_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "user_pool_id": S("UserPoolId"),
        "identity_pool_id": S("IdentityPoolId"),
        "role_arn": S("RoleArn"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable or disable Amazon Cognito authentication for OpenSearch Dashboards."})  # fmt: skip
    user_pool_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Cognito user pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication."})  # fmt: skip
    identity_pool_id: Optional[str] = field(default=None, metadata={"description": "The Amazon Cognito identity pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication."})  # fmt: skip
    role_arn: Optional[str] = field(default=None, metadata={"description": "The AmazonOpenSearchServiceCognitoAccess role that allows OpenSearch Service to configure your user pool and identity pool."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchEncryptionAtRestOptions:
    kind: ClassVar[str] = "aws_opensearch_encryption_at_rest_options"
    mapping: ClassVar[Dict[str, Bender]] = {"enabled": S("Enabled"), "kms_key_id": S("KmsKeyId")}
    enabled: Optional[bool] = field(default=None, metadata={"description": "True to enable encryption at rest."})  # fmt: skip
    kms_key_id: Optional[str] = field(default=None, metadata={"description": "The KMS key ID. Takes the form 1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchLogPublishingOption:
    kind: ClassVar[str] = "aws_opensearch_log_publishing_option"
    mapping: ClassVar[Dict[str, Bender]] = {
        "cloud_watch_logs_log_group_arn": S("CloudWatchLogsLogGroupArn"),
        "enabled": S("Enabled"),
    }
    cloud_watch_logs_log_group_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the CloudWatch Logs group to publish logs to."})  # fmt: skip
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the log should be published."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchServiceSoftwareOptions:
    kind: ClassVar[str] = "aws_opensearch_service_software_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "current_version": S("CurrentVersion"),
        "new_version": S("NewVersion"),
        "update_available": S("UpdateAvailable"),
        "cancellable": S("Cancellable"),
        "update_status": S("UpdateStatus"),
        "description": S("Description"),
        "automated_update_date": S("AutomatedUpdateDate"),
        "optional_deployment": S("OptionalDeployment"),
    }
    current_version: Optional[str] = field(default=None, metadata={"description": "The current service software version present on the domain."})  # fmt: skip
    new_version: Optional[str] = field(default=None, metadata={"description": "The new service software version, if one is available."})  # fmt: skip
    update_available: Optional[bool] = field(default=None, metadata={"description": "True if you're able to update your service software version. False if you can't update your service software version."})  # fmt: skip
    cancellable: Optional[bool] = field(default=None, metadata={"description": "True if you're able to cancel your service software version update. False if you can't cancel your service software update."})  # fmt: skip
    update_status: Optional[str] = field(default=None, metadata={"description": "The status of your service software update."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description of the service software update status."})  # fmt: skip
    automated_update_date: Optional[datetime] = field(default=None, metadata={"description": "The timestamp, in Epoch time, until which you can manually request a service software update. After this date, we automatically update your service software."})  # fmt: skip
    optional_deployment: Optional[bool] = field(default=None, metadata={"description": "True if a service software is never automatically updated. False if a service software is automatically updated after the automated update date."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchDomainEndpointOptions:
    kind: ClassVar[str] = "aws_opensearch_domain_endpoint_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enforce_https": S("EnforceHTTPS"),
        "tls_security_policy": S("TLSSecurityPolicy"),
        "custom_endpoint_enabled": S("CustomEndpointEnabled"),
        "custom_endpoint": S("CustomEndpoint"),
        "custom_endpoint_certificate_arn": S("CustomEndpointCertificateArn"),
    }
    enforce_https: Optional[bool] = field(default=None, metadata={"description": "True to require that all traffic to the domain arrive over HTTPS."})  # fmt: skip
    tls_security_policy: Optional[str] = field(default=None, metadata={"description": "Specify the TLS security policy to apply to the HTTPS endpoint of the domain. The policy can be one of the following values:    Policy-Min-TLS-1-0-2019-07: TLS security policy that supports TLS version 1.0 to TLS version 1.2    Policy-Min-TLS-1-2-2019-07: TLS security policy that supports only TLS version 1.2"})  # fmt: skip
    custom_endpoint_enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable a custom endpoint for the domain."})  # fmt: skip
    custom_endpoint: Optional[str] = field(default=None, metadata={"description": "The fully qualified URL for the custom endpoint."})  # fmt: skip
    custom_endpoint_certificate_arn: Optional[str] = field(default=None, metadata={"description": "The ARN for your security certificate, managed in Amazon Web Services Certificate Manager (ACM)."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchSAMLIdp:
    kind: ClassVar[str] = "aws_opensearch_saml_idp"
    mapping: ClassVar[Dict[str, Bender]] = {"metadata_content": S("MetadataContent"), "entity_id": S("EntityId")}
    metadata_content: Optional[str] = field(default=None, metadata={"description": "The metadata of the SAML application, in XML format."})  # fmt: skip
    entity_id: Optional[str] = field(default=None, metadata={"description": "The unique entity ID of the application in the SAML identity provider."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchSAMLOptionsOutput:
    kind: ClassVar[str] = "aws_opensearch_saml_options_output"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "idp": S("Idp") >> Bend(AwsOpenSearchSAMLIdp.mapping),
        "subject_key": S("SubjectKey"),
        "roles_key": S("RolesKey"),
        "session_timeout_minutes": S("SessionTimeoutMinutes"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "True if SAML is enabled."})  # fmt: skip
    idp: Optional[AwsOpenSearchSAMLIdp] = field(default=None, metadata={"description": "Describes the SAML identity provider's information."})  # fmt: skip
    subject_key: Optional[str] = field(default=None, metadata={"description": "The key used for matching the SAML subject attribute."})  # fmt: skip
    roles_key: Optional[str] = field(default=None, metadata={"description": "The key used for matching the SAML roles attribute."})  # fmt: skip
    session_timeout_minutes: Optional[int] = field(default=None, metadata={"description": "The duration, in minutes, after which a user session becomes inactive."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchAdvancedSecurityOptions:
    kind: ClassVar[str] = "aws_opensearch_advanced_security_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "internal_user_database_enabled": S("InternalUserDatabaseEnabled"),
        "saml_options": S("SAMLOptions") >> Bend(AwsOpenSearchSAMLOptionsOutput.mapping),
        "anonymous_auth_disable_date": S("AnonymousAuthDisableDate"),
        "anonymous_auth_enabled": S("AnonymousAuthEnabled"),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "True if fine-grained access control is enabled."})  # fmt: skip
    internal_user_database_enabled: Optional[bool] = field(default=None, metadata={"description": "True if the internal user database is enabled."})  # fmt: skip
    saml_options: Optional[AwsOpenSearchSAMLOptionsOutput] = field(default=None, metadata={"description": "Container for information about the SAML configuration for OpenSearch Dashboards."})  # fmt: skip
    anonymous_auth_disable_date: Optional[datetime] = field(default=None, metadata={"description": "Date and time when the migration period will be disabled. Only necessary when enabling fine-grained access control on an existing domain."})  # fmt: skip
    anonymous_auth_enabled: Optional[bool] = field(default=None, metadata={"description": "True if a 30-day migration period is enabled, during which administrators can create role mappings. Only necessary when enabling fine-grained access control on an existing domain."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchAutoTuneOptionsOutput:
    kind: ClassVar[str] = "aws_opensearch_auto_tune_options_output"
    mapping: ClassVar[Dict[str, Bender]] = {
        "state": S("State"),
        "error_message": S("ErrorMessage"),
        "use_off_peak_window": S("UseOffPeakWindow"),
    }
    state: Optional[str] = field(default=None, metadata={"description": "The current state of Auto-Tune on the domain."})  # fmt: skip
    error_message: Optional[str] = field(default=None, metadata={"description": "Any errors that occurred while enabling or disabling Auto-Tune."})  # fmt: skip
    use_off_peak_window: Optional[bool] = field(default=None, metadata={"description": "Whether the domain's off-peak window will be used to deploy Auto-Tune changes rather than a maintenance schedule."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchChangeProgressDetails:
    kind: ClassVar[str] = "aws_opensearch_change_progress_details"
    mapping: ClassVar[Dict[str, Bender]] = {"change_id": S("ChangeId"), "message": S("Message")}
    change_id: Optional[str] = field(default=None, metadata={"description": "The ID of the configuration change."})  # fmt: skip
    message: Optional[str] = field(default=None, metadata={"description": "A message corresponding to the status of the configuration change."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchWindowStartTime:
    kind: ClassVar[str] = "aws_opensearch_window_start_time"
    mapping: ClassVar[Dict[str, Bender]] = {"hours": S("Hours"), "minutes": S("Minutes")}
    hours: Optional[int] = field(default=None, metadata={"description": "The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, 17 refers to 5:00 P.M. UTC."})  # fmt: skip
    minutes: Optional[int] = field(default=None, metadata={"description": "The start minute of the window, in UTC."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchOffPeakWindow:
    kind: ClassVar[str] = "aws_opensearch_off_peak_window"
    mapping: ClassVar[Dict[str, Bender]] = {
        "window_start_time": S("WindowStartTime") >> Bend(AwsOpenSearchWindowStartTime.mapping)
    }
    window_start_time: Optional[AwsOpenSearchWindowStartTime] = field(default=None, metadata={"description": "A custom start time for the off-peak window, in Coordinated Universal Time (UTC). The window length will always be 10 hours, so you can't specify an end time. For example, if you specify 11:00 P.M. UTC as a start time, the end time will automatically be set to 9:00 A.M."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchOffPeakWindowOptions:
    kind: ClassVar[str] = "aws_opensearch_off_peak_window_options"
    mapping: ClassVar[Dict[str, Bender]] = {
        "enabled": S("Enabled"),
        "off_peak_window": S("OffPeakWindow") >> Bend(AwsOpenSearchOffPeakWindow.mapping),
    }
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether to enable an off-peak window. This option is only available when modifying a domain created prior to February 16, 2023, not when creating a new domain. All domains created after this date have the off-peak window enabled by default. You can't disable the off-peak window after it's enabled for a domain."})  # fmt: skip
    off_peak_window: Optional[AwsOpenSearchOffPeakWindow] = field(default=None, metadata={"description": "Off-peak window settings for the domain."})  # fmt: skip


@define(eq=False, slots=False)
class AwsOpenSearchDomain(AwsResource):
    kind: ClassVar[str] = "aws_opensearch_domain"
    kind_display: ClassVar[str] = "AWS OpenSearch Domain"
    kind_description: ClassVar[str] = "An AWS OpenSearch Domain provides a managed environment in the AWS cloud to easily deploy, operate, and scale OpenSearch, a popular search and analytics engine."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/aos/home?region={region}#opensearch/domains/{name}", "arn_tpl": "arn:{partition}:opensearch:{region}:{account}:domain/{name}"}  # fmt: skip
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("DomainId"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("DomainName"),
        "arn": S("ARN"),
        "created": S("Created"),
        "deleted": S("Deleted"),
        "endpoint": S("Endpoint"),
        "endpoint_v2": S("EndpointV2"),
        "endpoints": S("Endpoints"),
        "processing": S("Processing"),
        "upgrade_processing": S("UpgradeProcessing"),
        "engine_version": S("EngineVersion"),
        "cluster_config": S("ClusterConfig") >> Bend(AwsOpenSearchClusterConfig.mapping),
        "ebs_options": S("EBSOptions") >> Bend(AwsOpenSearchEBSOptions.mapping),
        "access_policies": S("AccessPolicies") >> ParseJson() >> Sorted(sort_list=True),
        "ip_address_type": S("IPAddressType"),
        "snapshot_options": S("SnapshotOptions", "AutomatedSnapshotStartHour"),
        "vpc_options": S("VPCOptions") >> Bend(AwsOpenSearchVPCDerivedInfo.mapping),
        "cognito_options": S("CognitoOptions") >> Bend(AwsOpenSearchCognitoOptions.mapping),
        "encryption_at_rest_options": S("EncryptionAtRestOptions")
        >> Bend(AwsOpenSearchEncryptionAtRestOptions.mapping),
        "node_to_node_encryption_options": S("NodeToNodeEncryptionOptions", "Enabled"),
        "advanced_options": S("AdvancedOptions"),
        "log_publishing_options": S("LogPublishingOptions"),
        "service_software_options": S("ServiceSoftwareOptions") >> Bend(AwsOpenSearchServiceSoftwareOptions.mapping),
        "domain_endpoint_options": S("DomainEndpointOptions") >> Bend(AwsOpenSearchDomainEndpointOptions.mapping),
        "advanced_security_options": S("AdvancedSecurityOptions") >> Bend(AwsOpenSearchAdvancedSecurityOptions.mapping),
        "auto_tune_options": S("AutoTuneOptions") >> Bend(AwsOpenSearchAutoTuneOptionsOutput.mapping),
        "change_progress_details": S("ChangeProgressDetails") >> Bend(AwsOpenSearchChangeProgressDetails.mapping),
        "off_peak_window_options": S("OffPeakWindowOptions") >> Bend(AwsOpenSearchOffPeakWindowOptions.mapping),
        "software_update_options": S("SoftwareUpdateOptions", "AutoSoftwareUpdateEnabled"),
    }
    created: Optional[bool] = field(default=None, metadata={"description": "Creation status of an OpenSearch Service domain. True if domain creation is complete. False if domain creation is still in progress."})  # fmt: skip
    deleted: Optional[bool] = field(default=None, metadata={"description": "Deletion status of an OpenSearch Service domain. True if domain deletion is complete. False if domain deletion is still in progress. Once deletion is complete, the status of the domain is no longer returned."})  # fmt: skip
    endpoint: Optional[str] = field(default=None, metadata={"description": "Domain-specific endpoint used to submit index, search, and data upload requests to the domain."})  # fmt: skip
    endpoint_v2: Optional[str] = field(default=None, metadata={"description": "The domain endpoint to which index and search requests are submitted. For example, search-imdb-movies-oopcnjfn6ugo.eu-west-1.es.amazonaws.com or doc-imdb-movies-oopcnjfn6u.eu-west-1.es.amazonaws.com."})  # fmt: skip
    endpoints: Optional[Dict[str, str]] = field(default=None, metadata={"description": "The key-value pair that exists if the OpenSearch Service domain uses VPC endpoints.. Example key, value: 'vpc','vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.us-east-1.es.amazonaws.com'."})  # fmt: skip
    processing: Optional[bool] = field(default=None, metadata={"description": "The status of the domain configuration. True if OpenSearch Service is processing configuration changes. False if the configuration is active."})  # fmt: skip
    upgrade_processing: Optional[bool] = field(default=None, metadata={"description": "The status of a domain version upgrade to a new version of OpenSearch or Elasticsearch. True if OpenSearch Service is in the process of a version upgrade. False if the configuration is active."})  # fmt: skip
    engine_version: Optional[str] = field(default=None, metadata={"description": "Version of OpenSearch or Elasticsearch that the domain is running, in the format Elasticsearch_X.Y or OpenSearch_X.Y."})  # fmt: skip
    cluster_config: Optional[AwsOpenSearchClusterConfig] = field(default=None, metadata={"description": "Container for the cluster configuration of the domain."})  # fmt: skip
    ebs_options: Optional[AwsOpenSearchEBSOptions] = field(default=None, metadata={"description": "Container for EBS-based storage settings for the domain."})  # fmt: skip
    access_policies: Optional[Json] = field(default=None, metadata={"description": "Identity and Access Management (IAM) policy document specifying the access policies for the domain."})  # fmt: skip
    ip_address_type: Optional[str] = field(default=None, metadata={"description": "The type of IP addresses supported by the endpoint for the domain."})  # fmt: skip
    snapshot_options: Optional[int] = field(default=None, metadata={"description": "DEPRECATED. Container for parameters required to configure automated snapshots of domain indexes."})  # fmt: skip
    vpc_options: Optional[AwsOpenSearchVPCDerivedInfo] = field(default=None, metadata={"description": "The VPC configuration for the domain."})  # fmt: skip
    cognito_options: Optional[AwsOpenSearchCognitoOptions] = field(default=None, metadata={"description": "Key-value pairs to configure Amazon Cognito authentication for OpenSearch Dashboards."})  # fmt: skip
    encryption_at_rest_options: Optional[AwsOpenSearchEncryptionAtRestOptions] = field(default=None, metadata={"description": "Encryption at rest settings for the domain."})  # fmt: skip
    node_to_node_encryption_options: Optional[bool] = field(default=None, metadata={"description": "Whether node-to-node encryption is enabled or disabled."})  # fmt: skip
    advanced_options: Optional[Dict[str, str]] = field(default=None, metadata={"description": "Key-value pairs that specify advanced configuration options."})  # fmt: skip
    log_publishing_options: Optional[Dict[str, AwsOpenSearchLogPublishingOption]] = field(default=None, metadata={"description": "Log publishing options for the domain."})  # fmt: skip
    service_software_options: Optional[AwsOpenSearchServiceSoftwareOptions] = field(default=None, metadata={"description": "The current status of the domain's service software."})  # fmt: skip
    domain_endpoint_options: Optional[AwsOpenSearchDomainEndpointOptions] = field(default=None, metadata={"description": "Additional options for the domain endpoint, such as whether to require HTTPS for all traffic."})  # fmt: skip
    advanced_security_options: Optional[AwsOpenSearchAdvancedSecurityOptions] = field(default=None, metadata={"description": "Settings for fine-grained access control."})  # fmt: skip
    auto_tune_options: Optional[AwsOpenSearchAutoTuneOptionsOutput] = field(default=None, metadata={"description": "Auto-Tune settings for the domain."})  # fmt: skip
    change_progress_details: Optional[AwsOpenSearchChangeProgressDetails] = field(default=None, metadata={"description": "Information about a configuration change happening on the domain."})  # fmt: skip
    off_peak_window_options: Optional[AwsOpenSearchOffPeakWindowOptions] = field(default=None, metadata={"description": "Options that specify a custom 10-hour window during which OpenSearch Service can perform configuration changes on the domain."})  # fmt: skip
    software_update_options: Optional[bool] = field(default=None, metadata={"description": "Service software update options for the domain."})  # fmt: skip

    @classmethod
    def collect_resources(cls, builder: GraphBuilder) -> None:
        try:
            if dl_raw := builder.client.list(service_name, "list-domain-names", "DomainNames"):
                items = builder.client.list(
                    aws_service=service_name,
                    action="describe-domains",
                    result_name="DomainStatusList",
                    DomainNames=[d["DomainName"] for d in dl_raw],
                )
                cls.collect(items, builder)
        except Boto3Error as e:
            msg = f"Error while collecting AwsOpenSearchDomain in region {builder.region.name}: {e}"
            builder.core_feedback.error(msg, log)
            raise
        except Exception as e:
            msg = f"Error while collecting AwsOpenSearchDomain in region {builder.region.name}: {e}"
            builder.core_feedback.info(msg, log)
            raise

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        if cluster_config := self.cluster_config:
            if instance_type := cluster_config.instance_type:
                builder.add_edge(self, reverse=True, clazz=AwsEc2InstanceType, id=instance_type)
        if vpc_options := self.vpc_options:
            if vpc_id := vpc_options.vpc_id:
                builder.dependant_node(self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Vpc, id=vpc_id)
            for security_group_id in self.vpc_options.security_group_ids or []:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2SecurityGroup, id=security_group_id
                )
            for subnet_id in self.vpc_options.subnet_ids or []:
                builder.dependant_node(
                    self, reverse=True, delete_same_as_default=True, clazz=AwsEc2Subnet, id=subnet_id
                )
        if cognito_options := self.cognito_options:
            if user_pool_id := cognito_options.user_pool_id:
                builder.add_edge(self, clazz=AwsCognitoUserPool, id=user_pool_id)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "list-domain-names"), AwsApiSpec(service_name, "describe-domain-names")]

    @classmethod
    def service_name(cls) -> Optional[str]:
        return service_name


resources: List[Type[AwsResource]] = [AwsOpenSearchDomain]
