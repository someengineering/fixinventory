from typing import ClassVar, Dict, Optional, List, Type, Any, Tuple

from attrs import define, field

from fix_plugin_aws.aws_client import AwsClient
from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder, parse_json
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import (
    BaseDNSZone,
    BaseDNSRecord,
    EdgeType,
    BaseDNSRecordSet,
    ModelReference,
)
from fixlib.graph import Graph
from fixlib.json_bender import F, Bender, S, Bend, ForallBend, bend
from fixlib.types import Json
from fixlib.utils import rrdata_as_dict

service_name = "route53"


@define(eq=False, slots=False)
class AwsRoute53ZoneConfig:
    kind: ClassVar[str] = "aws_route53_zone_config"
    kind_display: ClassVar[str] = "AWS Route53 Zone Config"
    kind_description: ClassVar[str] = (
        "Route53 Zone Config is a service provided by Amazon Web Services that allows"
        " users to configure DNS settings for their domain names in the cloud."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"comment": S("Comment"), "private_zone": S("PrivateZone")}
    comment: Optional[str] = field(default=None)
    private_zone: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53LinkedService:
    kind: ClassVar[str] = "aws_route53_linked_service"
    kind_display: ClassVar[str] = "AWS Route 53 Linked Service"
    kind_description: ClassVar[str] = (
        "The AWS Route 53 Linked Service is a configuration that integrates Route 53 with other AWS services"
        " via a service principal, which is an identifier that is used to grant permissions."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"service_principal": S("ServicePrincipal"), "description": S("Description")}
    service_principal: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53LoggingConfig:
    kind: ClassVar[str] = "aws_route53_logging_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "cloud_watch_logs_log_group_arn": S("CloudWatchLogsLogGroupArn"),
    }
    id: Optional[str] = field(default=None, metadata={"description": "The ID for a configuration for DNS query logging."})  # fmt: skip
    cloud_watch_logs_log_group_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the CloudWatch Logs log group that Amazon Route 53 is publishing logs to."})  # fmt: skip


@define(eq=False, slots=False)
class AwsRoute53Zone(AwsResource, BaseDNSZone):
    kind: ClassVar[str] = "aws_route53_zone"
    kind_display: ClassVar[str] = "AWS Route 53 Zone"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/route53/v2/hostedzones?region={region}#ListRecordSets/{id}", "arn_tpl": "arn:{partition}:route53:{region}:{account}:zone/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "AWS Route 53 Zones manage domain DNS settings, enabling users to direct"
        " internet traffic for their domains through various DNS records."
    )
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-hosted-zones", "HostedZones")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_route53_resource_record_set"],
            "delete": [],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id") >> F(lambda x: x.rsplit("/", 1)[-1]),  # remove leading "/hostedzones/"
        "name": S("Name"),
        "zone_caller_reference": S("CallerReference"),
        "zone_config": S("Config") >> Bend(AwsRoute53ZoneConfig.mapping),
        "zone_resource_record_set_count": S("ResourceRecordSetCount"),
        "zone_linked_service": S("LinkedService") >> Bend(AwsRoute53LinkedService.mapping),
    }
    zone_caller_reference: Optional[str] = field(default=None)
    zone_config: Optional[AwsRoute53ZoneConfig] = field(default=None)
    zone_resource_record_set_count: Optional[int] = field(default=None, metadata=dict(ignore_history=True))
    zone_linked_service: Optional[AwsRoute53LinkedService] = field(default=None)
    zone_logging_config: Optional[AwsRoute53LoggingConfig] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec(service_name, "list-resource-record-sets"),
            AwsApiSpec(service_name, "list-tags-for-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(zone: AwsRoute53Zone) -> None:
            tags = builder.client.get(
                service_name,
                "list-tags-for-resource",
                result_name="ResourceTagSet",
                ResourceType="hostedzone",
                ResourceId=zone.id,
            )
            if tags:
                zone.tags = bend(S("Tags", default=[]) >> ToDict(), tags)

        def fetch_logging_configuration(zone: AwsRoute53Zone) -> None:
            with builder.suppress("route53.list-query-logging-configs"):
                if res := builder.client.list(
                    service_name, "list-query-logging-configs", "QueryLoggingConfigs", HostedZoneId=zone.id
                ):
                    zone.zone_logging_config = parse_json(
                        res[0], AwsRoute53LoggingConfig, builder, AwsRoute53LoggingConfig.mapping
                    )

        for js in json:
            if zone := AwsRoute53Zone.from_api(js, builder):
                builder.add_node(zone, js)
                builder.submit_work(service_name, add_tags, zone)
                builder.submit_work(service_name, fetch_logging_configuration, zone)
                for rs_js in builder.client.list(
                    service_name, "list-resource-record-sets", "ResourceRecordSets", HostedZoneId=zone.id
                ):
                    if record_set := AwsRoute53ResourceRecordSet.from_api(rs_js, builder):
                        builder.add_node(record_set, rs_js)
                        builder.add_edge(zone, EdgeType.default, node=record_set)
                        for data in record_set.record_values:
                            record = AwsRoute53ResourceRecord(
                                id=record_set.id,
                                name=record_set.name,
                                record_type=record_set.record_type,
                                record_ttl=record_set.record_ttl or 0,
                                record_set_identifier=record_set.record_set_identifier,
                                record_data=data,
                                **rrdata_as_dict(record_set.record_type, data),
                            )
                            builder.add_node(record, js)
                            builder.add_edge(record_set, EdgeType.default, node=record)
                            builder.add_edge(record_set, EdgeType.delete, node=record)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service=service_name,
            action="change-tags-for-resource",
            result_name=None,
            ResourceType="hostedzone",
            ResourceId=self.id,
            AddTags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service=service_name,
            action="change-tags-for-resource",
            result_name=None,
            ResourceType="hostedzone",
            ResourceId=self.id,
            RemoveTagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient, graph: Graph) -> bool:
        client.call(
            aws_service=service_name, action="delete-hosted-zone", result_name=None, Id=self.id.rsplit("/", 1)[-1]
        )
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "change-tags-for-resource"),
            AwsApiSpec(service_name, "delete-hosted-zone"),
        ]


@define(eq=False, slots=False)
class AwsRoute53GeoLocation:
    kind: ClassVar[str] = "aws_route53_geo_location"
    kind_display: ClassVar[str] = "AWS Route53 Geo Location"
    kind_description: ClassVar[str] = (
        "Route53 Geo Location is a feature of AWS Route53 DNS service that allows you"
        " to route traffic based on the geographic location of your users, providing"
        " low latency and improved user experience."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "continent_code": S("ContinentCode"),
        "country_code": S("CountryCode"),
        "subdivision_code": S("SubdivisionCode"),
    }
    continent_code: Optional[str] = field(default=None)
    country_code: Optional[str] = field(default=None)
    subdivision_code: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53AliasTarget:
    kind: ClassVar[str] = "aws_route53_alias_target"
    kind_display: ClassVar[str] = "AWS Route 53 Alias Target"
    kind_description: ClassVar[str] = (
        "AWS Route 53 Alias Target is a feature of Amazon Route 53, a scalable domain"
        " name system web service that translates domain names to IP addresses. Alias"
        " Target allows you to route traffic to other AWS resources such as Amazon S3"
        " buckets, CloudFront distributions, and Elastic Load Balancers."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "hosted_zone_id": S("HostedZoneId"),
        "dns_name": S("DNSName"),
        "evaluate_target_health": S("EvaluateTargetHealth"),
    }
    hosted_zone_id: Optional[str] = field(default=None)
    dns_name: Optional[str] = field(default=None)
    evaluate_target_health: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53CidrRoutingConfig:
    kind: ClassVar[str] = "aws_route53_cidr_routing_config"
    kind_display: ClassVar[str] = "AWS Route 53 CIDR Routing Config"
    kind_description: ClassVar[str] = (
        "The AWS Route 53 CIDR Routing Config is a feature for managing how traffic is routed based"
        " on IP address location, allowing for more precise traffic routing decisions in Amazon Route 53 services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"collection_id": S("CollectionId"), "location_name": S("LocationName")}
    collection_id: Optional[str] = field(default=None)
    location_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53ResourceRecord(AwsResource, BaseDNSRecord):
    kind: ClassVar[str] = "aws_route53_resource_record"
    kind_display: ClassVar[str] = "AWS Route 53 Resource Record"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:route53:::{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Route 53 Resource Records are domain name system (DNS) records used by AWS"
        " Route 53 to route traffic to AWS resources or to external resources."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [],
            "delete": [],
        }
    }
    _record_set_identifier: Optional[str] = field(default=None)

    def _keys(self) -> Tuple[Any, ...]:
        return tuple(list(super()._keys()) + [self._record_set_identifier])

    @classmethod
    def service_name(cls) -> str:
        return service_name


@define(eq=False, slots=False)
class AwsRoute53ResourceRecordSet(AwsResource, BaseDNSRecordSet):
    kind: ClassVar[str] = "aws_route53_resource_record_set"
    kind_display: ClassVar[str] = "AWS Route 53 Resource Record Set"
    aws_metadata: ClassVar[Dict[str, Any]] = {"arn_tpl": "arn:{partition}:route53::{account}:recordset/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = (
        "Route 53 Resource Record Sets are DNS records that map domain names to IP"
        " addresses or other DNS resources, allowing users to manage domain name"
        " resolution in the Amazon Route 53 service."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": ["aws_route53_resource_record"],
            "delete": ["aws_route53_resource_record"],
        }
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Name"),
        "name": S("Name"),
        "record_set_identifier": S("SetIdentifier"),
        "record_type": S("Type"),
        "record_weight": S("Weight"),
        "record_region": S("Region"),
        "record_geo_location": S("GeoLocation") >> Bend(AwsRoute53GeoLocation.mapping),
        "record_fail_over": S("Failover"),
        "record_multi_value_answer": S("MultiValueAnswer"),
        "record_ttl": S("TTL"),
        "record_values": S("ResourceRecords", default=[]) >> ForallBend(S("Value")),
        "record_alias_target": S("AliasTarget") >> Bend(AwsRoute53AliasTarget.mapping),
        "record_health_check_id": S("HealthCheckId"),
        "record_traffic_policy_instance_id": S("TrafficPolicyInstanceId"),
        "record_cidr_routing_config": S("CidrRoutingConfig") >> Bend(AwsRoute53CidrRoutingConfig.mapping),
    }
    record_name: Optional[str] = field(default=None)
    record_set_identifier: Optional[str] = field(default=None)
    record_weight: Optional[int] = field(default=None)
    record_region: Optional[str] = field(default=None)
    record_geo_location: Optional[AwsRoute53GeoLocation] = field(default=None)
    record_fail_over: Optional[str] = field(default=None)
    record_multi_value_answer: Optional[bool] = field(default=None)
    record_alias_target: Optional[AwsRoute53AliasTarget] = field(default=None)
    record_health_check_id: Optional[str] = field(default=None)
    record_traffic_policy_instance_id: Optional[str] = field(default=None)
    record_cidr_routing_config: Optional[AwsRoute53CidrRoutingConfig] = field(default=None)

    def _keys(self) -> tuple[str, str, str, str, str, str, str, str, str, Optional[str]]:
        if self._graph is None:
            raise RuntimeError(f"_keys() called on {self.rtdname} before resource was added to graph")
        return (
            self.kind,
            self.cloud().id,
            self.account().id,
            self.region().id,
            self.zone().id,
            self.dns_zone().id,
            self.id,
            self.safe_name,
            self.record_type,
            self.record_set_identifier,
        )

    @classmethod
    def service_name(cls) -> str:
        return service_name


resources: List[Type[AwsResource]] = [AwsRoute53Zone, AwsRoute53ResourceRecord, AwsRoute53ResourceRecordSet]
