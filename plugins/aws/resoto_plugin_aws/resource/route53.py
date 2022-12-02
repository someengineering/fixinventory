from typing import ClassVar, Dict, Optional, List, Type, cast

from attrs import define, field
from resoto_plugin_aws.aws_client import AwsClient

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from resoto_plugin_aws.utils import ToDict

from resotolib.baseresources import (
    BaseDNSZone,
    BaseDNSRecord,
    EdgeType,
    BaseDNSRecordSet,
    ModelReference,
)
from resotolib.json_bender import F, Bender, S, Bend, ForallBend, bend
from resotolib.types import Json
from resotolib.utils import rrdata_as_dict


@define(eq=False, slots=False)
class AwsRoute53ZoneConfig:
    kind: ClassVar[str] = "aws_route53_zone_config"
    mapping: ClassVar[Dict[str, Bender]] = {"comment": S("Comment"), "private_zone": S("PrivateZone")}
    comment: Optional[str] = field(default=None)
    private_zone: Optional[bool] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53LinkedService:
    kind: ClassVar[str] = "aws_route53_linked_service"
    mapping: ClassVar[Dict[str, Bender]] = {"service_principal": S("ServicePrincipal"), "description": S("Description")}
    service_principal: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53Zone(AwsResource, BaseDNSZone):
    kind: ClassVar[str] = "aws_route53_zone"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("route53", "list-hosted-zones", "HostedZones")
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
    zone_resource_record_set_count: Optional[int] = field(default=None)
    zone_linked_service: Optional[AwsRoute53LinkedService] = field(default=None)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            cls.api_spec,
            AwsApiSpec("route53", "list-resource-record-sets"),
            AwsApiSpec("route53", "list-tags-for-resource"),
        ]

    @classmethod
    def collect(cls: Type[AwsResource], json: List[Json], builder: GraphBuilder) -> None:
        def add_tags(zone: AwsRoute53Zone) -> None:
            tags = builder.client.get(
                "route53",
                "list-tags-for-resource",
                result_name="ResourceTagSet",
                ResourceType="hostedzone",
                ResourceId=zone.id,
            )
            if tags:
                zone.tags = bend(S("Tags", default=[]) >> ToDict(), tags)

        for js in json:
            zone: AwsRoute53Zone = cast(AwsRoute53Zone, cls.from_api(js))
            builder.add_node(zone, js)
            builder.submit_work(add_tags, zone)
            for rs_js in builder.client.list(
                "route53", "list-resource-record-sets", "ResourceRecordSets", HostedZoneId=zone.id
            ):
                record_set = AwsRoute53ResourceRecordSet.from_api(rs_js)
                builder.add_node(record_set, rs_js)
                builder.add_edge(zone, EdgeType.default, node=record_set)
                for data in record_set.record_values:
                    record = AwsRoute53ResourceRecord(
                        id=record_set.id,
                        name=record_set.name,
                        record_type=record_set.record_type,
                        record_ttl=record_set.record_ttl or 0,
                        record_data=data,
                        **rrdata_as_dict(record_set.record_type, data),
                    )
                    builder.add_node(record, js)
                    builder.add_edge(record_set, EdgeType.default, node=record)
                    builder.add_edge(record_set, EdgeType.delete, node=record)

    def update_resource_tag(self, client: AwsClient, key: str, value: str) -> bool:
        client.call(
            aws_service="route53",
            action="change-tags-for-resource",
            result_name=None,
            ResourceType="hostedzone",
            ResourceId=self.id,
            AddTags=[{"Key": key, "Value": value}],
        )
        return True

    def delete_resource_tag(self, client: AwsClient, key: str) -> bool:
        client.call(
            aws_service="route53",
            action="change-tags-for-resource",
            result_name=None,
            ResourceType="hostedzone",
            ResourceId=self.id,
            RemoveTagKeys=[key],
        )
        return True

    def delete_resource(self, client: AwsClient) -> bool:
        client.call(aws_service="route53", action="delete-hosted-zone", result_name=None, Id=self.id.rsplit("/", 1)[-1])
        return True

    @classmethod
    def called_mutator_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec("route53", "change-tags-for-resource"),
            AwsApiSpec("route53", "delete-hosted-zone"),
        ]


@define(eq=False, slots=False)
class AwsRoute53GeoLocation:
    kind: ClassVar[str] = "aws_route53_geo_location"
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
    mapping: ClassVar[Dict[str, Bender]] = {"collection_id": S("CollectionId"), "location_name": S("LocationName")}
    collection_id: Optional[str] = field(default=None)
    location_name: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class AwsRoute53ResourceRecord(AwsResource, BaseDNSRecord):
    kind: ClassVar[str] = "aws_route53_resource_record"
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {
            "default": [],
            "delete": [],
        }
    }


@define(eq=False, slots=False)
class AwsRoute53ResourceRecordSet(AwsResource, BaseDNSRecordSet):
    kind: ClassVar[str] = "aws_route53_resource_record_set"
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


resources: List[Type[AwsResource]] = [AwsRoute53Zone, AwsRoute53ResourceRecord, AwsRoute53ResourceRecordSet]
