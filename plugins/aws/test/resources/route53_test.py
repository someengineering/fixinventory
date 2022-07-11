from collections import defaultdict
from typing import Dict

from resoto_plugin_aws.resource.route53 import AwsRoute53Zone
from test.resources import round_trip


def test_hosted_zone() -> None:
    first, builder = round_trip("route53/list-hosted-zones.json", AwsRoute53Zone, "HostedZones")
    type_count: Dict[str, int] = defaultdict(int)
    for node in builder.graph.nodes:
        type_count[node.kind] += 1
    assert type_count["aws_route53_zone"] == 3
    assert type_count["aws_route53_resource_record_set"] == 2
    assert type_count["aws_route53_resource_record"] == 5
