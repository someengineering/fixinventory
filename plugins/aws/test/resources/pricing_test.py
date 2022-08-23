from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.pricing import AwsPricingPrice, pricing_region
from resotolib.json import to_json, from_json
from test import aws_client, builder, aws_config  # noqa: F401


def test_json_serialization(aws_client: AwsClient) -> None:
    price = AwsPricingPrice.instance_type_price(aws_client, "m4.large", "us-east-1")
    assert price
    again = from_json(to_json(price), AwsPricingPrice)
    assert to_json(price) == to_json(again)


def test_price_region() -> None:
    assert pricing_region("us-east-1") == "US East (N. Virginia)"
    assert pricing_region("eu-central-1") == "EU (Frankfurt)"


def test_instance_type_pricing(aws_client: AwsClient) -> None:
    price = AwsPricingPrice.instance_type_price(aws_client, "m4.large", "us-east-1")
    assert price is not None
    assert price.on_demand_price_usd == 0.051


def test_volume_type_pricing(aws_client: AwsClient) -> None:
    price = AwsPricingPrice.volume_type_price(aws_client, "gp2", "us-east-1")
    assert price is not None
    assert price.on_demand_price_usd == 0.119
