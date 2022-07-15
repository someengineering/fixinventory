from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.resource.pricing import AwsPricingPrice, pricing_region
from test import aws_client, builder  # noqa: F401


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
