import json
from datetime import datetime
from functools import lru_cache
from typing import ClassVar, Dict, Optional, List, Any

from attr import field, frozen
from botocore.loaders import Loader

from resoto_plugin_aws.aws_client import AwsClient
from resotolib.json import from_json
from resotolib.json_bender import Bender, S, Bend, MapDict, F, ForallBend, bend
from resotolib.types import Json

EBS_TO_PRICING_NAMES = {
    "standard": "Magnetic",
    "gp2": "General Purpose",
    "gp3": "General Purpose",
    "io1": "Provisioned IOPS",
    "st1": "Throughput Optimized HDD",
    "sc1": "Cold HDD",
}


@lru_cache(maxsize=None)
def pricing_region(region: str) -> str:
    endpoints = Loader().load_data("endpoints")
    name: Optional[str] = bend(S("partitions")[0] >> S("regions", region, "description"), endpoints)
    if name is None:
        raise ValueError(f"Unknown pricing region: {region}")
    return name.replace("Europe", "EU")  # note: Europe is named differently in the price list


@frozen(eq=False)
class AwsPricingProduct:
    kind: ClassVar[str] = "aws_pricing_product"
    mapping: ClassVar[Dict[str, Bender]] = {
        "product_family": S("productFamily"),
        "sku": S("sku"),
        "attributes": S("attributes"),
    }
    product_family: Optional[str] = None
    attributes: Dict[str, str] = field(factory=dict)
    sku: Optional[str] = None


@frozen(eq=False)
class AwsPricingPriceDimension:
    kind: ClassVar[str] = "aws_pricing_price_dimension"
    mapping: ClassVar[Dict[str, Bender]] = {
        "unit": S("unit"),
        "end_range": S("endRange"),
        "description": S("description"),
        "applies_to": S("appliesTo"),
        "rate_code": S("rateCode"),
        "begin_range": S("beginRange"),
        "price_per_unit": S("pricePerUnit") >> MapDict(value_bender=F(float)),
    }
    unit: Optional[str] = None
    end_range: Optional[str] = None
    description: Optional[str] = None
    applies_to: List[Any] = field(factory=list)
    rate_code: Optional[str] = None
    begin_range: Optional[str] = None
    price_per_unit: Dict[str, float] = field(factory=dict)


@frozen(eq=False)
class AwsPricingTerm:
    kind: ClassVar[str] = "aws_pricing_term"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sku": S("sku"),
        "effective_date": S("effectiveDate"),
        "offer_term_code": S("offerTermCode"),
        "term_attributes": S("termAttributes"),
        "price_dimensions": S("priceDimensions")
        >> F(lambda x: list(x.values()))
        >> ForallBend(AwsPricingPriceDimension.mapping),
    }
    sku: Optional[str] = None
    effective_date: Optional[datetime] = None
    offer_term_code: Optional[str] = None
    term_attributes: Dict[str, str] = field(factory=dict)
    price_dimensions: List[AwsPricingPriceDimension] = field(factory=list)


@frozen(eq=False)
class AwsPricingPrice:
    kind: ClassVar[str] = "aws_pricing_price"
    mapping: ClassVar[Dict[str, Bender]] = {
        "product": S("product") >> Bend(AwsPricingProduct.mapping),
        "service_code": S("serviceCode"),
        "terms": S("terms")
        >> MapDict(
            value_bender=F(lambda x: list(x.values()) if isinstance(x, dict) else [])
            >> ForallBend(AwsPricingTerm.mapping)
        ),
    }
    product: Optional[AwsPricingProduct] = None
    service_code: Optional[str] = None
    terms: Dict[str, List[AwsPricingTerm]] = field(factory=dict)

    @property
    def on_demand_price_usd(self) -> float:
        if terms := self.terms.get("OnDemand", []):
            if dim := terms[0].price_dimensions:
                return dim[0].price_per_unit.get("USD", 0)
        return 0

    @classmethod
    def single_price_for(
        cls, client: AwsClient, service_code: str, search_filter: List[Json]
    ) -> "Optional[AwsPricingPrice]":
        # Prices are only available in us-east-1
        prices = client.global_region.list(
            "pricing", "get-products", "PriceList", ServiceCode=service_code, Filters=search_filter, MaxResults=1
        )
        return from_json(bend(cls.mapping, json.loads(prices[0])), AwsPricingPrice) if prices else None

    @classmethod
    def volume_type_price(cls, client: AwsClient, volume_type: str, region: str) -> "Optional[AwsPricingPrice]":
        if volume_type not in EBS_TO_PRICING_NAMES:
            return None
        search_filter = [
            {"Type": "TERM_MATCH", "Field": "volumeType", "Value": EBS_TO_PRICING_NAMES[volume_type]},
            {"Type": "TERM_MATCH", "Field": "volumeApiName", "Value": volume_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": pricing_region(region)},
        ]
        return cls.single_price_for(client, "AmazonEC2", search_filter)

    @classmethod
    def instance_type_price(cls, client: AwsClient, instance_type: str, region: str) -> "Optional[AwsPricingPrice]":
        search_filter = [
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "operation", "Value": "RunInstances"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": pricing_region(region)},
        ]
        return cls.single_price_for(client, "AmazonEC2", search_filter)


resources = [AwsPricingPrice]
