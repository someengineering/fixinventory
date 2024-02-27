import json
from datetime import datetime
from functools import lru_cache
from typing import Any, ClassVar, Dict, List, Optional

from attr import field, frozen
from botocore.loaders import Loader
from fix_plugin_aws.aws_client import AwsClient

from fixlib.json import from_json
from fixlib.json_bender import Bend, Bender, F, ForallBend, MapDict, S, bend
from fixlib.types import Json
from fix_plugin_aws.utils import arn_partition_by_region

service_name = "pricing"

EBS_TO_PRICING_NAMES = {
    "standard": "Magnetic",
    "gp2": "General Purpose",
    "gp3": "General Purpose",
    "io1": "Provisioned IOPS",
    "st1": "Throughput Optimized HDD",
    "sc1": "Cold HDD",
}


@lru_cache(maxsize=None)
def partition_index() -> Dict[str, int]:
    """Return a mapping from partition name to partition index."""
    index_map = {}
    try:
        endpoints = Loader().load_data("endpoints")
    except Exception:
        pass
    else:
        for idx, partition in enumerate(endpoints.get("partitions", [])):
            regions = partition.get("regions", {}).keys()
            if "us-east-1" in regions:
                index_map["aws"] = idx
            elif "us-gov-west-1" in regions:
                index_map["aws-us-gov"] = idx
            elif "cn-north-1" in regions:
                index_map["aws-cn"] = idx
    return index_map


@lru_cache(maxsize=None)
def pricing_region(region: str) -> str:
    idx = partition_index().get(arn_partition_by_region(region), 0)
    endpoints = Loader().load_data("endpoints")
    name: Optional[str] = bend(S("partitions")[idx] >> S("regions", region, "description"), endpoints)
    if name is None:
        raise ValueError(f"Unknown pricing region: {region}")
    return name.replace("Europe", "EU")  # note: Europe is named differently in the price list


@frozen(eq=False)
class AwsPricingProduct:
    kind: ClassVar[str] = "aws_pricing_product"
    kind_display: ClassVar[str] = "AWS Pricing Product"
    kind_description: ClassVar[str] = (
        "AWS Pricing Product is a resource that provides information about the"
        " pricing of various Amazon Web Services products and services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "product_family": S("productFamily"),
        "sku": S("sku"),
        "attributes": S("attributes"),
    }
    product_family: Optional[str] = None
    attributes: Optional[Dict[str, str]] = field(default=None)
    sku: Optional[str] = None


@frozen(eq=False)
class AwsPricingPriceDimension:
    kind: ClassVar[str] = "aws_pricing_price_dimension"
    kind_display: ClassVar[str] = "AWS Pricing Price Dimension"
    kind_description: ClassVar[str] = (
        "Price Dimensions in AWS Pricing are the specific unit for which usage is"
        " measured and priced, such as per hour or per GB."
    )
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
    kind_display: ClassVar[str] = "AWS Pricing Term"
    kind_description: ClassVar[str] = (
        "AWS Pricing Terms refer to the different pricing options and payment plans"
        " available for services on the Amazon Web Services platform."
    )
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
    kind_display: ClassVar[str] = "AWS Pricing Price"
    kind_description: ClassVar[str] = (
        "AWS Pricing Price refers to the cost associated with using various AWS"
        " services and resources. It includes charges for compute, storage, network"
        " usage, data transfer, and other services provided by Amazon Web Services."
    )
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
        # Prices are only available in the global region
        prices = client.global_region.list(
            service_name, "get-products", "PriceList", ServiceCode=service_code, Filters=search_filter, MaxResults=1
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
