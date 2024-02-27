from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, cast

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fixlib.baseresources import ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json

# This service is called Cloud Billing in the documentation
# https://cloud.google.com/billing/docs
# API https://googleapis.github.io/google-api-python-client/docs/dyn/cloudbilling_v1.html


@define(eq=False, slots=False)
class GcpBillingAccount(GcpResource):
    kind: ClassVar[str] = "gcp_billing_account"
    kind_display: ClassVar[str] = "GCP Billing Account"
    kind_description: ClassVar[str] = (
        "GCP Billing Account is a financial account used to manage the payment and"
        " billing information for Google Cloud Platform services."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_project_billing_info"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["billingAccounts"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="billingAccounts",
        response_regional_sub_path=None,
        required_iam_permissions=[],  # does not require any permissions
        mutate_iam_permissions=[],  # can not be deleted
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
        "display_name": S("displayName"),
        "master_billing_account": S("masterBillingAccount"),
        "open": S("open"),
    }

    display_name: Optional[str] = field(default=None)
    master_billing_account: Optional[str] = field(default=None)
    open: Optional[bool] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        for info in GcpProjectBillingInfo.collect_resources(graph_builder, name=self.name):
            graph_builder.add_edge(self, node=info)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [cls.api_spec, GcpProjectBillingInfo.api_spec]


@define(eq=False, slots=False)
class GcpProjectBillingInfo(GcpResource):
    kind: ClassVar[str] = "gcp_project_billing_info"
    kind_display: ClassVar[str] = "GCP Project Billing Info"
    kind_description: ClassVar[str] = (
        "GCP Project Billing Info provides information and management capabilities"
        " for the billing aspects of a Google Cloud Platform project."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["billingAccounts", "projects"],
        action="list",
        request_parameter={"name": "{name}"},
        request_parameter_in={"name"},
        response_path="projectBillingInfo",
        response_regional_sub_path=None,
        # valid permission name according to documentation, but gcloud emits an error
        # required_iam_permissions=["billing.resourceAssociations.list"],
        required_iam_permissions=[],
        mutate_iam_permissions=["billing.resourceAssociations.delete"],
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
        "billing_account_name": S("billingAccountName"),
        "billing_enabled": S("billingEnabled"),
        "project_billing_info_project_id": S("projectId"),
    }
    billing_account_name: Optional[str] = field(default=None)
    billing_enabled: Optional[bool] = field(default=None)
    project_billing_info_project_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpService(GcpResource):
    kind: ClassVar[str] = "gcp_service"
    kind_display: ClassVar[str] = "GCP Service"
    kind_description: ClassVar[str] = (
        "GCP Service refers to any of the various services and products offered by"
        " Google Cloud Platform, which provide scalable cloud computing solutions for"
        " businesses and developers."
    )
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_sku"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["services"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="services",
        response_regional_sub_path=None,
        required_iam_permissions=[],  # does not require any permissions
        mutate_iam_permissions=[],  # can not be deleted
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("serviceId"),
        "tags": S("labels", default={}),
        "name": S("name"),
        "display_name": S("displayName"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "business_entity_name": S("businessEntityName"),
    }

    business_entity_name: Optional[str] = field(default=None)
    display_name: Optional[str] = field(default=None)

    @classmethod
    def collect(cls: Type[GcpResource], raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpService and for each:
        # - collect related GcpSku
        result: List[GcpResource] = super().collect(raw, builder)  # type: ignore
        SERVICES_COLLECT_LIST = [
            "Compute Engine",
        ]
        service_names = [
            service.name for service in cast(List[GcpService], result) if service.display_name in SERVICES_COLLECT_LIST
        ]
        for service_name in service_names:
            builder.submit_work(GcpSku.collect_resources, builder, parent=service_name)

        return result

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        def filter(node: GcpResource) -> bool:
            return isinstance(node, GcpSku) and node.name is not None and node.name.startswith(self.id)

        builder.add_edges(self, filter=filter)

    @classmethod
    def called_collect_apis(cls) -> List[GcpApiSpec]:
        return [cls.api_spec, GcpSku.api_spec]


@define(eq=False, slots=False)
class GcpCategory:
    kind: ClassVar[str] = "gcp_category"
    kind_display: ClassVar[str] = "GCP Category"
    kind_description: ClassVar[str] = (
        "GCP Category is a classification system used by Google Cloud Platform to"
        " organize various cloud resources and services into different categories."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "resource_family": S("resourceFamily"),
        "resource_group": S("resourceGroup"),
        "service_display_name": S("serviceDisplayName"),
        "usage_type": S("usageType"),
    }
    resource_family: Optional[str] = field(default=None)
    resource_group: Optional[str] = field(default=None)
    service_display_name: Optional[str] = field(default=None)
    usage_type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpGeoTaxonomy:
    kind: ClassVar[str] = "gcp_geo_taxonomy"
    kind_display: ClassVar[str] = "GCP Geo Taxonomy"
    kind_description: ClassVar[str] = (
        "GCP Geo Taxonomy within a SKU refers to the classification of Google Cloud resources"
        " based on geographic regions and types, which impacts pricing and availability."
    )
    mapping: ClassVar[Dict[str, Bender]] = {"regions": S("regions", default=[]), "type": S("type")}
    regions: List[str] = field(factory=list)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAggregationInfo:
    kind: ClassVar[str] = "gcp_aggregation_info"
    kind_display: ClassVar[str] = "GCP Aggregation Info"
    kind_description: ClassVar[str] = (
        "GCP Aggregation Info refers to how usage and cost data are compiled and summarized over time."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregation_count": S("aggregationCount"),
        "aggregation_interval": S("aggregationInterval"),
        "aggregation_level": S("aggregationLevel"),
    }
    aggregation_count: Optional[int] = field(default=None)
    aggregation_interval: Optional[str] = field(default=None)
    aggregation_level: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpMoney:
    kind: ClassVar[str] = "gcp_money"
    kind_display: ClassVar[str] = "GCP Money"
    kind_description: ClassVar[str] = (
        "In GCP's Money structure, amounts are represented using a currency_code for the type of currency,"
        " and nanos to denote a fraction of that currency down to one-billionth, ensuring precise"
        " financial calculations."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "currency_code": S("currencyCode"),
        "nanos": S("nanos"),
        "units": S("units"),
    }
    currency_code: Optional[str] = field(default=None)
    nanos: Optional[int] = field(default=None)
    units: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpTierRate:
    kind: ClassVar[str] = "gcp_tier_rate"
    kind_display: ClassVar[str] = "GCP Tier Rate"
    kind_description: ClassVar[str] = (
        "GCP Tier Rate refers to the pricing tiers for different levels of usage of"
        " Google Cloud Platform services. Higher tiers typically offer discounted"
        " rates for increased usage volumes."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "start_usage_amount": S("startUsageAmount"),
        "unit_price": S("unitPrice", default={}) >> Bend(GcpMoney.mapping),
    }
    start_usage_amount: Optional[float] = field(default=None)
    unit_price: Optional[GcpMoney] = field(default=None)


@define(eq=False, slots=False)
class GcpPricingExpression:
    kind: ClassVar[str] = "gcp_pricing_expression"
    kind_display: ClassVar[str] = "GCP Pricing Expression"
    kind_description: ClassVar[str] = (
        "GCP Pricing Expression delineates the structure of pricing for a particular service, including the base"
        " units of measurement, conversion factors, detailed descriptions, and tiered pricing rates to calculate"
        " the cost based on usage."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "base_unit": S("baseUnit"),
        "base_unit_conversion_factor": S("baseUnitConversionFactor"),
        "base_unit_description": S("baseUnitDescription"),
        "display_quantity": S("displayQuantity"),
        "tiered_rates": S("tieredRates", default=[]) >> ForallBend(GcpTierRate.mapping),
        "usage_unit": S("usageUnit"),
        "usage_unit_description": S("usageUnitDescription"),
    }
    base_unit: Optional[str] = field(default=None)
    base_unit_conversion_factor: Optional[float] = field(default=None)
    base_unit_description: Optional[str] = field(default=None)
    display_quantity: Optional[float] = field(default=None)
    tiered_rates: List[GcpTierRate] = field(factory=list)
    usage_unit: Optional[str] = field(default=None)
    usage_unit_description: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpPricingInfo:
    kind: ClassVar[str] = "gcp_pricing_info"
    kind_display: ClassVar[str] = "GCP Pricing Info"
    kind_description: ClassVar[str] = (
        "GCP Pricing Info provides information on the pricing models and costs"
        " associated with using Google Cloud Platform services."
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregation_info": S("aggregationInfo", default={}) >> Bend(GcpAggregationInfo.mapping),
        "currency_conversion_rate": S("currencyConversionRate"),
        "effective_time": S("effectiveTime"),
        "pricing_expression": S("pricingExpression", default={}) >> Bend(GcpPricingExpression.mapping),
        "summary": S("summary"),
    }
    aggregation_info: Optional[GcpAggregationInfo] = field(default=None)
    currency_conversion_rate: Optional[float] = field(default=None)
    effective_time: Optional[datetime] = field(default=None)
    pricing_expression: Optional[GcpPricingExpression] = field(default=None)
    summary: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSku(GcpResource):
    kind: ClassVar[str] = "gcp_sku"
    kind_display: ClassVar[str] = "GCP SKU"
    kind_description: ClassVar[str] = (
        "GCP SKU represents a Stock Keeping Unit in Google Cloud Platform, providing"
        " unique identifiers for different resources and services."
    )
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["services", "skus"],
        action="list",
        request_parameter={"parent": "{parent}"},
        request_parameter_in={"parent"},
        response_path="skus",
        response_regional_sub_path=None,
        required_iam_permissions=[],  # does not require any permissions
        mutate_iam_permissions=[],  # can not be deleted
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("skuId"),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "category": S("category", default={}) >> Bend(GcpCategory.mapping),
        "geo_taxonomy": S("geoTaxonomy", default={}) >> Bend(GcpGeoTaxonomy.mapping),
        "sku_pricing_info": S("pricingInfo", default=[]) >> ForallBend(GcpPricingInfo.mapping),
        "service_provider_name": S("serviceProviderName"),
        "service_regions": S("serviceRegions", default=[]),
        "sku_id": S("skuId"),
    }
    category: Optional[GcpCategory] = field(default=None)
    geo_taxonomy: Optional[GcpGeoTaxonomy] = field(default=None)
    sku_pricing_info: List[GcpPricingInfo] = field(factory=list)
    service_provider_name: Optional[str] = field(default=None)
    service_regions: List[str] = field(factory=list)
    usage_unit_nanos: Optional[int] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        if len(self.sku_pricing_info) > 0:
            if not (pricing_expression := self.sku_pricing_info[0].pricing_expression):
                return

            tiered_rates = pricing_expression.tiered_rates
            cost = -1
            if len(tiered_rates) == 1:
                if tiered_rates[0].unit_price and tiered_rates[0].unit_price.nanos:
                    cost = tiered_rates[0].unit_price.nanos

            else:
                for tiered_rate in tiered_rates:
                    if sua := tiered_rate.start_usage_amount:
                        if sua > 0:
                            if tiered_rate.unit_price and tiered_rate.unit_price.nanos:
                                cost = tiered_rate.unit_price.nanos
                                break
            if cost > -1:
                self.usage_unit_nanos = cost


resources = [GcpBillingAccount, GcpService]
