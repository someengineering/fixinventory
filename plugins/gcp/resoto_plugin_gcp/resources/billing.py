from typing import ClassVar, Dict, Optional, List

from attr import define, field

from resoto_plugin_gcp.gcp_client import GcpApiSpec
from resoto_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from resotolib.baseresources import ModelReference
from resotolib.json_bender import Bender, S, Bend, ForallBend
from resotolib.types import Json


@define(eq=False, slots=False)
class GcpBillingAccount(GcpResource):
    kind: ClassVar[str] = "gcp_billing_account"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["billingAccounts"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="billingAccounts",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "account_display_name": S("displayName"),
        "account_master_billing_account": S("masterBillingAccount"),
        "account_open": S("open"),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_project_billing_info"]},
    }

    account_display_name: Optional[str] = field(default=None)
    account_master_billing_account: Optional[str] = field(default=None)
    account_open: Optional[bool] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        for info in GcpProjectBillingInfo.collect_resources(graph_builder, name=self.name):
            graph_builder.add_edge(self, node=info)


@define(eq=False, slots=False)
class GcpProjectBillingInfo(GcpResource):
    kind: ClassVar[str] = "gcp_project_billing_info"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["billingAccounts", "projects"],
        action="list",
        request_parameter={"name": "{name}"},
        request_parameter_in={"name"},
        response_path="projectBillingInfo",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "info_billing_account_name": S("billingAccountName"),
        "info_billing_enabled": S("billingEnabled"),
        "info_project_id": S("projectId"),
    }
    info_billing_account_name: Optional[str] = field(default=None)
    info_billing_enabled: Optional[bool] = field(default=None)
    info_project_id: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpService(GcpResource):
    kind: ClassVar[str] = "gcp_service"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["services"],
        action="list",
        request_parameter={},
        request_parameter_in=set(),
        response_path="services",
        response_regional_sub_path=None,
    )
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id").or_else(S("name")).or_else(S("selfLink")),
        "tags": S("labels", default={}),
        "name": S("name"),
        "ctime": S("creationTimestamp"),
        "description": S("description"),
        "link": S("selfLink"),
        "label_fingerprint": S("labelFingerprint"),
        "deprecation_status": S("deprecated", default={}) >> Bend(GcpDeprecationStatus.mapping),
        "service_business_entity_name": S("businessEntityName"),
        "service_display_name": S("displayName"),
        "service_service_id": S("serviceId"),
    }
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_sku"]},
    }
    service_business_entity_name: Optional[str] = field(default=None)
    service_display_name: Optional[str] = field(default=None)
    service_service_id: Optional[str] = field(default=None)

    def post_process(self, graph_builder: GraphBuilder, source: Json) -> None:
        for sku in GcpSku.collect_resources(graph_builder, parent=self.id):
            graph_builder.add_edge(self, node=sku)


@define(eq=False, slots=False)
class GcpCategory:
    kind: ClassVar[str] = "gcp_category"
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
    mapping: ClassVar[Dict[str, Bender]] = {"regions": S("regions", default=[]), "type": S("type")}
    regions: List[str] = field(factory=list)
    type: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpAggregationInfo:
    kind: ClassVar[str] = "gcp_aggregation_info"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "start_usage_amount": S("startUsageAmount"),
        "unit_price": S("unitPrice", default={}) >> Bend(GcpMoney.mapping),
    }
    start_usage_amount: Optional[float] = field(default=None)
    unit_price: Optional[GcpMoney] = field(default=None)


@define(eq=False, slots=False)
class GcpPricingExpression:
    kind: ClassVar[str] = "gcp_pricing_expression"
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
    mapping: ClassVar[Dict[str, Bender]] = {
        "aggregation_info": S("aggregationInfo", default={}) >> Bend(GcpAggregationInfo.mapping),
        "currency_conversion_rate": S("currencyConversionRate"),
        "effective_time": S("effectiveTime"),
        "pricing_expression": S("pricingExpression", default={}) >> Bend(GcpPricingExpression.mapping),
        "summary": S("summary"),
    }
    aggregation_info: Optional[GcpAggregationInfo] = field(default=None)
    currency_conversion_rate: Optional[float] = field(default=None)
    effective_time: Optional[str] = field(default=None)
    pricing_expression: Optional[GcpPricingExpression] = field(default=None)
    summary: Optional[str] = field(default=None)


@define(eq=False, slots=False)
class GcpSku(GcpResource):
    kind: ClassVar[str] = "gcp_sku"
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service="cloudbilling",
        version="v1",
        accessors=["services", "skus"],
        action="list",
        request_parameter={"parent": "{parent}"},
        request_parameter_in={"parent"},
        response_path="skus",
        response_regional_sub_path=None,
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
        "sku_category": S("category", default={}) >> Bend(GcpCategory.mapping),
        "sku_geo_taxonomy": S("geoTaxonomy", default={}) >> Bend(GcpGeoTaxonomy.mapping),
        "sku_pricing_info": S("pricingInfo", default=[]) >> ForallBend(GcpPricingInfo.mapping),
        "sku_service_provider_name": S("serviceProviderName"),
        "sku_service_regions": S("serviceRegions", default=[]),
    }
    sku_category: Optional[GcpCategory] = field(default=None)
    sku_geo_taxonomy: Optional[GcpGeoTaxonomy] = field(default=None)
    sku_pricing_info: List[GcpPricingInfo] = field(factory=list)
    sku_service_provider_name: Optional[str] = field(default=None)
    sku_service_regions: List[str] = field(factory=list)


resources = [GcpBillingAccount, GcpService]
