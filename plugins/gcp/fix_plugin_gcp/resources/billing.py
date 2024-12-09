from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attr import define, field

from fix_plugin_gcp.gcp_client import GcpApiSpec
from fix_plugin_gcp.resources.base import GcpResource, GcpDeprecationStatus, GraphBuilder
from fixlib.baseresources import ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend
from fixlib.types import Json

# This service is called Cloud Billing in the documentation
# https://cloud.google.com/billing/docs
# API https://googleapis.github.io/google-api-python-client/docs/dyn/cloudbilling_v1.html

service_name = "cloudbilling"


@define(eq=False, slots=False)
class GcpBillingAccount(GcpResource):
    kind: ClassVar[str] = "gcp_billing_account"
    _kind_display: ClassVar[str] = "GCP Billing Account"
    _kind_description: ClassVar[str] = "A GCP Billing Account is a financial entity in Google Cloud Platform that manages payment for services used across projects. It tracks costs, sets budgets, generates invoices, and handles payments. Users can associate multiple projects with a single billing account, view detailed usage reports, and configure alerts for spending thresholds."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/billing/docs/how-to/manage-billing-account"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "account", "group": "management"}
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_project_billing_info"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service=service_name,
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
    _kind_display: ClassVar[str] = "GCP Project Billing Info"
    _kind_description: ClassVar[str] = "GCP Project Billing Info provides detailed financial data for Google Cloud Platform projects. It displays current charges, past expenses, and usage breakdowns for services and resources. Users can view, analyze, and export billing information, set budget alerts, and manage payment methods. This feature helps organizations track costs and make informed decisions about cloud spending."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/billing/docs/how-to/get-project-billing-info"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "resource", "group": "management"}
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service=service_name,
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
    _kind_display: ClassVar[str] = "GCP Service"
    _kind_description: ClassVar[str] = "Google Cloud Platform (GCP) Service is a suite of cloud computing tools and infrastructure provided by Google. It offers computing, storage, networking, and data analytics capabilities. Users can deploy applications, manage databases, and process data using GCP's infrastructure. The service supports various programming languages and provides APIs for integration with other systems."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/docs"
    _kind_service: ClassVar[Optional[str]] = service_name
    _metadata: ClassVar[Dict[str, Any]] = {"icon": "service", "group": "management"}
    _reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["gcp_sku"]},
    }
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service=service_name,
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
    def collect(cls, raw: List[Json], builder: GraphBuilder) -> List[GcpResource]:
        # Additional behavior: iterate over list of collected GcpService and for each:
        # - collect related GcpSku
        SERVICES_COLLECT_LIST = [
            "Compute Engine",
        ]
        service_names: List[str] = []
        services = []
        for service in raw:
            if service.get("displayName") in SERVICES_COLLECT_LIST:
                service_names.append(str(service["name"]))
                services.append(service)
        result = super().collect(services, builder)

        for s_name in service_names:
            builder.submit_work(GcpSku.collect_resources, builder, parent=s_name)

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
    _kind_display: ClassVar[str] = "GCP SKU"
    _kind_description: ClassVar[str] = "GCP SKU (Google Cloud Platform Stock Keeping Unit) is a unique identifier for a specific product or service within Google Cloud. It represents a distinct billing unit for resources, features, or offerings. SKUs help users track and manage their cloud usage, costs, and resource allocation across different GCP services and configurations."  # fmt: skip
    _docs_url: ClassVar[str] = "https://cloud.google.com/skus"
    _kind_service: ClassVar[Optional[str]] = service_name
    api_spec: ClassVar[GcpApiSpec] = GcpApiSpec(
        service=service_name,
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


resources: List[Type[GcpResource]] = [GcpBillingAccount, GcpService]
