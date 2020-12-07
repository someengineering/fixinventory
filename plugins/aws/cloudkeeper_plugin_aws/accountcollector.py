import botocore.exceptions
import concurrent.futures
import networkx
import cloudkeeper.logging
import socket
import urllib3
import json
import re
from functools import lru_cache
from threading import Lock
from collections.abc import Mapping
from cloudkeeper.args import ArgumentParser
from cloudkeeper.graph import Graph
from cloudkeeper.utils import make_valid_timestamp, chunks, get_resource_attributes
from .utils import aws_session, paginate
from .resources import *
from prometheus_client import Summary, Counter
from pkg_resources import resource_filename
from typing import List, Optional, Dict, Tuple
from retrying import retry
from pprint import pformat


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


# boto3 has no way of converting between short and long region names
# The pricing API expects long region names, whereas ever other API works with short region names.
# The mapping can be found in one of the SDK's resource files 'endpoints.json' from where we read it.
endpoint_file = resource_filename("botocore", "data/endpoints.json")
with open(endpoint_file, "r") as f:
    endpoints = json.load(f)
EC2_TO_PRICING_REGIONS = {
    k: v["description"]
    for k, v in next(iter(endpoints.get("partitions", [])), {})
    .get("regions", {})
    .items()
}

# Again the pricing API uses slightly different tenancy names than all the other APIs.
# This static mapping translates between them.
PRICING_TO_EC2_TENANCY = {"Shared": "default", "Host": "host", "Dedicated": "dedicated"}

EBS_TO_PRICING_NAMES = {
    "standard": "Magnetic",
    "gp2": "General Purpose",
    "io1": "Provisioned IOPS",
    "st1": "Throughput Optimized HDD",
    "sc1": "Cold HDD",
}

# This dict maps from quota names to service names.
# If the key is a string we try to match it directly.
# If the key is a re.Pattern we'll try to match that. If it's value is of type int we'll map to that group number
# otherwise we'll use the string value as the key in the resulting map.
QUOTA_TO_SERVICE_MAP = {
    "ebs": {
        "General Purpose (SSD) volume storage": "gp2",
        "Magnetic volume storage": "standard",
        "Max Cold HDD (SC1) Storage": "sc1",
        "Max Throughput Optimized HDD (ST1) Storage": "st1",
        "Provisioned IOPS (SSD) volume storage": "io1",
        "Number of EBS snapshots": "snapshots",
        "Provisioned IOPS": "iops",
    },
    "vpc": {"Internet gateways per Region": "igw", "VPCs per Region": "vpc"},
    "ec2": {
        "Total running On-Demand instances": "total",
        "Running On-Demand F instances": "f_ondemand",
        "Running On-Demand G instances": "g_ondemand",
        "Running On-Demand Inf instances": "inf_ondemand",
        "Running On-Demand P instances": "p_ondemand",
        "Running On-Demand X instances": "x_ondemand",
        "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances": "standard_ondemand",
        re.compile("Running On-Demand (.*) hosts"): 1,
    },
    "elasticloadbalancing": {
        "Application Load Balancers per Region": "alb",
        "Classic Load Balancers per Region": "elb",
    },
    "s3": {},
    "iam": {
        "Access keys per user": "access_keys_per_user",
        "Groups per account": "groups",
        "Customer managed policies per account": "policies",
        "Instance profiles per account": "instance_profiles",
        "Roles per account": "roles",
        "Server certificates per account": "server_certificates",
        "Users per account": "users",
    },
}

metrics_unhandled_collector_exceptions = Counter(
    "cloudkeeper_plugin_aws_unhandled_collector_exceptions_total",
    "Unhandled AWS Plugin Collector Exceptions",
    ["account", "region", "collector"],
)
metrics_collect_vpcs = Summary(
    "cloudkeeper_plugin_aws_collect_vpcs_seconds",
    "Time it took the collect_vpcs() method",
)
metrics_collect_subnets = Summary(
    "cloudkeeper_plugin_aws_collect_subnets_seconds",
    "Time it took the collect_subnets() method",
)
metrics_collect_route_tables = Summary(
    "cloudkeeper_plugin_aws_collect_route_tables_seconds",
    "Time it took the collectroute_tables() method",
)
metrics_collect_security_groups = Summary(
    "cloudkeeper_plugin_aws_collect_security_groups_seconds",
    "Time it took the collect_security_groups() method",
)
metrics_collect_internet_gateways = Summary(
    "cloudkeeper_plugin_aws_collect_internet_gateways_seconds",
    "Time it took the collect_internet_gateways() method",
)
metrics_collect_instances = Summary(
    "cloudkeeper_plugin_aws_collect_instances_seconds",
    "Time it took the collect_instances() method",
)
metrics_collect_keypairs = Summary(
    "cloudkeeper_plugin_aws_collect_keypairs_seconds",
    "Time it took the collect_keypairs() method",
)
metrics_collect_autoscaling_groups = Summary(
    "cloudkeeper_plugin_aws_collect_autoscaling_groups_seconds",
    "Time it took the collect_autoscaling_groups() method",
)
metrics_collect_reserved_instances = Summary(
    "cloudkeeper_plugin_aws_collect_reserved_instances_seconds",
    "Time it took the collect_reserved_instances() method",
)
metrics_collect_volumes = Summary(
    "cloudkeeper_plugin_aws_collect_volumes_seconds",
    "Time it took the collect_volumes() method",
)
metrics_collect_snapshots = Summary(
    "cloudkeeper_plugin_aws_collect_snapshots_seconds",
    "Time it took the collect_snapshots() method",
)
metrics_collect_volume_metrics = Summary(
    "cloudkeeper_plugin_aws_collect_volume_metrics_seconds",
    "Time it took the collect_volume_metrics() method",
)
metrics_collect_network_interfaces = Summary(
    "cloudkeeper_plugin_aws_collect_network_interfaces_seconds",
    "Time it took the collect_network_interfaces() method",
)
metrics_collect_network_acls = Summary(
    "cloudkeeper_plugin_aws_collect_network_acls_seconds",
    "Time it took the collect_network_acls() method",
)
metrics_collect_nat_gateways = Summary(
    "cloudkeeper_plugin_aws_collect_nat_gateways_seconds",
    "Time it took the collect_nat_gateways() method",
)
metrics_collect_vpc_peering_connections = Summary(
    "cloudkeeper_plugin_aws_collect_vpc_peering_connections_seconds",
    "Time it took the collect_vpc_peering_connections() method",
)
metrics_collect_vpc_endpoints = Summary(
    "cloudkeeper_plugin_aws_collect_vpc_endpoints_seconds",
    "Time it took the collect_vpc_endpoints() method",
)
metrics_collect_buckets = Summary(
    "cloudkeeper_plugin_aws_collect_buckets_seconds",
    "Time it took the collect_buckets() method",
)
metrics_collect_s3_buckets = Summary(
    "cloudkeeper_plugin_aws_collect_s3_buckets_seconds",
    "Time it took the collect_s3_buckets() method",
)
metrics_collect_elbs = Summary(
    "cloudkeeper_plugin_aws_collect_elbs_seconds",
    "Time it took the collect_elbs() method",
)
metrics_collect_alb_target_groups = Summary(
    "cloudkeeper_plugin_aws_collect_alb_target_groups_seconds",
    "Time it took the collect_alb_target_groups() method",
)
metrics_collect_albs = Summary(
    "cloudkeeper_plugin_aws_collect_albs_seconds",
    "Time it took the collect_albs() method",
)
metrics_collect_rds_instances = Summary(
    "cloudkeeper_plugin_aws_collect_rds_instances_seconds",
    "Time it took the collect_rds_instances() method",
)
metrics_collect_rds_metrics = Summary(
    "cloudkeeper_plugin_aws_collect_rds_metrics_seconds",
    "Time it took the collect_rds_metrics() method",
)
metrics_collect_iam_policies = Summary(
    "cloudkeeper_plugin_aws_collect_iam_policies_seconds",
    "Time it took the collect_iam_policies() method",
)
metrics_collect_iam_groups = Summary(
    "cloudkeeper_plugin_aws_collect_iam_groups_seconds",
    "Time it took the collect_iam_groups() method",
)
metrics_collect_iam_instance_profiles = Summary(
    "cloudkeeper_plugin_aws_collect_iam_instance_profiles_seconds",
    "Time it took the collect_iam_instance_profiles() method",
)
metrics_collect_iam_roles = Summary(
    "cloudkeeper_plugin_aws_collect_iam_roles_seconds",
    "Time it took the collect_iam_roles() method",
)
metrics_collect_iam_users = Summary(
    "cloudkeeper_plugin_aws_collect_iam_users_seconds",
    "Time it took the collect_iam_users() method",
)
metrics_collect_iam_server_certificates = Summary(
    "cloudkeeper_plugin_aws_collect_iam_server_certificates_seconds",
    "Time it took the collect_iam_server_certificates() method",
)
metrics_collect_cloudformation_stacks = Summary(
    "cloudkeeper_plugin_aws_collect_cloudformation_stacks_seconds",
    "Time it took the collect_cloudformation_stacks() method",
)
metrics_collect_eks_clusters = Summary(
    "cloudkeeper_plugin_aws_collect_eks_clusters_seconds",
    "Time it took the collect_eks_clusters() method",
)
metrics_collect_elastic_ips = Summary(
    "cloudkeeper_plugin_aws_collect_elastic_ips_seconds",
    "Time it took the collect_elastic_ips() method",
)
metrics_get_eks_nodegroups = Summary(
    "cloudkeeper_plugin_aws_get_eks_nodegroups_seconds",
    "Time it took the get_eks_nodegroups() method",
)


def retry_on_request_limit_exceeded(e):
    if isinstance(e, botocore.exceptions.ClientError):
        if e.response["Error"]["Code"] in ("RequestLimitExceeded", "Throttling"):
            log.debug(
                "AWS API request limit exceeded or throttling, retrying with exponential backoff"
            )
            return True
    return False


class AWSAccountCollector:
    def __init__(self, regions: List, account: AWSAccount) -> None:
        self.regions = [AWSRegion(region, {}, account=account) for region in regions]
        self.account = account
        self.root = self.account
        self.graph = Graph()
        resource_attr = get_resource_attributes(self.root)
        self.graph.add_node(self.root, label=self.root.name, **resource_attr)

        # The pricing info is being used to cache the results of pricing information. This way we don't ask
        # the API 10 times what the price of an e.g. m5.xlarge instance is. The lock is being used to ensure
        # we're not doing multiple identical calls while fetching instance information in parallel threads.
        self._price_info = {"ec2": {}, "ebs": {}}
        self._price_info_lock = Lock()

        self.global_collectors = {
            "iam_policies": self.collect_iam_policies,
            "iam_groups": self.collect_iam_groups,
            "iam_instance_profiles": self.collect_iam_instance_profiles,
            "iam_roles": self.collect_iam_roles,
            "iam_users": self.collect_iam_users,
            "iam_server_certificates": self.collect_iam_server_certificates,
            "s3_buckets": self.collect_s3_buckets,
        }
        self.region_collectors = {
            "reserved_instances": self.collect_reserved_instances,
            "vpcs": self.collect_vpcs,
            "subnets": self.collect_subnets,
            "route_tables": self.collect_route_tables,
            "security_groups": self.collect_security_groups,
            "internet_gateways": self.collect_internet_gateways,
            "keypairs": self.collect_keypairs,
            "instances": self.collect_instances,
            "volumes": self.collect_volumes,
            "snapshots": self.collect_snapshots,
            "elbs": self.collect_elbs,
            "albs": self.collect_albs,
            "alb_target_groups": self.collect_alb_target_groups,
            "autoscaling_groups": self.collect_autoscaling_groups,
            "network_acls": self.collect_network_acls,
            "network_interfaces": self.collect_network_interfaces,
            "nat_gateways": self.collect_nat_gateways,
            "rds_instances": self.collect_rds_instances,
            "cloudformation_stacks": self.collect_cloudformation_stacks,
            "eks_clusters": self.collect_eks_clusters,
            "vpc_peering_connections": self.collect_vpc_peering_connections,
            "vpc_endpoints": self.collect_vpc_endpoints,
            "elastic_ips": self.collect_elastic_ips,
        }
        self.collector_set = set(self.global_collectors.keys()).union(
            set(self.region_collectors.keys())
        )

    def collect(self) -> None:
        account_alias = self.account_alias()
        if account_alias:
            self.account.name = self.account.account_alias = account_alias

        collectors = self.collector_set
        if len(ArgumentParser.args.aws_collect) > 0:
            collectors = set(ArgumentParser.args.aws_collect).intersection(
                self.collector_set
            )
        log.debug(
            f"Running the following collectors in account {self.account.dname}: {', '.join(collectors)}"
        )

        # Collect global resources like IAM and S3 first
        global_region = AWSRegion("us-east-1", {}, name="global", account=self.account)
        graph = self.collect_resources(self.global_collectors, global_region)
        log.debug(f"Adding graph of region {global_region.name} to account graph")
        self.graph = networkx.compose(self.graph, graph)
        self.graph.add_edge(self.root, global_region)

        # Collect regions in parallel after global resources have been collected
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=ArgumentParser.args.aws_region_pool_size,
            thread_name_prefix=f"aws_{self.account.id}",
        ) as executor:
            futures = {
                executor.submit(
                    self.collect_resources, self.region_collectors, region
                ): region
                for region in self.regions
            }
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    graph = future.result()
                except Exception:
                    log.exception(
                        (
                            f"Unhandeled exception while collecting resources in "
                            f"account {self.account.dname} region {region.name}"
                        )
                    )
                else:
                    log.debug(f"Adding graph of region {region.name} to account graph")
                    self.graph = networkx.compose(self.graph, graph)
                    self.graph.add_edge(self.root, region)

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=retry_on_request_limit_exceeded,
    )
    def collect_resources(self, collectors: Dict, region: AWSRegion) -> Graph:
        log.info(
            f"Collecting resources in AWS account {self.account.dname} region {region.name}"
        )
        graph = Graph()
        resource_attr = get_resource_attributes(region)
        graph.add_node(region, label=region.name, **resource_attr)
        for collector_name, collector in collectors.items():
            if (
                len(ArgumentParser.args.aws_collect) > 0
                and collector_name not in ArgumentParser.args.aws_collect
            ) or collector_name in ArgumentParser.args.aws_no_collect:
                log.debug(
                    f"Not running {collector_name} collector in account {self.account.dname} region {region.name}"
                )
                continue
            try:
                log.debug(
                    f"Running {collector_name} collector in account {self.account.dname} region {region.name}"
                )
                collector(region, graph)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "UnauthorizedOperation":
                    log.error(
                        f"Not authorized to collect resources in account {self.account.dname} region {region.id}"
                    )
                    return graph
                else:
                    log.exception(
                        (
                            f"An AWS API error occured during {collector_name} resource collection in "
                            f"account {self.account.dname} region {region.name} - skipping resources"
                        )
                    )
                    metrics_unhandled_collector_exceptions.labels(
                        account=self.account.dname,
                        region=region.name,
                        collector=collector_name,
                    ).inc()
            except Exception:
                log.exception(
                    (
                        f"Unhandeled collector exception while collecting {collector_name} resources in "
                        f"account {self.account.dname} region {region.name}"
                    )
                )
                metrics_unhandled_collector_exceptions.labels(
                    account=self.account.dname,
                    region=region.name,
                    collector=collector_name,
                ).inc()
        return graph

    # todo: more targeted caching than four layers of lru_cache()
    @lru_cache()
    def get_s3_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS S3 Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "s3")

    @lru_cache()
    def get_elb_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS ELB Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "elasticloadbalancing")

    @lru_cache()
    def get_vpc_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS VPC Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "vpc")

    @lru_cache()
    def get_ec2_instance_type_quota(self, region: AWSRegion, instance_type: str) -> int:
        # TODO: support dedicated hosts
        log.debug(
            (
                f"Retrieving AWS EC2 Instance Type Quota in account {self.account.dname} region {region.id} "
                f"for instance type {instance_type}"
            )
        )
        return self.get_ec2_service_quotas(region).get(instance_type, -1.0)

    @lru_cache()
    def get_ec2_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS EC2 Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "ec2")

    @lru_cache()
    def get_ebs_volume_type_quota(self, region: AWSRegion, volume_type: str) -> int:
        log.debug(
            (
                f"Retrieving AWS EBS Volume Type Quota in account {self.account.dname} region {region.id} "
                f"for instance type {volume_type}"
            )
        )
        return self.get_ebs_service_quotas(region).get(volume_type, -1.0)

    @lru_cache()
    def get_ebs_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS EBS Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "ebs")

    @lru_cache()
    def get_iam_service_quotas(self, region: AWSRegion) -> Dict:
        log.debug(
            f"Retrieving AWS IAM Service Quotas in account {self.account.dname} region {region.id}"
        )
        return self.get_service_quotas(region, "iam")

    @lru_cache()
    def get_service_quotas(self, region: AWSRegion, service: str) -> Dict:
        try:
            service_quotas = self.get_raw_service_quotas(region, service)
        except botocore.exceptions.ClientError:
            log.exception(
                f"Failed to retrieve raw service quotas in account {self.account.dname} region {region.name}"
            )
            metrics_unhandled_collector_exceptions.labels(
                account=self.account.name, region=region.name, collector="Service Quota"
            ).inc()
            return {}
        log.debug(
            (
                f"Trying to parse raw AWS Service Quotas in account {self.account.dname} region {region.id} for "
                f"service {service}"
            )
        )
        quotas = {}
        if service not in QUOTA_TO_SERVICE_MAP:
            log.error(f"Service {service} not in quota service map")
            return quotas
        for service_quota in service_quotas:
            quota_name = str(service_quota.get("QuotaName", ""))
            quota_value = float(service_quota.get("Value", -1.0))
            service_name = QUOTA_TO_SERVICE_MAP[service].get(quota_name)
            if service_name:
                quotas[service_name] = quota_value
            else:
                for key, value in QUOTA_TO_SERVICE_MAP[service].items():
                    if isinstance(key, re.Pattern):
                        m = key.search(quota_name)
                        if m:
                            if isinstance(value, int):
                                try:
                                    quotas[m.group(value)] = quota_value
                                except IndexError:
                                    log.error(
                                        f"Group {value} specified for regex {key} does not exist"
                                    )
                            else:
                                quotas[value] = quota_value
        return quotas

    @lru_cache()
    def get_raw_service_quotas(self, region: AWSRegion, service: str) -> List:
        log.debug(
            (
                f"Retrieving raw AWS Service Quotas in account {self.account.dname} region {region.id} for "
                f"service {service}"
            )
        )
        service_quotas = []
        if "quotas" in ArgumentParser.args.aws_no_collect:
            log.debug(
                (
                    f"Skipping quotas collection in account {self.account.dname} region {region.id} for "
                    f"service {service}"
                )
            )
            return service_quotas

        try:
            session = aws_session(self.account.id, self.account.role)
            client = session.client("service-quotas", region_name=region.id)
            response = client.list_service_quotas(ServiceCode=service)
            service_quotas = response.get("Quotas", [])
            while response.get("NextToken") is not None:
                response = client.list_service_quotas(
                    ServiceCode=service, NextToken=response["NextToken"]
                )
                service_quotas.extend(response.get("Quotas", []))

        except (
            socket.gaierror,
            urllib3.exceptions.NewConnectionError,
            botocore.exceptions.EndpointConnectionError,
        ):
            log.error(
                f"AWS Service Quotas Endpoint not available in region {region.id}"
            )
        return service_quotas

    def get_quota_services(self, region: AWSRegion) -> List:
        log.debug(
            (
                f"Retrieving list of AWS ServiceQuota supported services in "
                f"account {self.account.dname} region {region.id}"
            )
        )
        try:
            session = aws_session(self.account.id, self.account.role)
            client = session.client("service-quotas", region_name=region.id)
            response = client.list_services()
            services = response.get("Services", [])
            while response.get("NextToken") is not None:
                response = client.list_services(NextToken=response["NextToken"])
                services.extend(response.get("Services", []))

            services = [service["ServiceCode"] for service in services]
            return services
        except (
            socket.gaierror,
            urllib3.exceptions.NewConnectionError,
            botocore.exceptions.EndpointConnectionError,
        ):
            log.error(
                f"AWS Service Quotas Endpoint not available in region {region.id}"
            )
            return []

    @metrics_collect_volumes.time()
    def collect_volumes(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EBS Volumes in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        volumes = []
        for volume in ec2.volumes.all():
            try:
                v = AWSEC2Volume(
                    volume.id,
                    self.tags_as_dict(volume.tags),
                    account=self.account,
                    region=region,
                    ctime=volume.create_time,
                )
                v.name = v.tags.get("Name", v.id)
                v.volume_size = volume.size
                v.volume_type = volume.volume_type
                v.volume_status = volume.state
                log.debug(
                    f"Found volume {v.id} of type {v.volume_type} size {v.volume_size} status {v.volume_status}"
                )
                graph.add_resource(region, v)
                volumes.append(v)
                volume_type_info = self.get_volume_type_info(
                    region, graph, v.volume_type
                )
                if volume_type_info:
                    graph.add_edge(volume_type_info, v)
                for attachment in volume.attachments:
                    if "InstanceId" in attachment:
                        instance_id = attachment["InstanceId"]
                        log.debug(
                            f"Volume {volume.id} is attached to instance {instance_id}"
                        )
                        instance = graph.search_first("id", instance_id)
                        if instance:
                            graph.add_edge(v, instance)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {volume} - skipping")
        self.collect_volume_metrics(region, volumes)

    @metrics_collect_volume_metrics.time()
    def collect_volume_metrics(self, region: AWSRegion, volumes: List) -> None:
        resources = [
            volume for volume in volumes if volume.volume_status == "available"
        ]
        log.info(
            (
                f"Collecting AWS EBS Volume Metrics for {len(resources)} volumes in "
                f"account {self.account.dname} region {region.id}"
            )
        )
        atime_metric = "VolumeReadOps"
        mtime_metric = "VolumeWriteOps"
        namespace = "AWS/EBS"
        dimension_name = "VolumeId"
        dimension_attr = "id"
        resource_prefix = "vol"
        for chunk in chunks(resources, 100):
            self.set_metrics(
                region,
                chunk,
                atime_metric,
                mtime_metric,
                namespace,
                dimension_name,
                dimension_attr,
                resource_prefix,
            )

    @metrics_collect_rds_metrics.time()
    def collect_rds_metrics(self, region: AWSRegion, resources: List) -> None:
        log.info(
            (
                f"Collecting AWS RDS Metrics for {len(resources)} databases in "
                f"account {self.account.dname} region {region.id}"
            )
        )
        atime_metric = mtime_metric = "DatabaseConnections"
        namespace = "AWS/RDS"
        dimension_name = "DBInstanceIdentifier"
        dimension_attr = "name"
        resource_prefix = "db"
        for chunk in chunks(resources, 100):
            self.set_metrics(
                region,
                chunk,
                atime_metric,
                mtime_metric,
                namespace,
                dimension_name,
                dimension_attr,
                resource_prefix,
            )

    def set_metrics(
        self,
        region: AWSRegion,
        resources: List,
        atime_metric: str,
        mtime_metric: str,
        namespace: str,
        dimension_name: str,
        dimension_attr: str,
        resource_prefix: str,
    ) -> None:
        log.debug(
            f"Setting AWS Metrics for {len(resources)} resources in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        cw = session.client("cloudwatch", region_name=region.id)

        end_time = datetime.now()
        start_time = end_time - timedelta(days=60)

        if atime_metric == mtime_metric:
            metric_names = [atime_metric]
        else:
            metric_names = [atime_metric, mtime_metric]

        query = []
        for resource in resources:
            for metric_name in metric_names:
                query.append(
                    {
                        "Id": "metric_"
                        + metric_name
                        + "_"
                        + re.sub("[^0-9a-zA-Z]+", "_", resource.id),
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": [
                                    {
                                        "Name": dimension_name,
                                        "Value": getattr(resource, dimension_attr),
                                    }
                                ],
                            },
                            "Period": 3600,
                            "Stat": "Sum",
                            "Unit": "Count",
                        },
                        "ReturnData": True,
                    }
                )

        response = self.get_metrics(cw, query, start_time, end_time)
        metrics = response.get("MetricDataResults", [])
        while response.get("NextToken") is not None and any(
            (
                len(metric["Values"]) > 0
                for metric in response.get("MetricDataResults", [])
            )
        ):
            response = self.get_metrics(
                cw, query, start_time, end_time, response.get("NextToken")
            )
            metrics.extend(response.get("MetricDataResults", []))

        try:
            atime, mtime = self.get_atime_mtime_from_metrics(
                metrics, resource_prefix, atime_metric, mtime_metric
            )

            # if after we retrieved a resources's metrics we don't find any atime/mtime for it
            # we will fall back to setting atime/mtime to either the earliest date we tried to
            # retrieve metrics for or the creation time of the volume, whichever is more recent
            fallback_time = make_valid_timestamp(start_time)

            for resource in resources:
                if resource.ctime > fallback_time:
                    fallback_time = resource.ctime

                if resource.id in atime:
                    resource.atime = atime[resource.id]
                else:
                    resource.atime = fallback_time

                if resource.id in mtime:
                    resource.mtime = mtime[resource.id]
                else:
                    resource.mtime = fallback_time
        except ValueError:
            log.exception(f"Error while processing metrics for resource {resource.id}")

    def get_atime_mtime_from_metrics(
        self,
        metrics: List,
        resource_prefix: str,
        atime_metric: str,
        mtime_metric: str,
    ) -> Tuple:
        atime = {}
        mtime = {}
        for metric in metrics:
            id = metric.get("Id")
            _, metric_name, resource_id = id.split("_", 2)
            if not resource_id.startswith(f"{resource_prefix}_"):
                raise ValueError(f"Invalid resource Id {resource_id}")
            resource_prefix_idx = len(resource_prefix) + 1
            resource_id = f"{resource_prefix}-" + resource_id[resource_prefix_idx:]

            timestamps = metric.get("Timestamps", [])
            values = metric.get("Values", [])
            if len(timestamps) != len(values):
                raise ValueError(
                    f"Number of timestamps {len(timestamps)} doesn't match number of values {len(values)}"
                )

            if metric_name not in (atime_metric, mtime_metric):
                raise ValueError(f"Retrieved unknown metric {metric_name}")

            if (metric_name == atime_metric and resource_id in atime) or (
                metric_name == mtime_metric and resource_id in mtime
            ):
                continue

            for timestamp, value in zip(timestamps, values):
                if value > 0:
                    if metric_name == atime_metric and atime.get(resource_id) is None:
                        log.debug(f"Setting atime for {resource_id} to {timestamp}")
                        atime[resource_id] = timestamp
                    if metric_name == mtime_metric and mtime.get(resource_id) is None:
                        log.debug(f"Setting mtime for {resource_id} to {timestamp}")
                        mtime[resource_id] = timestamp
                    break

        return (atime, mtime)

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=3000,
        wait_exponential_max=300000,
        retry_on_exception=retry_on_request_limit_exceeded,
    )
    def get_metrics(self, cw, query, start_time, end_time, next_token=None) -> Dict:
        log.debug("Fetching CloudWatch metrics")
        if next_token:
            response = cw.get_metric_data(
                MetricDataQueries=query,
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampDescending",
                NextToken=next_token,
            )
        else:
            response = cw.get_metric_data(
                MetricDataQueries=query,
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampDescending",
            )
        return response

    @metrics_collect_iam_server_certificates.time()
    def collect_iam_server_certificates(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Server Certificates in account {self.account.dname} region {region.id}"
        )
        cq = AWSIAMServerCertificateQuota(
            "iam_server_certificates_quota", {}, account=self.account, region=region
        )
        cq.quota = self.get_iam_service_quotas(region).get("server_certificates", -1.0)
        graph.add_resource(region, cq)
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_server_certificates()
        certificates = response.get("ServerCertificateMetadataList", [])
        while response.get("Marker") is not None:
            response = client.list_server_certificates(Marker=response["Marker"])
            certificates.extend(response.get("ServerCertificateMetadataList", []))

        for certificate in certificates:
            c = AWSIAMServerCertificate(
                certificate["ServerCertificateId"],
                {},
                account=self.account,
                region=region,
                ctime=certificate.get("UploadDate"),
            )
            c.path = certificate.get("Path")
            c.name = certificate.get("ServerCertificateName")
            c.arn = certificate.get("Arn")
            c.expires = certificate.get("Expiration")
            log.debug(
                f"Found IAM Server Certificate {c.dname} in account {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, c)
            graph.add_edge(cq, c)

    @metrics_collect_iam_policies.time()
    def collect_iam_policies(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Policies in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_policies(Scope="Local", OnlyAttached=False)
        policies = response.get("Policies", [])
        while response.get("Marker") is not None:
            response = client.list_policies(
                Scope="Local", OnlyAttached=False, Marker=response["Marker"]
            )
            policies.extend(response.get("Policies", []))

        response = client.list_policies(Scope="AWS", OnlyAttached=True)
        policies.extend(response.get("Policies", []))
        while response.get("Marker") is not None:
            response = client.list_policies(
                Scope="Local", OnlyAttached=True, Marker=response["Marker"]
            )
            policies.extend(response.get("Policies", []))

        for policy in policies:
            p = AWSIAMPolicy(
                policy["PolicyId"],
                {},
                account=self.account,
                region=region,
                ctime=policy.get("CreateDate"),
            )
            p.name = policy.get("PolicyName")
            p.arn = policy.get("Arn")
            p.mtime = policy.get("UpdateDate")

            # We can not delete AWS pre-defined policies
            # so we mark them as phantom resource
            if p.arn.startswith("arn:aws:iam::aws:"):
                p.phantom = True

            log.debug(
                f"Found {p.rtdname} ({p.id}) {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, p)

    @metrics_collect_iam_groups.time()
    def collect_iam_groups(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Groups in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_groups()
        groups = response.get("Groups", [])
        while response.get("Marker") is not None:
            response = client.list_policies(Marker=response["Marker"])
            groups.extend(response.get("Groups", []))

        for group in groups:
            g = AWSIAMGroup(
                group["GroupId"],
                {},
                account=self.account,
                region=region,
                ctime=group.get("CreateDate"),
            )
            g.name = group.get("GroupName")
            g.arn = group.get("Arn")
            log.debug(
                f"Found {g.rtdname} in account {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, g)

            group_session = aws_session(self.account.id, self.account.role)
            group_client = group_session.client("iam", region_name=region.id)

            try:
                group_response = group_client.list_group_policies(GroupName=g.name)
                group_policies = group_response.get("PolicyNames", [])
                while group_response.get("Marker") is not None:
                    group_response = group_client.list_group_policies(
                        GroupName=g.name, Marker=group_response["Marker"]
                    )
                    group_policies.extend(group_response.get("PolicyNames", []))
                g.group_policies = list(group_policies)

                group_response = group_client.list_attached_group_policies(
                    GroupName=g.name
                )
                policies = group_response.get("AttachedPolicies", [])
                while group_response.get("Marker") is not None:
                    group_response = group_client.list_attached_group_policies(
                        GroupName=g.name, Marker=group_response["Marker"]
                    )
                    policies.extend(group_response.get("AttachedPolicies", []))
                for policy in policies:
                    p = graph.search_first("arn", policy["PolicyArn"])
                    if p:
                        graph.add_edge(p, g)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.exception(
                        (
                            f"An error occurred when trying to retrieve group information for "
                            f"group {g.name} in account {self.account.dname} region {region.name}"
                        )
                    )
                    continue
                else:
                    raise

    @metrics_collect_iam_instance_profiles.time()
    def collect_iam_instance_profiles(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Instance Profiles in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_instance_profiles()
        instance_profiles = response.get("InstanceProfiles", [])
        while response.get("Marker") is not None:
            response = client.list_instance_profiles(Marker=response["Marker"])
            instance_profiles.extend(response.get("InstanceProfiles", []))

        for instance_profile in instance_profiles:
            ip = AWSIAMInstanceProfile(
                instance_profile["InstanceProfileId"],
                {},
                account=self.account,
                region=region,
                ctime=instance_profile.get("CreateDate"),
            )
            ip.name = instance_profile.get("InstanceProfileName")
            ip.arn = instance_profile.get("Arn")
            log.debug(
                f"Found {ip.rtdname} in account {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, ip)

    @metrics_collect_iam_roles.time()
    def collect_iam_roles(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Roles in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_roles()
        roles = response.get("Roles", [])
        while response.get("Marker") is not None:
            response = client.list_roles(Marker=response["Marker"])
            roles.extend(response.get("Roles", []))

        for role in roles:
            r = AWSIAMRole(
                role["RoleId"],
                self.tags_as_dict(role.get("Tags", [])),
                account=self.account,
                region=region,
                ctime=role.get("CreateDate"),
                atime=role.get("RoleLastUsed", {}).get("LastUsedDate"),
            )
            r.name = role.get("RoleName")
            r.arn = role.get("Arn")
            log.debug(
                f"Found {r.rtdname} in account {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, r)

            role_session = aws_session(self.account.id, self.account.role)
            role_client = role_session.client("iam", region_name=region.id)

            try:
                role_response = role_client.list_role_policies(RoleName=r.name)
                role_policies = role_response.get("PolicyNames", [])
                while role_response.get("Marker") is not None:
                    role_response = role_client.list_role_policies(
                        RoleName=r.name, Marker=role_response["Marker"]
                    )
                    role_policies.extend(role_response.get("PolicyNames", []))
                r.role_policies = list(role_policies)

                role_response = role_client.list_instance_profiles_for_role(
                    RoleName=r.name
                )
                instance_profiles = role_response.get("InstanceProfiles", [])
                while role_response.get("Marker") is not None:
                    role_response = role_client.list_instance_profiles_for_role(
                        RoleName=r.name, Marker=role_response["Marker"]
                    )
                    instance_profiles.extend(role_response.get("InstanceProfiles", []))

                for instance_profile in instance_profiles:
                    ip = graph.search_first("arn", instance_profile["Arn"])
                    if ip:
                        graph.add_edge(r, ip)

                role_response = role_client.list_attached_role_policies(RoleName=r.name)
                policies = role_response.get("AttachedPolicies", [])
                while role_response.get("Marker") is not None:
                    role_response = role_client.list_attached_role_policies(
                        RoleName=r.name, Marker=role_response["Marker"]
                    )
                    policies.extend(role_response.get("AttachedPolicies", []))
                for policy in policies:
                    p = graph.search_first("arn", policy["PolicyArn"])
                    if p:
                        graph.add_edge(r, p)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.exception(
                        (
                            f"An error occurred when trying to retrieve role information for "
                            f"role {r.name} in account {self.account.dname} region {region.name}"
                        )
                    )
                    continue
                else:
                    raise

    @metrics_collect_iam_users.time()
    def collect_iam_users(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS IAM Users in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam", region_name=region.id)

        response = client.list_users()
        users = response.get("Users", [])
        while response.get("Marker") is not None:
            response = client.list_users(Marker=response["Marker"])
            users.extend(response.get("Users", []))

        for user in users:
            u = AWSIAMUser(
                user["UserId"],
                self.tags_as_dict(user.get("Tags", [])),
                account=self.account,
                region=region,
                ctime=user.get("CreateDate"),
            )
            u.name = user.get("UserName")
            u.arn = user.get("Arn")
            u.atime = user.get("PasswordLastUsed")
            log.debug(
                f"Found IAM User {u.name} ({u.id}) in account {self.account.dname} region {region.id}"
            )
            graph.add_resource(region, u)

            user_session = aws_session(self.account.id, self.account.role)
            user_client = user_session.client("iam", region_name=region.id)

            try:
                user_response = user_client.list_user_policies(UserName=u.name)
                user_policies = user_response.get("PolicyNames", [])
                while user_response.get("Marker") is not None:
                    user_response = user_client.list_user_policies(
                        UserName=u.name, Marker=user_response["Marker"]
                    )
                    user_policies.extend(user_response.get("PolicyNames", []))
                u.user_policies = list(user_policies)

                user_response = user_client.list_attached_user_policies(UserName=u.name)
                policies = user_response.get("AttachedPolicies", [])
                while user_response.get("Marker") is not None:
                    user_response = user_client.list_attached_user_policies(
                        UserName=u.name, Marker=user_response["Marker"]
                    )
                    policies.extend(user_response.get("AttachedPolicies", []))
                for policy in policies:
                    p = graph.search_first("arn", policy["PolicyArn"])
                    if p:
                        graph.add_edge(p, u)

                user_response = user_client.list_groups_for_user(UserName=u.name)
                groups = user_response.get("Groups", [])
                while user_response.get("Marker") is not None:
                    user_response = user_client.list_groups_for_user(
                        UserName=u.name, Marker=user_response["Marker"]
                    )
                    groups.extend(user_response.get("Groups", []))
                for group in groups:
                    g = graph.search_first("arn", group["Arn"])
                    if g:
                        graph.add_edge(g, u)

                user_response = user_client.list_access_keys(UserName=u.name)
                access_keys = user_response.get("AccessKeyMetadata", [])
                while user_response.get("Marker") is not None:
                    user_response = user_client.list_access_keys(
                        UserName=u.name, Marker=user_response["Marker"]
                    )
                    access_keys.extend(user_response.get("AccessKeyMetadata", []))
                for access_key in access_keys:
                    ak = AWSIAMAccessKey(
                        access_key["AccessKeyId"],
                        {},
                        user_name=u.name,
                        account=self.account,
                        region=region,
                        ctime=access_key.get("CreateDate"),
                    )
                    ak.access_key_status = access_key.get("Status")
                    log.debug(
                        (
                            f"Found IAM Access Key {ak.id} for user {u.name} in "
                            f"account {self.account.dname} region {region.id}"
                        )
                    )
                    graph.add_resource(u, ak)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.exception(
                        (
                            f"An error occurred when trying to retrieve user information for "
                            f"user {u.name} in account {self.account.dname} region {region.name}"
                        )
                    )
                    continue
                else:
                    raise

    # todo: this assumes all reservations within a region, not az
    @metrics_collect_reserved_instances.time()
    def collect_reserved_instances(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EC2 Reserved Instances in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        response = client.describe_reserved_instances()
        reserved_instances = response.get("ReservedInstances", [])
        for ri in reserved_instances:
            if ri["State"] == "active":
                log.debug(
                    f"Found active reservation of type {ri['OfferingType']} for instance type {ri['InstanceType']}"
                )
                instance_type_info = self.get_instance_type_info(
                    region, graph, ri["InstanceType"]
                )
                if instance_type_info and "InstanceCount" in ri:
                    instance_type_info.reservations += ri["InstanceCount"]
                    log.debug(
                        (
                            f"Reserved instance count for instance type {ri['InstanceType']} in account "
                            f"{self.account.dname} region {region.name} is now {instance_type_info.reservations}"
                        )
                    )
                if ri["Scope"] != "Region":
                    log.error(
                        "Found currently unsupported reservation with scope outside region"
                    )

    @metrics_collect_instances.time()
    def collect_instances(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EC2 Instances in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for instance in ec2.instances.all():
            try:
                i = AWSEC2Instance(
                    instance.id,
                    self.tags_as_dict(instance.tags),
                    account=self.account,
                    region=region,
                    ctime=instance.launch_time,
                )
                instance_name = i.tags.get("Name")
                if instance_name:
                    i.name = instance_name
                i.instance_type = instance.instance_type
                i.instance_status = instance.state["Name"]
                if isinstance(
                    instance.iam_instance_profile, Mapping
                ) and instance.iam_instance_profile.get("Arn"):
                    log.debug(
                        (
                            f"Queuing deferred connection from instance profile "
                            f"{instance.iam_instance_profile['Arn']} to instance {i.id}"
                        )
                    )
                    i.add_deferred_connection(
                        "arn", instance.iam_instance_profile["Arn"]
                    )
                log.debug(
                    f"Found instance {i.id} of type {i.instance_type} status {i.instance_status}"
                )
                instance_type_info = self.get_instance_type_info(
                    region, graph, i.instance_type
                )
                if instance_type_info:
                    graph.add_edge(instance_type_info, i)
                    i.instance_cores = instance_type_info.instance_cores
                    i.instance_memory = instance_type_info.instance_memory
                else:
                    try:
                        i.instance_cores = instance.cpu_options["CoreCount"]
                    except TypeError:
                        log.exception(
                            f"Unable to determine number of CPU cores for instance type {i.instance_type}"
                        )
                graph.add_resource(region, i)
                kp = graph.search_first_all(
                    {"name": instance.key_name, "resource_type": "aws_ec2_keypair"}
                )
                if kp:
                    graph.add_edge(kp, i)

            except botocore.exceptions.ClientError:
                log.exception(
                    f"Some boto3 call failed on resource {instance} - skipping"
                )

    @metrics_collect_autoscaling_groups.time()
    def collect_autoscaling_groups(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Autoscaling Groups in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("autoscaling", region_name=region.id)
        for autoscaling_group in paginate(client.describe_auto_scaling_groups):
            name = autoscaling_group["AutoScalingGroupName"]
            tags = self.tags_as_dict(autoscaling_group.get("Tags", []))
            log.debug(f"Found Autoscaling Group {name}")
            asg = AWSAutoScalingGroup(
                name,
                tags,
                account=self.account,
                region=region,
                ctime=autoscaling_group.get("CreatedTime"),
            )
            asg.arn = autoscaling_group.get("AutoScalingGroupARN")
            graph.add_resource(region, asg)
            for instance in autoscaling_group.get("Instances", []):
                instance_id = instance["InstanceId"]
                i = graph.search_first("id", instance_id)
                if i:
                    graph.add_edge(i, asg)

    @metrics_collect_network_acls.time()
    def collect_network_acls(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Network ACLs in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        for network_acl in paginate(client.describe_network_acls):
            acl_id = network_acl["NetworkAclId"]
            vpc_id = network_acl.get("VpcId")
            tags = self.tags_as_dict(network_acl.get("Tags", []))
            acl_name = tags.get("Name", acl_id)
            acl = AWSEC2NetworkAcl(
                acl_id, tags, name=acl_name, account=self.account, region=region
            )
            acl.is_default = network_acl.get("IsDefault", False)
            log.debug(f"Found Network ACL {acl.name}")
            graph.add_resource(region, acl)
            if vpc_id:
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, acl)
            for association in network_acl.get("Associations", []):
                subnet_id = association.get("SubnetId")
                if subnet_id:
                    s = graph.search_first("id", subnet_id)
                    if s:
                        graph.add_edge(acl, s)

    @metrics_collect_nat_gateways.time()
    def collect_nat_gateways(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS NAT gateways in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        for nat_gw in paginate(client.describe_nat_gateways):
            ngw_id = nat_gw["NatGatewayId"]
            vpc_id = nat_gw.get("VpcId")
            subnet_id = nat_gw.get("SubnetId")
            tags = self.tags_as_dict(nat_gw.get("Tags", []))
            ngw_name = tags.get("Name", ngw_id)
            ngw = AWSEC2NATGateway(
                ngw_id,
                tags,
                name=ngw_name,
                account=self.account,
                region=region,
                ctime=nat_gw.get("CreateTime"),
            )
            ngw.nat_gateway_status = nat_gw.get("State")
            log.debug(f"Found NAT gateway {ngw.name}")
            graph.add_resource(region, ngw)
            if vpc_id:
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, ngw)
            if subnet_id:
                s = graph.search_first("id", subnet_id)
                if s:
                    graph.add_edge(s, ngw)
            for gateway_address in nat_gw.get("NatGatewayAddresses", []):
                network_interface_id = gateway_address.get("NetworkInterfaceId")
                if network_interface_id:
                    n = graph.search_first("id", network_interface_id)
                    if n:
                        graph.add_edge(n, ngw)

    @metrics_collect_snapshots.time()
    def collect_snapshots(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EC2 snapshots in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        for snapshot in paginate(client.describe_snapshots, OwnerIds=["self"]):
            snap_id = snapshot["SnapshotId"]
            tags = self.tags_as_dict(snapshot.get("Tags", []))
            snap_name = tags.get("Name", snap_id)
            snap = AWSEC2Snapshot(
                snap_id,
                tags,
                name=snap_name,
                account=self.account,
                region=region,
                ctime=snapshot.get("StartTime"),
            )
            snap.snapshot_status = snapshot.get("State", "")
            snap.description = snapshot.get("Description", "")
            snap.volume_id = snapshot.get("VolumeId")
            snap.volume_size = snapshot.get("VolumeSize", 0)
            snap.owner_id = snapshot.get("OwnerId")
            snap.owner_alias = snapshot.get("OwnerAlias", "")
            snap.encrypted = snapshot.get("Encrypted", False)
            log.debug(f"Found AWS EC2 snapshot {snap.dname}")
            graph.add_resource(region, snap)

    #            if snap.volume_id:
    #                v = graph.search_first('id', snap.volume_id)
    #                if v:
    #                    graph.add_edge(v, snap)

    @metrics_collect_vpc_peering_connections.time()
    def collect_vpc_peering_connections(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS VPC Peering Connections in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        for peering_connection in paginate(client.describe_vpc_peering_connections):
            pc_id = peering_connection["VpcPeeringConnectionId"]
            tags = self.tags_as_dict(peering_connection.get("Tags", []))
            pc_name = tags.get("Name", pc_id)
            pc = AWSVPCPeeringConnection(
                pc_id, tags, name=pc_name, account=self.account, region=region
            )
            pc.vpc_peering_connection_status = peering_connection.get("Status", {}).get(
                "Code"
            )
            log.debug(f"Found AWS VPC Peering Connection {pc.name}")
            graph.add_resource(region, pc)
            accepter_vpc_id = peering_connection.get("AccepterVpcInfo", {}).get("VpcId")
            accepter_vpc_region = peering_connection.get("AccepterVpcInfo", {}).get(
                "Region"
            )
            requester_vpc_id = peering_connection.get("RequesterVpcInfo", {}).get(
                "VpcId"
            )
            requester_vpc_region = peering_connection.get("RequesterVpcInfo", {}).get(
                "Region"
            )
            vpc_ids = []
            if accepter_vpc_region == region.name:
                vpc_ids.append(accepter_vpc_id)
            if requester_vpc_region == region.name:
                vpc_ids.append(requester_vpc_id)
            for vpc_id in vpc_ids:
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, pc)

    @metrics_collect_vpc_endpoints.time()
    def collect_vpc_endpoints(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS VPC Endpoints in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        for endpoint in paginate(client.describe_vpc_endpoints):
            ep_id = endpoint["VpcEndpointId"]
            tags = self.tags_as_dict(endpoint.get("Tags", []))
            ep_name = tags.get("Name", ep_id)
            ep = AWSVPCEndpoint(
                ep_id,
                tags,
                name=ep_name,
                account=self.account,
                region=region,
                ctime=endpoint.get("CreationTimestamp"),
            )
            ep.vpc_endpoint_status = endpoint.get("State", "")
            ep.vpc_endpoint_type = endpoint.get("VpcEndpointType", "")
            log.debug(f"Found AWS VPC Endpoint {ep.name}")
            graph.add_resource(region, ep)
            if endpoint.get("VpcId"):
                v = graph.search_first("id", endpoint.get("VpcId"))
                if v:
                    graph.add_edge(v, ep)
            for rt_id in endpoint.get("RouteTableIds", []):
                rt = graph.search_first("id", rt_id)
                if rt:
                    graph.add_edge(rt, ep)
            for sn_id in endpoint.get("SubnetIds", []):
                sn = graph.search_first("id", sn_id)
                if sn:
                    graph.add_edge(sn, ep)
            for security_group in endpoint.get("Groups", []):
                sg_id = security_group["GroupId"]
                sg = graph.search_first("id", sg_id)
                if sg:
                    graph.add_edge(sg, ep)
            for ni_id in endpoint.get("NetworkInterfaceIds", []):
                ni = graph.search_first("id", ni_id)
                if ni:
                    graph.add_edge(ni, ep)

    @metrics_collect_keypairs.time()
    def collect_keypairs(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EC2 Key Pairs in account {self.account.dname}, region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)
        response = client.describe_key_pairs()
        for keypair in response.get("KeyPairs", []):
            keypair_name = keypair["KeyName"]
            keypair_id = keypair["KeyPairId"]
            tags = self.tags_as_dict(keypair.get("Tags", []))
            log.debug(f"Found AWS EC2 Key Pair {keypair_name}")
            kp = AWSEC2KeyPair(
                keypair_id, tags, account=self.account, region=region, name=keypair_name
            )
            kp.fingerprint = keypair.get("KeyFingerprint")
            graph.add_resource(region, kp)

    @metrics_collect_rds_instances.time()
    def collect_rds_instances(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS RDS instances in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("rds", region_name=region.id)

        response = client.describe_db_instances()
        dbs = response.get("DBInstances", [])
        while response.get("Marker") is not None:
            response = client.describe_db_instances(Marker=response["Marker"])
            dbs.extend(response.get("DBInstances", []))

        databases = []
        for db in dbs:
            log.debug(f"Found RDS {db['DBInstanceArn']}")
            d = AWSRDSInstance(
                db["DbiResourceId"],
                {},
                account=self.account,
                region=region,
                ctime=db.get("InstanceCreateTime"),
            )
            d.name = db.get("DBInstanceIdentifier", db["DbiResourceId"])
            d.db_type = db.get("Engine")
            d.db_status = db.get("DBInstanceStatus")
            d.db_endpoint = f"{db['Endpoint']['Address']}:{db['Endpoint']['Port']}"
            d.instance_type = db.get("DBInstanceClass")
            d.volume_size = int(db.get("AllocatedStorage", 0))
            d.volume_iops = int(db.get("Iops", 0))
            databases.append(d)
            graph.add_resource(region, d)

            for security_group in db.get("VpcSecurityGroups", []):
                sg_id = security_group.get("VpcSecurityGroupId")
                if sg_id:
                    sg = graph.search_first("id", sg_id)
                    if sg:
                        graph.add_edge(sg, d)
            vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
            if vpc_id:
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, d)

            for subnet in db.get("DBSubnetGroup", {}).get("Subnets"):
                subnet_id = subnet.get("SubnetIdentifier")
                s = graph.search_first("id", subnet_id)
                if s:
                    graph.add_edge(s, d)

        self.collect_rds_metrics(region, databases)

    @metrics_collect_s3_buckets.time()
    def collect_s3_buckets(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS S3 Buckets in account {self.account.dname} region {region.id}"
        )
        bq = AWSS3BucketQuota("s3_quota", {}, account=self.account, region=region)
        bq.quota = self.get_s3_service_quotas(region).get("s3", -1.0)
        graph.add_resource(region, bq)
        session = aws_session(self.account.id, self.account.role)
        s3 = session.resource("s3", region_name=region.id)

        for bucket in s3.buckets.all():
            try:
                b = AWSS3Bucket(
                    bucket.name,
                    {},
                    account=self.account,
                    region=region,
                    ctime=bucket.creation_date,
                )
                log.debug(f"Found bucket {b.id}")
                graph.add_resource(region, b)
                graph.add_edge(bq, b)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {bucket} - skipping")

    @metrics_collect_alb_target_groups.time()
    def collect_alb_target_groups(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS ALB Target Groups in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        client = session.client("elbv2", region_name=region.id)

        response = client.describe_target_groups()
        target_groups = response.get("TargetGroups", [])
        while response.get("NextMarker") is not None:
            response = client.describe_target_groups(Marker=response["NextMarker"])
            target_groups.extend(response.get("TargetGroups", []))

        for target_group in target_groups:
            arn = target_group["TargetGroupArn"]
            tags = client.describe_tags(ResourceArns=[arn])
            tags = self.tags_as_dict(next(iter(tags["TagDescriptions"]))["Tags"])
            tg = AWSALBTargetGroup(
                target_group["TargetGroupName"],
                tags,
                account=self.account,
                region=region,
            )
            tg.arn = arn
            tg.target_type = target_group["TargetType"]
            log.debug(f"Found ALB Target Group {tg.name}")
            graph.add_resource(region, tg)

            vpc_id = target_group.get("VpcId")
            v = graph.search_first("id", vpc_id)
            if v:
                graph.add_edge(v, tg)

            backends = []
            if tg.target_type == "instance":
                response = client.describe_target_health(TargetGroupArn=tg.arn)
                thds = response.get("TargetHealthDescriptions", [])
                for thd in thds:
                    target = thd["Target"]
                    instance_id = target["Id"]
                    backends.append(instance_id)
                    i = graph.search_first("id", instance_id)
                    if i:
                        graph.add_edge(i, tg)

            load_balancer_arns = target_group.get("LoadBalancerArns", [])
            for load_balancer_arn in load_balancer_arns:
                alb = graph.search_first("arn", load_balancer_arn)
                if alb:
                    alb.backends.extend(backends)
                    graph.add_edge(tg, alb)

    @metrics_collect_albs.time()
    def collect_albs(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS ALBs in account {self.account.dname} region {region.id}"
        )
        aq = AWSALBQuota("alb_quota", {}, account=self.account, region=region)
        aq.quota = self.get_elb_service_quotas(region).get("alb", -1.0)
        graph.add_resource(region, aq)

        session = aws_session(self.account.id, self.account.role)
        client = session.client("elbv2", region_name=region.id)

        response = client.describe_load_balancers()
        albs = response.get("LoadBalancers", [])
        while response.get("NextMarker") is not None:
            response = client.describe_load_balancers(Marker=response["NextMarker"])
            albs.extend(response.get("LoadBalancers", []))

        for alb in albs:
            try:
                log.debug(f"Found ALB {alb['LoadBalancerName']} ({alb['DNSName']})")
                arn = alb["LoadBalancerArn"]
                tags = client.describe_tags(ResourceArns=[arn])
                tags = self.tags_as_dict(next(iter(tags["TagDescriptions"]))["Tags"])
                a = AWSALB(
                    alb["LoadBalancerName"],
                    tags,
                    account=self.account,
                    region=region,
                    ctime=alb.get("CreatedTime"),
                )
                a.arn = arn
                a.lb_type = "alb"
                graph.add_resource(region, a)
                graph.add_edge(aq, a)

                vpc_id = alb.get("VPCId")
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, a)

                availability_zones = alb.get("AvailabilityZones", [])
                for availability_zone in availability_zones:
                    subnet_id = availability_zone["SubnetId"]
                    s = graph.search_first("id", subnet_id)
                    if s:
                        graph.add_edge(s, a)

                security_groups = alb.get("SecurityGroups", [])
                for sg_id in security_groups:
                    sg = graph.search_first("id", sg_id)
                    if sg:
                        graph.add_edge(sg, a)

                response = client.describe_listeners(LoadBalancerArn=arn)
                listeners = response.get("Listeners", [])
                while response.get("NextMarker") is not None:
                    response = client.describe_listeners(
                        LoadBalancerArn=arn, Marker=response["NextMarker"]
                    )
                    listeners.extend(response.get("Listeners", []))
                for listener in listeners:
                    certificates = listener.get("Certificates", [])
                    for certificate in certificates:
                        certificate_arn = certificate.get("CertificateArn")
                        if certificate_arn:
                            log.debug(
                                f"Queuing deferred connection from Server Certificate {certificate_arn} to ALB {a.id}"
                            )
                            a.add_deferred_connection("arn", certificate_arn)

            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {alb} - skipping")

    @metrics_collect_elbs.time()
    def collect_elbs(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS ELBs in account {self.account.dname} region {region.id}"
        )
        eq = AWSELBQuota("elb_quota", {}, account=self.account, region=region)
        eq.quota = self.get_elb_service_quotas(region).get("elb", -1.0)
        graph.add_resource(region, eq)

        session = aws_session(self.account.id, self.account.role)
        client = session.client("elb", region_name=region.id)

        response = client.describe_load_balancers()
        elbs = response.get("LoadBalancerDescriptions", [])
        while response.get("NextMarker") is not None:
            response = client.describe_load_balancers(Marker=response["NextMarker"])
            elbs.extend(response.get("LoadBalancerDescriptions", []))

        for elb in elbs:
            try:
                log.debug(f"Found ELB {elb['LoadBalancerName']} ({elb['DNSName']})")
                tags = client.describe_tags(LoadBalancerNames=[elb["LoadBalancerName"]])
                tags = self.tags_as_dict(next(iter(tags["TagDescriptions"]))["Tags"])
                e = AWSELB(
                    elb["DNSName"],
                    tags,
                    account=self.account,
                    region=region,
                    ctime=elb.get("CreatedTime"),
                )
                e.name = elb["LoadBalancerName"]
                e.lb_type = "elb"
                instances = [i["InstanceId"] for i in elb.get("Instances", [])]
                e.backends.extend(instances)
                graph.add_resource(region, e)
                graph.add_edge(eq, e)

                vpc_id = elb.get("VPCId")
                v = graph.search_first("id", vpc_id)
                if v:
                    graph.add_edge(v, e)

                for instance_id in instances:
                    i = graph.search_first("id", instance_id)
                    if i:
                        graph.add_edge(i, e)

                subnets = elb.get("Subnets", [])
                for subnet_id in subnets:
                    s = graph.search_first("id", subnet_id)
                    if s:
                        graph.add_edge(s, e)

                security_groups = elb.get("SecurityGroups", [])
                for sg_id in security_groups:
                    sg = graph.search_first("id", sg_id)
                    if sg:
                        graph.add_edge(sg, e)

                listener_descriptions = elb.get("ListenerDescriptions", [])
                for listener_description in listener_descriptions:
                    listener = listener_description.get("Listener", {})
                    ssl_certificate_id = listener.get("SSLCertificateId")
                    if ssl_certificate_id:
                        log.debug(
                            f"Queuing deferred connection from Server Certificate {ssl_certificate_id} to ELB {e.id}"
                        )
                        e.add_deferred_connection("arn", ssl_certificate_id)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {elb} - skipping")

    @metrics_collect_vpcs.time()
    def collect_vpcs(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS VPCs in account {self.account.dname} region {region.id}"
        )
        vq = AWSVPCQuota("vpc_quota", {}, account=self.account, region=region)
        vq.quota = self.get_vpc_service_quotas(region).get("vpc", -1.0)
        graph.add_resource(region, vq)
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for vpc in ec2.vpcs.all():
            try:
                vpc_tags = self.tags_as_dict(vpc.tags)
                vpc_name = vpc_tags.get("Name", vpc.id)
                v = AWSVPC(
                    vpc.id,
                    vpc_tags,
                    name=vpc_name,
                    is_default=vpc.is_default,
                    account=self.account,
                    region=region,
                )
                if v.is_default:
                    # Protect the default VPC from being cleaned
                    v.protected = True
                log.debug(f"Found VPC {v.id}")
                graph.add_resource(region, v)
                graph.add_edge(vq, v)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {vpc} - skipping")

    @metrics_collect_subnets.time()
    def collect_subnets(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Subnets in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for subnet in ec2.subnets.all():
            try:
                tags = self.tags_as_dict(subnet.tags)
                subnet_name = tags.get("Name", subnet.id)
                s = AWSEC2Subnet(
                    subnet.id,
                    tags,
                    name=subnet_name,
                    account=self.account,
                    region=region,
                )
                log.debug(f"Found subnet {s.id}")
                graph.add_resource(region, s)
                if subnet.vpc_id:
                    log.debug(f"Subnet {s.id} is attached to VPC {subnet.vpc_id}")
                    v = graph.search_first("id", subnet.vpc_id)
                    if v:
                        graph.add_edge(v, s)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {subnet} - skipping")

    @metrics_collect_internet_gateways.time()
    def collect_internet_gateways(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Internet Gateways in account {self.account.dname} region {region.id}"
        )
        igwq = AWSEC2InternetGatewayQuota(
            "igw_quota", {}, account=self.account, region=region
        )
        igwq.quota = self.get_vpc_service_quotas(region).get("igw", -1.0)
        graph.add_resource(region, igwq)
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for igw in ec2.internet_gateways.all():
            try:
                tags = self.tags_as_dict(igw.tags)
                igw_name = tags.get("Name", igw.id)
                i = AWSEC2InternetGateway(
                    igw.id, tags, name=igw_name, account=self.account, region=region
                )
                log.debug(f"Found Internet Gateway {i.id}")
                graph.add_resource(region, i)
                graph.add_edge(igwq, i)
                for attachment in igw.attachments:
                    if "VpcId" in attachment:
                        vpc_id = attachment["VpcId"]
                        log.debug(
                            f"Internet Gateway {igw.id} is attached to VPC {vpc_id}"
                        )
                        v = graph.search_first("id", vpc_id)
                        if v:
                            graph.add_edge(v, i)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {igw} - skipping")

    @metrics_collect_security_groups.time()
    def collect_security_groups(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Security Groups in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for sg in ec2.security_groups.all():
            try:
                s = AWSEC2SecurityGroup(
                    sg.id,
                    self.tags_as_dict(sg.tags),
                    name=sg.group_name,
                    account=self.account,
                    region=region,
                )
                log.debug(f"Found Security Group {s.id}")
                graph.add_resource(region, s)
                if sg.vpc_id:
                    log.debug(f"Security Group {s.id} is attached to VPC {sg.vpc_id}")
                    v = graph.search_first("id", sg.vpc_id)
                    if v:
                        graph.add_edge(v, s)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {sg} - skipping")

    @metrics_collect_route_tables.time()
    def collect_route_tables(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Route Tables in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for rt in ec2.route_tables.all():
            try:
                tags = self.tags_as_dict(rt.tags)
                rt_name = tags.get("Name", rt.id)
                r = AWSEC2RouteTable(
                    rt.id, tags, name=rt_name, account=self.account, region=region
                )
                log.debug(f"Found Route Table {r.id}")
                graph.add_resource(region, r)
                if rt.vpc_id:
                    log.debug(f"Route Table {r.id} is attached to VPC {rt.vpc_id}")
                    v = graph.search_first("id", rt.vpc_id)
                    if v:
                        graph.add_edge(v, r)
            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {rt} - skipping")

    @metrics_collect_network_interfaces.time()
    def collect_network_interfaces(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Network Interfaces in account {self.account.dname} region {region.id}"
        )
        session = aws_session(self.account.id, self.account.role)
        ec2 = session.resource("ec2", region_name=region.id)
        for ni in ec2.network_interfaces.all():
            try:
                n = AWSEC2NetworkInterface(
                    ni.id,
                    self.tags_as_dict(ni.tag_set),
                    account=self.account,
                    region=region,
                )
                n.network_interface_status = ni.status
                n.network_interface_type = ni.interface_type
                n.mac = ni.mac_address
                n.description = ni.description
                for address in ni.private_ip_addresses:
                    private_ip = address.get("PrivateIpAddress")
                    if (
                        "Association" in address
                        and "PublicIp" in address["Association"]
                    ):
                        public_ip = address["Association"]["PublicIp"]
                    else:
                        public_ip = ""
                    n.private_ips.append(private_ip)
                    n.public_ips.append(public_ip)
                for address in ni.ipv6_addresses:
                    n.v6_ips.append(address["Ipv6Address"])
                log.debug(
                    f"Found Network Interface {n.id} with status {n.network_interface_status}"
                )
                graph.add_resource(region, n)
                if ni.vpc_id:
                    log.debug(f"Network Interface {n.id} resides in VPC {ni.vpc_id}")
                    v = graph.search_first("id", ni.vpc_id)
                    if v:
                        graph.add_edge(v, n)
                if ni.subnet_id:
                    log.debug(
                        f"Network Interface {n.id} resides in Subnet {ni.subnet_id}"
                    )
                    s = graph.search_first("id", ni.subnet_id)
                    if s:
                        graph.add_edge(s, n)
                if ni.attachment and "InstanceId" in ni.attachment:
                    instance_id = ni.attachment["InstanceId"]
                    log.debug(
                        f"Network Interface {n.id} is attached to instance {instance_id}"
                    )
                    i = graph.search_first("id", instance_id)
                    if i:
                        graph.add_edge(n, i)
                for group in ni.groups:
                    group_id = group.get("GroupId")
                    if group_id:
                        log.debug(
                            f"Network Interface {n.id} is assigned to security group {group_id}"
                        )
                        sg = graph.search_first("id", group_id)
                        if sg:
                            graph.add_edge(sg, n)

            except botocore.exceptions.ClientError:
                log.exception(f"Some boto3 call failed on resource {ni} - skipping")

    @metrics_collect_cloudformation_stacks.time()
    def collect_cloudformation_stacks(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Cloudformation Stacks in account {self.account.dname} region {region.id}"
        )

        session = aws_session(self.account.id, self.account.role)
        client = session.client("cloudformation", region_name=region.id)

        response = client.describe_stacks()
        stacks = response.get("Stacks", [])
        while response.get("NextToken") is not None:
            response = client.describe_stacks(NextToken=response["NextToken"])
            stacks.extend(response.get("Stacks", []))

        for stack in stacks:
            s = AWSCloudFormationStack(
                stack["StackId"],
                self.tags_as_dict(stack["Tags"]),
                account=self.account,
                region=region,
                ctime=stack.get("CreationTime"),
            )
            s.name = stack["StackName"]
            s.stack_status = stack.get("StackStatus", "")
            s.stack_status_reason = stack.get("StackStatusReason", "")
            s.stack_parameters = self.parameters_as_dict(stack.get("Parameters", []))
            s.mtime = stack.get("LastUpdatedTime")
            log.debug(f"Found Cloudformation Stack {s.name} ({s.id})")
            graph.add_resource(region, s)

    @metrics_collect_eks_clusters.time()
    def collect_eks_clusters(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS EKS Clusters in account {self.account.dname} region {region.id}"
        )

        session = aws_session(self.account.id, self.account.role)
        client = session.client("eks", region_name=region.id)

        response = client.list_clusters()
        clusters = response.get("clusters", [])
        while response.get("nextToken") is not None:
            response = client.list_clusters(nextToken=response["nextToken"])
            clusters.extend(response.get("clusters", []))

        for cluster in clusters:
            response = client.describe_cluster(name=cluster)
            cluster = response["cluster"]
            c = AWSEKSCluster(
                cluster["arn"],
                cluster.get("tags", {}),
                account=self.account,
                region=region,
                ctime=cluster.get("createdAt"),
            )
            c.name = cluster.get("name")
            c.arn = cluster.get("arn")
            c.cluster_status = cluster.get("status")
            c.cluster_endpoint = cluster.get("endpoint")
            if "roleArn" in cluster:
                log.debug(
                    f"Queuing deferred connection from role {cluster['roleArn']} to {c.resource_type} {c.id}"
                )
                c.add_deferred_connection("arn", cluster["roleArn"])
            graph.add_resource(region, c)
            self.get_eks_nodegroups(region, graph, c)

    @metrics_collect_elastic_ips.time()
    def collect_elastic_ips(self, region: AWSRegion, graph: Graph) -> None:
        log.info(
            f"Collecting AWS Elastic IPs in account {self.account.dname} region {region.id}"
        )

        session = aws_session(self.account.id, self.account.role)
        client = session.client("ec2", region_name=region.id)

        response = client.describe_addresses()
        addresses = response.get("Addresses", [])
        for address in addresses:
            allocation_id = address["AllocationId"]
            public_ip = address.get("PublicIp")
            private_ip_address = address.get("PrivateIpAddress")
            ip_address = public_ip if public_ip is not None else private_ip_address
            tags = self.tags_as_dict(address.get("Tags", []))
            name = tags.get("Name", allocation_id)
            ip = AWSEC2ElasticIP(
                allocation_id, tags, name=name, account=self.account, region=region
            )
            ip.ip_address = ip_address
            ip.allocation_id = allocation_id
            ip.association_id = address.get("AssociationId")
            ip.instance_id = address.get("InstanceId")
            ip.public_ip = public_ip
            ip.private_ip_address = private_ip_address
            ip.domain = address.get("Domain")
            ip.network_interface_id = address.get("NetworkInterfaceId")
            ip.network_interface_owner_id = address.get("NetworkInterfaceOwnerId")
            log.debug(f"Found Elastic IP {ip.dname}")
            graph.add_resource(region, ip)
            i = graph.search_first("id", ip.instance_id)
            if i:
                graph.add_edge(ip, i)
            ni = graph.search_first("id", ip.network_interface_id)
            if ni:
                graph.add_edge(ni, ip)

    @metrics_get_eks_nodegroups.time()
    def get_eks_nodegroups(
        self, region: AWSRegion, graph: Graph, cluster: AWSEKSCluster
    ) -> None:
        log.info(
            f"Collecting AWS EKS Nodegroups in account {self.account.dname} region {region.id} cluster {cluster.id}"
        )

        session = aws_session(self.account.id, self.account.role)
        client = session.client("eks", region_name=region.id)

        response = client.list_nodegroups(clusterName=cluster.name)
        nodegroups = response.get("nodegroups", [])
        while response.get("nextToken") is not None:
            response = client.list_nodegroups(nextToken=response["nextToken"])
            nodegroups.extend(response.get("nodegroups", []))

        for nodegroup in nodegroups:
            response = client.describe_nodegroup(
                clusterName=cluster.name, nodegroupName=nodegroup
            )
            nodegroup = response["nodegroup"]
            n = AWSEKSNodegroup(
                nodegroup["nodegroupArn"],
                nodegroup.get("tags", {}),
                account=self.account,
                region=region,
                ctime=nodegroup.get("createdAt"),
            )
            n.name = nodegroup.get("nodegroupName")
            n.cluster_name = cluster.name
            n.arn = nodegroup.get("nodegroupArn")
            n.nodegroup_status = nodegroup.get("status")
            graph.add_resource(cluster, n)
            for autoscaling_group in nodegroup.get("resources", {}).get(
                "autoScalingGroups", []
            ):
                log.debug(
                    f"Nodegroup {n.name} is connected to autoscaling group {autoscaling_group['name']}"
                )
                asg = graph.search_first_all(
                    {
                        "name": autoscaling_group["name"],
                        "resource_type": "aws_autoscaling_group",
                    }
                )
                if asg:
                    graph.add_edge(asg, n)

    def account_alias(self) -> Optional[str]:
        session = aws_session(self.account.id, self.account.role)
        client = session.client("iam")
        account_aliases = client.list_account_aliases().get("AccountAliases", [])
        if len(account_aliases) == 0:
            log.debug(f"Found no account alias for account {self.account.dname}")
            return None
        first_alias = account_aliases[0]
        log.debug(f"Found account alias {first_alias} for account {self.account.dname}")
        return first_alias

    def get_price_info(self, service, search_filter):
        session = aws_session(self.account.id, self.account.role)
        client = session.client("pricing", region_name="us-east-1")

        response = client.get_products(ServiceCode=service, Filters=search_filter)
        price_list = [json.loads(price) for price in response.get("PriceList", [])]
        while response.get("NextToken") is not None:
            response = client.get_products(
                ServiceCode=service,
                Filters=search_filter,
                NextToken=response["NextToken"],
            )
            price_list.extend(
                [json.loads(price) for price in response.get("PriceList", [])]
            )

        return price_list

    def get_instance_type_info(
        self, region: AWSRegion, graph: Graph, instance_type: str
    ) -> Optional[AWSEC2InstanceType]:
        with self._price_info_lock:
            if region.id not in self._price_info["ec2"]:
                self._price_info["ec2"][region.id] = {}

            if instance_type in self._price_info["ec2"][region.id]:
                return self._price_info["ec2"][region.id][instance_type]

            if region.id not in EC2_TO_PRICING_REGIONS:
                return None

            service = "AmazonEC2"
            search_filter = [
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "TERM_MATCH", "Field": "operation", "Value": "RunInstances"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {
                    "Type": "TERM_MATCH",
                    "Field": "location",
                    "Value": EC2_TO_PRICING_REGIONS[region.id],
                },
            ]

            log.debug(
                (
                    f"Retrieving pricing information for instances of type {instance_type} in "
                    f"account {self.account.dname} region {region.id}"
                )
            )
            price_list = self.get_price_info(service, search_filter)

            # price_info['ec2'][instance_type] = {
            #     'memory': 16,
            #     'clock': 2.5,
            #     'ecu': 166,
            #     'cores': 12,
            #     'pricing': {
            #         'tenancy': {
            #             'default': {
            #                 'ondemand': {
            #                     'onetime': 0.0,
            #                     'hourly': 0.4070000000
            #                 },
            #                 'reserved': {
            #                     'no': {
            #                         '1yr': {
            #                             'onetime': 2307,
            #                             'hourly': 0.54
            #                         },
            #                         '3yr': {}
            #                     },
            #                     'partial': {},
            #                     'all': {}
            #                 }
            #             },
            #             'host': {},
            #             'dedicated': {}
            #         }
            #     }
            # }

            price_info = {}
            for price in price_list:
                attributes = price.get("product", {}).get("attributes")
                terms = price.get("terms")
                tenancy = attributes.get("tenancy")
                ec2_tenancy = PRICING_TO_EC2_TENANCY.get(tenancy)
                attr_instance_type = attributes.get("instanceType")
                if instance_type != attr_instance_type:
                    log.error(
                        (
                            f"Error in pricing API call, returned instance type {attr_instance_type} "
                            f"doesn't match requested instance type {instance_type}"
                        )
                    )
                    return None
                memory = float(attributes.get("memory", 0).split(" ")[0])
                cores = int(attributes.get("vcpu", 0))
                od = terms.get("OnDemand", {})
                id1 = list(od)[0]
                id2 = list(od[id1]["priceDimensions"])[0]
                price = float(od[id1]["priceDimensions"][id2]["pricePerUnit"]["USD"])
                if instance_type not in price_info:
                    price_info[instance_type] = {
                        "memory": memory,
                        "cores": cores,
                        "tenancy": {},
                    }
                price_info[instance_type]["tenancy"][ec2_tenancy] = price
            if instance_type not in price_info:
                log.error(
                    (
                        f"Error in pricing API call, instance type {instance_type} "
                        f"was not found in price list: {pformat(price_list)}"
                    )
                )
                return None
            node = AWSEC2InstanceType(
                instance_type, {}, account=self.account, region=region
            )
            node.instance_cores = price_info[instance_type]["cores"]
            node.instance_memory = price_info[instance_type]["memory"]
            node.ondemand_cost = price_info[instance_type]["tenancy"]["default"]
            quota_type = "vcpu"
            if instance_type.startswith(("a", "c", "d", "h", "i", "m", "r", "t", "z")):
                quota_name = "standard_ondemand"
            elif instance_type.startswith("f"):
                quota_name = "f_ondemand"
            elif instance_type.startswith("g"):
                quota_name = "g_ondemand"
            elif instance_type.startswith("p"):
                quota_name = "p_ondemand"
            elif instance_type.startswith("x"):
                quota_name = "x_ondemand"
            elif instance_type.startswith("inf"):
                quota_name = "inf_ondemand"
            else:
                quota_type = "standard"
                quota_name = instance_type
            quota_node_name = quota_name + "_quota"
            quota_node = graph.search_first("name", quota_node_name)
            if not isinstance(quota_node, BaseQuota):
                quota_node = AWSEC2InstanceQuota(
                    quota_node_name, {}, account=self.account, region=region
                )
                quota_node.quota = self.get_ec2_instance_type_quota(region, quota_name)
                quota_node.quota_type = quota_type
                graph.add_resource(region, quota_node)
            self._price_info["ec2"][region.id][instance_type] = node
            graph.add_resource(region, node)
            graph.add_edge(quota_node, node)
            log.debug(
                (
                    f"Found instance type info for {node.dname} in account {self.account.dname} region {region.name}: "
                    f"Cores {node.instance_cores}, Memory {node.instance_memory}, OnDemand Cost {node.ondemand_cost}"
                )
            )
            return node

    def get_volume_type_info(
        self, region: AWSRegion, graph: Graph, volume_type: str
    ) -> Optional[AWSEC2VolumeType]:
        with self._price_info_lock:
            if region.id not in self._price_info["ebs"]:
                self._price_info["ebs"][region.id] = {}

            if volume_type in self._price_info["ebs"][region.id]:
                return self._price_info["ebs"][region.id][volume_type]

            if region.id not in EC2_TO_PRICING_REGIONS:
                return None

            service = "AmazonEC2"
            search_filter = [
                {
                    "Type": "TERM_MATCH",
                    "Field": "volumeType",
                    "Value": EBS_TO_PRICING_NAMES[volume_type],
                },
                {
                    "Type": "TERM_MATCH",
                    "Field": "location",
                    "Value": EC2_TO_PRICING_REGIONS[region.id],
                },
            ]

            log.debug(
                (
                    f"Retrieving pricing information for volumes of type {volume_type} in "
                    f"account {self.account.dname} region {region.id}"
                )
            )
            price_list = self.get_price_info(service, search_filter)

            price_info = 0.0

            for price in price_list:
                attributes = price.get("product", {}).get("attributes")
                terms = price.get("terms")
                attr_volume_type = attributes.get("volumeType")
                if EBS_TO_PRICING_NAMES[volume_type] != attr_volume_type:
                    log.error(
                        (
                            f"Error in pricing API call, returned volume type {attr_volume_type} "
                            f"doesn't match requested volume type {EBS_TO_PRICING_NAMES[volume_type]}"
                        )
                    )
                    return None
                od = terms.get("OnDemand", {})
                id1 = list(od)[0]
                id2 = list(od[id1]["priceDimensions"])[0]
                price = float(od[id1]["priceDimensions"][id2]["pricePerUnit"]["USD"])
                price_info = price
                if price_info > 0:
                    break
            node = AWSEC2VolumeType(
                volume_type, {}, account=self.account, region=region
            )
            node.ondemand_cost = price_info
            node.quota = self.get_ebs_volume_type_quota(region, volume_type)
            self._price_info["ebs"][region.id][volume_type] = node
            graph.add_resource(region, node)
            log.debug(
                (
                    f"Found volume type info for {node.dname} in account {self.account.dname} "
                    f"region {region.id}: OnDemand Cost {node.ondemand_cost}"
                )
            )
            return node

    @staticmethod
    def tags_as_dict(tags: List) -> Dict:
        return {tag["Key"]: tag["Value"] for tag in tags or []}

    @staticmethod
    def parameters_as_dict(parameters: List) -> Dict:
        return {
            parameter["ParameterKey"]: parameter["ParameterValue"]
            for parameter in parameters or []
        }
