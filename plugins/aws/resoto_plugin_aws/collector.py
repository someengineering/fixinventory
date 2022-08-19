import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Type

from botocore.exceptions import ClientError

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource import (
    athena,
    autoscaling,
    cloudformation,
    cloudwatch,
    dynamodb,
    ec2,
    eks,
    elasticbeanstalk,
    elasticache,
    elb,
    elbv2,
    iam,
    kinesis,
    kms,
    lambda_,
    rds,
    route53,
    s3,
    service_quotas,
    sqs,
    redshift,
)
from resoto_plugin_aws.resource.base import AwsRegion, AwsAccount, AwsResource, GraphBuilder, ExecutorQueue
from resotolib.baseresources import Cloud, EdgeType
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.aws")


global_resources: List[Type[AwsResource]] = (
    dynamodb.global_resources + ec2.global_resources + iam.resources + route53.resources + s3.resources
)
regional_resources: List[Type[AwsResource]] = (
    autoscaling.resources
    + athena.resources
    + cloudformation.resources
    + cloudwatch.resources
    + dynamodb.resources
    + ec2.resources
    + eks.resources
    + elasticbeanstalk.resources
    + elasticache.resources
    + elb.resources
    + elbv2.resources
    + kinesis.resources
    + kms.resources
    + lambda_.resources
    + rds.resources
    + service_quotas.resources
    + sqs.resources
    + redshift.resources
)
all_resources: List[Type[AwsResource]] = global_resources + regional_resources


class AwsAccountCollector:
    def __init__(self, config: AwsConfig, cloud: Cloud, account: AwsAccount, regions: List[str]) -> None:
        self.config = config
        self.cloud = cloud
        self.account = account
        self.global_region = AwsRegion(id="us-east-1", tags={}, name="global", account=account)
        self.regions = [AwsRegion(id=region, tags={}, account=account) for region in regions]
        self.graph = Graph(root=self.account)
        self.client = AwsClient(config, account.id, role=account.role, profile=account.profile, region="us-east-1")

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"aws_{self.account.id}", max_workers=self.config.shared_pool_size
        ) as executor:
            shared_queue = ExecutorQueue(executor, self.account.name)
            shared_queue.submit_work(self.update_account)
            global_builder = GraphBuilder(
                self.graph, self.cloud, self.account, self.global_region, self.client, shared_queue
            )
            global_builder.add_node(self.global_region)

            # all global resources
            for resource in global_resources:
                if self.config.should_collect(resource.kind):
                    resource.collect_resources(global_builder)
            shared_queue.wait_for_submitted_work()

            # all regions are collected in parallel.
            # note: when the thread pool context is left, all submitted work is done (or an exception has been thrown)
            with ThreadPoolExecutor(
                thread_name_prefix=f"aws_{self.account.id}_regions", max_workers=self.config.region_pool_size
            ) as per_region_executor:
                for region in self.regions:
                    per_region_executor.submit(self.collect_region, region, global_builder)

            # connect nodes
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, AwsResource):
                    if isinstance(node, AwsAccount):
                        pass
                    elif isinstance(node, AwsRegion):
                        global_builder.add_edge(self.account, EdgeType.default, node=node)
                    elif rg := node.region():
                        global_builder.add_edge(rg, EdgeType.default, node=node)
                    else:
                        global_builder.add_edge(self.account, EdgeType.default, node=node)
                    node.connect_in_graph(global_builder, data.get("source", {}))
                else:
                    raise Exception("Only AWS resources expected")

            # wait for all futures to finish
            shared_queue.wait_for_submitted_work()

    def collect_region(self, region: AwsRegion, global_builder: GraphBuilder) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"aws_{self.account.id}_{region.id}",
            max_workers=self.config.region_resources_pool_size,
        ) as executor:
            queue = ExecutorQueue(executor, region.name)
            global_builder.add_node(region)
            region_builder = global_builder.for_region(region, queue)
            for resource in regional_resources:
                if self.config.should_collect(resource.kind):
                    resource.collect_resources(region_builder)

    def update_account(self) -> None:
        # account alias
        try:
            if account_aliases := self.client.list("iam", "list_account_aliases", "AccountAliases"):
                self.account.name = self.account.account_alias = account_aliases[0]
        except ClientError as e:
            log.debug(f"Could not get account aliases: {e}")

        log.info(f"Collecting AWS IAM Account Summary in account {self.account.dname}")
        sm = self.client.get("iam", "get-account-summary", "SummaryMap") or {}
        self.account.users = int(sm.get("Users", 0))
        self.account.groups = int(sm.get("Groups", 0))
        self.account.account_mfa_enabled = int(sm.get("AccountMFAEnabled", 0))
        self.account.account_access_keys_present = int(sm.get("AccountAccessKeysPresent", 0))
        self.account.account_signing_certificates_present = int(sm.get("AccountSigningCertificatesPresent", 0))
        self.account.mfa_devices = int(sm.get("MFADevices", 0))
        self.account.mfa_devices_in_use = int(sm.get("MFADevicesInUse", 0))
        self.account.policies = int(sm.get("Policies", 0))
        self.account.policy_versions_in_use = int(sm.get("PolicyVersionsInUse", 0))
        self.account.global_endpoint_token_version = int(sm.get("GlobalEndpointTokenVersion", 0))
        self.account.server_certificates = int(sm.get("ServerCertificates", 0))

        # boto will fail, when there is no Custom PasswordPolicy defined (only AWS Default). This is intended behaviour.
        try:
            app = self.client.get("iam", "get-account-password-policy", "PasswordPolicy") or {}
            self.account.minimum_password_length = int(app.get("MinimumPasswordLength", 0))
            self.account.require_symbols = bool(app.get("RequireSymbols", None))
            self.account.require_numbers = bool(app.get("RequireNumbers", None))
            self.account.require_uppercase_characters = bool(app.get("RequireUppercaseCharacters", None))
            self.account.require_lowercase_characters = bool(app.get("RequireLowercaseCharacters", None))
            self.account.allow_users_to_change_password = bool(app.get("AllowUsersToChangePassword", None))
            self.account.expire_passwords = bool(app.get("ExpirePasswords", None))
            self.account.max_password_age = int(app.get("MaxPasswordAge", 0))
            self.account.password_reuse_prevention = int(app.get("PasswordReusePrevention", 0))
            self.account.hard_expiry = bool(app.get("HardExpiry", None))
        except Exception:
            log.debug(f"The Password Policy for account {self.account.dname} cannot be found.")
