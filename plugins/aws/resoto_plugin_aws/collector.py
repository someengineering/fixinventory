import concurrent
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass
from typing import List, Type

from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource.base import AWSRegion, AWSAccount, AWSResource, GraphBuilder
from resoto_plugin_aws.resource.ec2 import AWSEC2Instance, AWSEC2KeyPair, AWSEC2Volume, AWSEC2NetworkAcl
from resotolib.baseresources import Cloud, EdgeType
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.aws")


@dataclass
class AwsResourceSpec:
    resource: Type[AWSResource]
    service: str
    api_action: str
    result_property: str

    def collect(self, builder: GraphBuilder) -> None:
        log.debug(f"Collecting {self.resource.__name__} in region {builder.region.name}")
        try:
            response = builder.client.call(self.service, self.api_action)
            items = response.get(self.result_property, [])
            self.resource.collect(items, builder)
        except Boto3Error as e:
            log.error(f"Error while collecting {self.resource.__name__} in region {builder.region.name}: {e}")
            raise


global_resources: List[AwsResourceSpec] = []  # iam, s3, route53, etc.
regional_resources: List[AwsResourceSpec] = [
    AwsResourceSpec(AWSEC2Instance, "ec2", "describe-instances", "Reservations"),
    AwsResourceSpec(AWSEC2KeyPair, "ec2", "describe-key-pairs", "KeyPairs"),
    AwsResourceSpec(AWSEC2Volume, "ec2", "describe-volumes", "Volumes"),
    AwsResourceSpec(AWSEC2NetworkAcl, "ec2", "describe-network-acls", "NetworkAcls"),
]


class AwsAccountCollector:
    def __init__(self, config: AwsConfig, cloud: Cloud, account: AWSAccount, regions: List[str]) -> None:
        self.config = config
        self.cloud = cloud
        self.account = account
        self.global_region = AWSRegion("us-east-1", {}, name="global", _account=account)
        self.regions = [AWSRegion(region, {}, _account=account) for region in regions]
        self.graph = Graph(root=self.account)
        self.client = AwsClient(config, account.id, account.role)

    def collect(self) -> None:
        with ThreadPoolExecutor(
            max_workers=self.config.region_pool_size, thread_name_prefix=f"aws_{self.account.id}"
        ) as executor:
            # collect all resources as parallel as possible
            futures: List[Future[None]] = [executor.submit(self.update_account)]

            # all regional resources for all configured regions
            for region in self.regions:
                client = self.client.for_region(region.name)
                builder = GraphBuilder(self.graph, self.cloud, self.account, region, client)
                for resource in regional_resources:
                    if self.config.should_collect(resource.resource.kind):
                        futures.append(executor.submit(resource.collect, builder))

            # all global resources
            builder = GraphBuilder(self.graph, self.cloud, self.account, self.global_region, self.client)
            for resource in global_resources:
                if self.config.should_collect(resource.resource.kind):
                    futures.append(executor.submit(resource.collect, builder))

            # wait until all futures are complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    log.exception(f"Unhandled exception in account {self.account.name} region {region.name}")

            # connect account to all regions
            for region in self.regions:
                builder.add_edge(self.account, EdgeType.default, node=region)

            # connect nodes
            for node, data in list(self.graph.nodes(data=True)):
                if isinstance(node, AWSResource):
                    if rg := node.region():
                        builder.add_edge(rg, EdgeType.default, node=node)
                    node.connect_in_graph(builder, data.get("source", {}))
                else:
                    raise Exception("Only AWS resources expected")

    def update_account(self) -> None:
        # account alias
        try:
            result = self.client.call("iam", "list_account_aliases")
            account_aliases = result.get("AccountAliases", [])
            if account_aliases:
                self.account.name = self.account.account_alias = account_aliases[0]
        except ClientError as e:
            log.debug(f"Could not get account aliases: {e}")

        log.info(f"Collecting AWS IAM Account Summary in account {self.account.dname}")
        response_as = self.client.call("iam", "get_account_summary")
        sm = response_as.get("SummaryMap", {})
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
            response_app = self.client.call("iam", "get_account_password_policy")
            app = response_app.get("PasswordPolicy", {})
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
        except Boto3Error:
            log.debug(f"The Password Policy for account {self.account.dname} cannot be found.")
