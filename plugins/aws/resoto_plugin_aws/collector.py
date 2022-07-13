import concurrent
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from typing import List, Type, Any

from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.config import AwsConfig
from resoto_plugin_aws.resource import iam, ec2, route53, elbv2, autoscaling, s3, cloudwatch, cloudformation, eks
from resoto_plugin_aws.resource.base import AwsRegion, AwsAccount, AwsResource, GraphBuilder, AwsApiSpec
from resotolib.baseresources import Cloud, EdgeType
from resotolib.graph import Graph

log = logging.getLogger("resoto.plugins.aws")


global_resources: List[Type[AwsResource]] = iam.resources + route53.resources + ec2.global_resources + s3.resources
regional_resources: List[Type[AwsResource]] = (
    ec2.resources
    + elbv2.resources
    + autoscaling.resources
    + cloudwatch.resources
    + cloudformation.resources
    + eks.resources
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
        self.client = AwsClient(config, account.id, account.role)

    @staticmethod
    def collect_resource(resource: Type[AwsResource], spec: AwsApiSpec, builder: GraphBuilder) -> None:
        log.debug(f"Collecting {resource.__name__} in region {builder.region.name}")
        try:
            kwargs = spec.parameter or {}
            items = builder.client.list(spec.service, spec.api_action, spec.result_property, **kwargs)
            resource.collect(items, builder)
        except Boto3Error as e:
            log.error(f"Error while collecting {resource.__name__} in region {builder.region.name}: {e}")
            raise

    def collect(self) -> None:
        def wait_for_futures(fs: List[Future[Any]]) -> None:
            # wait until all futures are complete
            for future in concurrent.futures.as_completed(fs):
                try:
                    future.result()
                except Exception as ex:
                    log.exception(f"Unhandled exception in account {self.account.name}: {ex}")
                    raise
            fs.clear()

        with ThreadPoolExecutor(
            max_workers=self.config.region_pool_size, thread_name_prefix=f"aws_{self.account.id}"
        ) as executor:
            # collect all resources as parallel as possible
            futures: List[Future[None]] = [executor.submit(self.update_account)]

            # all global resources
            builder = GraphBuilder(self.graph, self.cloud, self.account, self.global_region, self.client)
            for resource in global_resources:
                if (spec := resource.api_spec) and self.config.should_collect(resource.kind):
                    futures.append(executor.submit(self.collect_resource, resource, spec, builder))
            wait_for_futures(futures)

            # all regional resources for all configured regions
            for region in self.regions:
                region_builder = builder.for_region(region)
                for resource in regional_resources:
                    if (spec := resource.api_spec) and self.config.should_collect(resource.kind):
                        futures.append(executor.submit(self.collect_resource, resource, spec, region_builder))
            wait_for_futures(futures)

            # connect account to all regions
            for region in self.regions:
                builder.add_edge(self.account, EdgeType.default, node=region)

            # connect nodes as parallel as possible
            for idx, (node, data) in enumerate(list(self.graph.nodes(data=True))):
                if isinstance(node, AwsResource):
                    if rg := node.region():
                        builder.add_edge(rg, EdgeType.default, node=node)
                    futures.append(executor.submit(node.connect_in_graph, builder, data.get("source", {})))
                    if idx % 100 == 0:  # only spawn 100 futures at a time
                        wait_for_futures(futures)
                else:
                    raise Exception("Only AWS resources expected")

            # wait for all futures to finish
            wait_for_futures(futures)

    def update_account(self) -> None:
        # account alias
        try:
            if account_aliases := self.client.list("iam", "list_account_aliases", "AccountAliases"):
                self.account.name = self.account.account_alias = account_aliases[0]
        except ClientError as e:
            log.debug(f"Could not get account aliases: {e}")

        log.info(f"Collecting AWS IAM Account Summary in account {self.account.dname}")
        sm = self.client.get("iam", "get_account_summary", "SummaryMap") or {}
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
            app = self.client.get("iam", "get_account_password_policy", "PasswordPolicy") or {}
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
