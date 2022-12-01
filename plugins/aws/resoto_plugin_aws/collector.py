import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Type

from botocore.exceptions import ClientError

from resoto_plugin_aws.aws_client import AwsClient
from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.resource import (
    apigateway,
    athena,
    autoscaling,
    cloudformation,
    cloudwatch,
    dynamodb,
    ec2,
    ecs,
    eks,
    elasticbeanstalk,
    elasticache,
    elb,
    elbv2,
    glacier,
    iam,
    kinesis,
    kms,
    lambda_,
    rds,
    route53,
    s3,
    service_quotas,
    sns,
    sqs,
    redshift,
)
from resoto_plugin_aws.resource.base import AwsRegion, AwsAccount, AwsResource, GraphBuilder, ExecutorQueue, AwsApiSpec
from resotolib.baseresources import Cloud, EdgeType
from resotolib.core.actions import CoreFeedback
from resotolib.graph import Graph
from resotolib.proc import set_thread_name

log = logging.getLogger("resoto.plugins.aws")


global_resources: List[Type[AwsResource]] = (
    dynamodb.global_resources
    + ec2.global_resources
    + iam.resources
    + route53.resources
    + s3.resources
    + service_quotas.resources
)
regional_resources: List[Type[AwsResource]] = (
    apigateway.resources
    + autoscaling.resources
    + athena.resources
    + cloudformation.resources
    + cloudwatch.resources
    + dynamodb.resources
    + ec2.resources
    + ecs.resources
    + eks.resources
    + elasticbeanstalk.resources
    + elasticache.resources
    + elb.resources
    + elbv2.resources
    + glacier.resources
    + kinesis.resources
    + kms.resources
    + lambda_.resources
    + rds.resources
    + service_quotas.resources
    + sns.resources
    + sqs.resources
    + redshift.resources
)
all_resources: List[Type[AwsResource]] = global_resources + regional_resources


def called_collect_apis() -> List[AwsApiSpec]:
    """
    Return a list of all the APIs that are called by the collector during the collect cycle.
    """
    # list all calls here, that are not defined in any resource.
    additional_calls = [AwsApiSpec("pricing", "get-products")]
    specs = [spec for r in all_resources for spec in r.called_collect_apis()] + additional_calls
    return sorted(specs, key=lambda s: s.service + "::" + s.api_action)


def called_mutator_apis() -> List[AwsApiSpec]:
    """
    Return a list of all the APIs that are called to mutate resources.
    """
    # explicitly list all calls here, that should be allowed to mutate resources.
    additional_calls = [AwsApiSpec("ec2", "start-instances"), AwsApiSpec("ec2", "stop-instances")]
    specs = [spec for r in all_resources for spec in r.called_mutator_apis()] + additional_calls
    return sorted(specs, key=lambda s: s.service + "::" + s.api_action)


class AwsAccountCollector:
    def __init__(
        self, config: AwsConfig, cloud: Cloud, account: AwsAccount, regions: List[str], core_feedback: CoreFeedback
    ) -> None:
        self.config = config
        self.cloud = cloud
        self.account = account
        self.core_feedback = core_feedback
        self.global_region = AwsRegion(id="us-east-1", tags={}, name="global", account=account)
        self.regions = [AwsRegion(id=region, tags={}, account=account) for region in regions]
        self.graph = Graph(root=self.account)
        self.client = AwsClient(
            config,
            account.id,
            role=account.role,
            profile=account.profile,
            region="us-east-1",
            core_feedback=core_feedback,
        )

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"aws_{self.account.id}", max_workers=self.config.shared_pool_size
        ) as executor:
            # The shared executor is used to parallelize the collection of resources "as fast as possible"
            # It should only be used in scenarios, where it is safe to do so.
            # This executor is shared between all regions.
            shared_queue = ExecutorQueue(executor, self.account.safe_name)
            shared_queue.submit_work(self.update_account)
            global_builder = GraphBuilder(
                self.graph, self.cloud, self.account, self.global_region, self.client, shared_queue, self.core_feedback
            )
            global_builder.core_feedback.progress_done(self.global_region.safe_name, 0, 1)
            global_builder.add_node(self.global_region)

            log.info(f"[Aws:{self.account.id}] Collect global resources.")

            # all global resources
            for resource in global_resources:
                if self.config.should_collect(resource.kind):
                    resource.collect_resources(global_builder)
            shared_queue.wait_for_submitted_work()
            global_builder.core_feedback.progress_done(self.global_region.safe_name, 1, 1)

            log.info(f"[Aws:{self.account.id}] Collect regional resources.")

            # all regions are collected in parallel.
            # note: when the thread pool context is left, all submitted work is done (or an exception has been thrown)
            with ThreadPoolExecutor(
                thread_name_prefix=f"aws_{self.account.id}_regions", max_workers=self.config.region_pool_size
            ) as per_region_executor:
                for region in self.regions:
                    per_region_executor.submit(self.collect_region, region, global_builder.for_region(region))

            log.info(f"[Aws:{self.account.id}] Connect resources and create edges.")

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
            self.core_feedback.progress_done(self.account.dname, 1, 1, context=[self.cloud.id])

            log.info(f"[Aws:{self.account.id}] Collecting resources done.")

    def collect_region(self, region: AwsRegion, regional_builder: GraphBuilder) -> None:
        def collect_resource(resource: Type[AwsResource], rb: GraphBuilder) -> None:
            try:
                resource.collect_resources(rb)
                log.info(f"[Aws:{self.account.id}:{region.safe_name}] finished collecting: {resource.kind}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "UnauthorizedOperation":
                    msg = (
                        f"Not authorized to collect {resource.kind} resources in account"
                        f" {self.account.id} region {region.id} - skipping resource"
                    )
                    self.core_feedback.error(msg, log)
                    return None

        try:
            regional_thread_name = f"aws_{self.account.id}_{region.id}"
            set_thread_name(regional_thread_name)
            with ThreadPoolExecutor(
                thread_name_prefix=regional_thread_name, max_workers=self.config.region_resources_pool_size
            ) as executor:
                regional_builder.core_feedback.progress_done(region.safe_name, 0, 1)
                # In case an exception is thrown for any resource, we should give up as quick as possible.
                queue = ExecutorQueue(executor, region.safe_name, fail_on_first_exception=True)
                regional_builder.add_node(region)
                for res in regional_resources:
                    if self.config.should_collect(res.kind):
                        queue.submit_work(collect_resource, res, regional_builder)
                queue.wait_for_submitted_work()
                regional_builder.core_feedback.progress_done(region.safe_name, 1, 1)
        except Exception as e:
            msg = f"Error collecting resources in account {self.account.id} region {region.id}: {e} - skipping region"
            self.core_feedback.error(msg, log)
            return None

    def update_account(self) -> None:
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

        # client returns None when there is no Custom PasswordPolicy defined (only AWS Default).
        app = self.client.get("iam", "get-account-password-policy", "PasswordPolicy", expected_errors=["NoSuchEntity"])
        if app:
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
