import logging
from concurrent.futures import ThreadPoolExecutor, Future
from typing import List, Type

from resoto_plugin_aws.aws_client import AwsClient, ErrorAccumulator
from resoto_plugin_aws.configuration import AwsConfig
from resoto_plugin_aws.resource import (
    apigateway,
    athena,
    autoscaling,
    config,
    cloudformation,
    cloudfront,
    cloudtrail,
    cloudwatch,
    cognito,
    dynamodb,
    ec2,
    ecs,
    efs,
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
    sagemaker,
    service_quotas,
    sns,
    sqs,
    redshift,
)
from resoto_plugin_aws.resource.base import (
    AwsRegion,
    AwsAccount,
    AwsResource,
    GraphBuilder,
    ExecutorQueue,
    AwsApiSpec,
    GatherFutures,
)
from resotolib.baseresources import Cloud, EdgeType
from resotolib.core.actions import CoreFeedback
from resotolib.core.progress import ProgressTree, ProgressDone
from resotolib.graph import Graph
from resotolib.proc import set_thread_name

log = logging.getLogger("resoto.plugins.aws")

global_resources: List[Type[AwsResource]] = (
    cloudfront.resources
    + dynamodb.global_resources
    + iam.resources
    + route53.resources
    + s3.resources
    + service_quotas.resources
)
regional_resources: List[Type[AwsResource]] = (
    sagemaker.resources  # start with sagemaker, because it is very slow
    + apigateway.resources
    + autoscaling.resources
    + athena.resources
    + config.resources
    + cloudformation.resources
    + cloudtrail.resources
    + cloudwatch.resources
    + cognito.resources
    + dynamodb.resources
    + ec2.resources
    + efs.resources
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
    additional_calls = [
        AwsApiSpec("pricing", "get-products"),
        AwsApiSpec("ec2", "describe-regions"),
        AwsApiSpec("iam", "get-account-summary"),
        AwsApiSpec("iam", "get-account-password-policy"),
        AwsApiSpec("iam", "list-account-aliases"),
        AwsApiSpec("organizations", "list-accounts"),
    ]
    additional_calls += cloudwatch.AwsCloudwatchMetricData.called_collect_apis()
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
        self.error_accumulator = ErrorAccumulator()
        self.client = AwsClient(
            config,
            account.id,
            role=account.role,
            profile=account.profile,
            region=self.global_region.id,
            error_accumulator=self.error_accumulator,
        )

    def collect(self) -> None:
        with ThreadPoolExecutor(
            thread_name_prefix=f"aws_{self.account.id}", max_workers=self.config.resource_pool_size
        ) as executor:
            # The shared executor is used to spread work for the whole account.
            # Note: only tasks_per_key threads are running max for each region.
            tpk = self.config.shared_tasks_per_key([r.id for r in self.regions])
            shared_queue = ExecutorQueue(executor, tasks_per_key=tpk, name=self.account.safe_name)
            global_builder = GraphBuilder(
                self.graph, self.cloud, self.account, self.global_region, self.client, shared_queue, self.core_feedback
            )
            global_builder.submit_work("iam", self.update_account)

            # mark open progress for all regions
            progress = ProgressTree(self.account.dname, path=[self.cloud.id])
            progress.add_progress(ProgressDone(self.global_region.safe_name, 0, 1))
            for region in self.regions:
                progress.add_progress(ProgressDone(region.safe_name, 0, 1))
            global_builder.core_feedback.progress(progress)

            # all global resources
            log.info(f"[Aws:{self.account.id}] Collect global resources.")
            self.collect_resources(global_resources, global_builder, shared_queue)

            # regions are collected with the configured parallelism
            # note: when the thread pool context is left, all submitted work is done (or an exception has been thrown)
            log.info(f"[Aws:{self.account.id}] Collect regional resources.")
            for region in self.regions:
                self.collect_resources(regional_resources, global_builder.for_region(region), shared_queue)
            shared_queue.wait_for_submitted_work()

            # connect nodes
            log.info(f"[Aws:{self.account.id}] Connect resources and create edges.")
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
            self.error_accumulator.report_all(global_builder.core_feedback)

            log.info(f"[Aws:{self.account.id}] Collecting resources done.")

    def collect_resources(
        self,
        resources: List[Type[AwsResource]],
        builder: GraphBuilder,
        resource_queue: ExecutorQueue,
    ) -> Future[None]:
        region = builder.region

        def collect_resource(resource: Type[AwsResource], rb: GraphBuilder) -> None:
            try:
                set_thread_name(f"aws_{self.account.id}_{region.id}_{resource.kind}")
                resource.collect_resources(rb)
                log.info(f"[Aws:{self.account.id}:{region.safe_name}] finished collecting: {resource.kind}")
            except Exception as e:
                msg = (
                    f"Error collecting resources {resource.__name__} in account {self.account.id} "
                    f"region {region.id}: {e} - skipping region"
                )
                builder.core_feedback.error(msg, log)
                raise

        region_futures = []
        builder.add_node(region)
        for res in resources:
            if self.config.should_collect(res.kind):
                key = region.id + ":" + res.api_spec.service if res.api_spec else "global"
                region_futures.append(resource_queue.submit_work(key, collect_resource, res, builder))

        def work_done(_: Future[None]) -> None:
            builder.core_feedback.progress_done(region.safe_name, 1, 1)
            self.error_accumulator.report_region(builder.core_feedback, region.id)

        # once all futures are done
        when_done = GatherFutures.all(region_futures)
        when_done.add_done_callback(work_done)
        return when_done

    # TODO: move into separate AwsAccountSettings
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
