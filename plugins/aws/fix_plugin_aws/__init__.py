import logging
import multiprocessing
import os
from concurrent import futures
from typing import List, Optional, Tuple, Union, Sequence, Any
import subprocess
import json

import boto3
import botocore.exceptions
from prometheus_client import Counter, Summary

import fixlib.logger
import fixlib.proc
from fixlib.args import ArgumentParser, Namespace
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    Cloud,
    metrics_resource_cleanup_exceptions,
    metrics_resource_pre_cleanup_exceptions,
)
from fixlib.config import Config, RunningConfig
from fixlib.core.actions import CoreFeedback
from fixlib.core.custom_command import execute_command_on_resource
from fixlib.core.progress import ProgressDone, ProgressTree
from fixlib.graph import Graph
from fixlib.logger import log, setup_logger
from fixlib.types import JsonElement, Json
from fixlib.utils import log_runtime
from .collector import AwsAccountCollector
from .configuration import AwsConfig
from .resource.base import AwsAccount, AwsResource, get_client
from .utils import arn_partition_by_region, aws_session, global_region_by_partition

logging.getLogger("boto").setLevel(logging.CRITICAL)

metrics_collect = Summary("fix_plugin_aws_collect_seconds", "Time it took the collect() method")
metrics_unhandled_account_exceptions = Counter(
    "fix_plugin_aws_unhandled_account_exceptions_total",
    "Unhandled AWS Plugin Account Exceptions",
    ["account"],
)

GLOBAL_REGIONS = ("us-east-1", "us-gov-west-1", "cn-north-1")


class AWSCollectorPlugin(BaseCollectorPlugin):
    cloud = "aws"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__regions: List[str] = []
        self.core_feedback: Optional[CoreFeedback] = None

    @staticmethod
    def add_config(cfg: Config) -> None:
        cfg.add_config(AwsConfig)

    @staticmethod
    def auto_enableable() -> bool:
        for region in GLOBAL_REGIONS:
            try:
                account_id = (
                    boto3.session.Session(region_name=region).client("sts").get_caller_identity().get("Account")
                )
                log.debug(f"plugin: AWS auto discovery succeeded in {region}, running in account {account_id}.")
                return True
            except Exception as e:
                log.debug(f"plugin: AWS auto discovery failed in {region}: {e}")
        return False

    @metrics_collect.time()
    def collect(self) -> None:
        try:
            self.collect_aws()
        except Exception as ex:
            if self.core_feedback:
                self.core_feedback.error(f"Unhandled exception in AWS Plugin: {ex}", log)
            else:
                log.warning(f"No CoreFeedback available! Unhandled exception in AWS Plugin: {ex}")
            raise

    def collect_aws(self) -> None:
        log.debug("plugin: AWS collecting resources")
        aws_config: AwsConfig = Config.aws
        assert self.core_feedback, "core_feedback is not set"

        accounts = get_accounts(self.core_feedback.with_context(self.root.id))
        if len(accounts) == 0:
            log.warning("No accounts found")
            return

        progress = ProgressTree(self.cloud)
        for account in accounts:
            # Even if the account is collected later, mark it as expected progress
            progress.add_progress(ProgressDone(account.dname, 0, 1))
            add_str = f" partition {account.partition}"
            if account.role:
                add_str += f" role {account.role}"
            if account.profile:
                add_str += f" profile {account.profile}"
            log.debug(f"Found {account.rtdname}{add_str}")
        self.core_feedback.progress(progress)

        max_workers = len(accounts) if len(accounts) < aws_config.account_pool_size else aws_config.account_pool_size
        pool_args = {"max_workers": max_workers}
        pool_executor = futures.ThreadPoolExecutor
        if aws_config.fork_process:
            collect_method = collect_in_process
        else:
            collect_method = collect_account

        with pool_executor(**pool_args) as executor:  # type: ignore
            wait_for = [
                executor.submit(
                    collect_method,
                    account,
                    self.regions(profile=account.profile, partition=account.partition),
                    ArgumentParser.args,
                    Config.running_config,
                    self.core_feedback.with_context(self.root.id, account.dname),
                    self.root,
                    self.task_data or {},
                )
                for account in accounts
            ]
            for future in futures.as_completed(wait_for):
                account_graph = future.result()
                if not isinstance(account_graph, Graph):
                    log.debug(f"Skipping account graph of invalid type {type(account_graph)}")
                    continue
                self.send_account_graph(account_graph)
                del account_graph

        # collect done, purge all session caches
        aws_config.sessions().purge_caches()

    def regions(self, profile: Optional[str] = None, partition: str = "aws") -> List[str]:
        if len(self.__regions) == 0:
            if not Config.aws.region or (isinstance(Config.aws.region, list) and len(Config.aws.region) == 0):
                add_log_str = ""
                if profile:
                    add_log_str += f" profile {profile}"
                if partition:
                    add_log_str += f" partition {partition}"
                log.debug(f"AWS region not specified, assuming all regions{add_log_str}")
                self.__regions = all_regions(profile=profile, partition=partition)
            else:
                self.__regions = list(Config.aws.region)
        return self.__regions

    @execute_command_on_resource(
        name="aws",
        info="Execute aws commands on AWS resources",
        args_description={
            "service": "Defines the AWS service, like ec2, s3, iam, etc.",
            "operation": "Defines the operation to execute.",
            "operation_args": "Defines the arguments for the operation. The parameters depend on the operation.",
            "--account": "[Optional] The AWS account identifier.",
            "--role": "[Optional] The AWS role.",
            "--profile": "[Optional] The AWS profile to use.",
            "--region": "[Optional] The AWS region.",
        },
        description="Execute an operation on an AWS resource.\n"
        "For a list of services with respective operations see "
        "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/index.html#available-services\n\n"
        "By default the operation runs with the same credentials as the collect process.\n"
        "You can override the credentials by providing the account, role, profile and region arguments.\n\n"
        "There are two modes of operation:\n"
        "1. Use a search and then pipe the result of the search into the `aws` command. "
        "Every resource matched by the search will invoke this command. "
        "You can use templating parameter to define the exact invocation arguments. "
        "Account, region, profile and role is defined by the resource if not defined explicitly.\n"
        "2. Call the `aws` command directly without passing any resource to interact "
        "with AWS using the credentials defined via configuration.\n\n"
        "## Examples\n\n"
        "```shell\n"
        "# Search for all ec2 volumes and then call describe-volumes on each volume\n"
        "# See AWS CLI for available services and commands.\n"
        "# Please note the {id} parameter. The aws command is invoked for any volume and replaces the id parameter"
        " with the volume id.\n"
        "> search is(aws_ec2_volume) | aws ec2 describe-volume-attribute --volume-id {id} --attribute autoEnableIO\n"
        "AutoEnableIO:\n"
        "Value: false\n"
        "VolumeId: vol-009b0a28d2754927e\n\n"
        "# Get the current caller identity\n"
        "> aws sts get-caller-identity\n"
        "UserId: AIDA42373XXXXXXXXXXXX\n"
        "Account: '882374444444'\n"
        "Arn: arn:aws:iam::882374444444:user/matthias\n"
        "```\n\n",
        allowed_on_kind="aws_resource",
    )
    def call_aws_function(
        self, config: Config, resource: Optional[BaseResource], args: List[str]
    ) -> Union[JsonElement, BaseResource]:
        if resource:
            ac = resource.account()
            session = aws_session(ac.id, ac.role, ac.profile, ac.partition)  # type: ignore
        else:
            session = aws_session()

        credentials = session.get_credentials()
        env = os.environ.copy()

        env["AWS_ACCESS_KEY_ID"] = credentials.access_key
        env["AWS_SECRET_ACCESS_KEY"] = credentials.secret_key
        env["AWS_SESSION_TOKEN"] = credentials.token
        if resource:
            env["AWS_DEFAULT_REGION"] = resource.region().id
        else:
            env["AWS_DEFAULT_REGION"] = session.region_name

        cli_result = subprocess.run(["aws"] + args, timeout=10, capture_output=True, check=False, env=env)
        if cli_result.returncode != 0:
            raise RuntimeError(f"AWS {cli_result.stderr.decode('utf-8')}")
        response_str = cli_result.stdout.decode("utf-8")
        try:
            response = json.loads(response_str)
        except Exception:
            response = response_str.splitlines()
        if not response:
            result = []
        elif isinstance(response, list):
            result = response
        else:
            result = [response]

        return result[0] if len(result) == 1 else result

    @staticmethod
    def update_tag(config: Config, resource: BaseResource, key: str, value: str) -> bool:
        """Update the tag of a resource"""
        if isinstance(resource, AwsResource):
            client = get_client(config, resource)
            return resource.update_resource_tag(client, key, value)

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")

    @staticmethod
    def delete_tag(config: Config, resource: BaseResource, key: str) -> bool:
        """Delete the tag of a resource"""
        if isinstance(resource, AwsResource):
            client = get_client(config, resource)
            return resource.delete_resource_tag(client, key)

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")

    @staticmethod
    def pre_cleanup(config: Config, resource: BaseResource, graph: Graph) -> bool:
        if isinstance(resource, AwsResource):
            client = get_client(config, resource)

            if not hasattr(resource, "pre_delete_resource"):
                return True

            if graph is None:
                graph = resource._graph

            if resource.protected:
                log.warning(f"Resource {resource.rtdname} is protected - refusing modification")
                resource.log("Modification was requested even though resource is protected" " - refusing")
                return False

            if resource.phantom:
                log.warning(f"Can't cleanup phantom resource {resource.rtdname}")
                return False

            if resource.cleaned:
                log.debug(f"Resource {resource.rtdname} has already been cleaned up")
                return True

            account = resource.account(graph)
            region = resource.region(graph)
            if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                log.warning(f"Could not determine account or region for pre cleanup of {resource.rtdname}")
                return False

            log_suffix = f" in account {account.dname} region {region.name}"
            resource.log("Trying to run pre clean up")
            log.debug(f"Trying to run pre clean up {resource.rtdname}{log_suffix}")
            try:
                if not getattr(resource, "pre_delete_resource")(client, graph):
                    resource.log("Failed to run pre clean up")
                    log.warning(f"Failed to run pre clean up {resource.rtdname}{log_suffix}")
                    return False
                resource.log("Successfully ran pre clean up")
                log.info(f"Successfully ran pre clean up {resource.rtdname}{log_suffix}")
            except Exception as e:
                resource.log("An error occurred during pre clean up", exception=e)
                log.warning(f"An error occurred during pre clean up {resource.rtdname}{log_suffix}")
                cloud = resource.cloud(graph)
                metrics_resource_pre_cleanup_exceptions.labels(
                    cloud=cloud.name,
                    account=account.dname,
                    region=region.name,
                    kind=resource.kind,
                ).inc()
                raise
            return True

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")

    @staticmethod
    def cleanup(config: Config, resource: BaseResource, graph: Graph) -> bool:
        if isinstance(resource, AwsResource):
            if resource.phantom:
                raise RuntimeError(f"Can't cleanup phantom resource {resource.rtdname}")

            if resource.cleaned:
                log.debug(f"Resource {resource.rtdname} has already been cleaned up")
                return True

            if resource.protected:
                log.warning(f"Resource {resource.rtdname} is protected - refusing modification")
                resource.log(("Modification was requested even though resource is protected" " - refusing"))
                return False

            resource._changes.add("cleaned")
            if graph is None:
                graph = resource._graph

            account = resource.account(graph)
            region = resource.region(graph)
            if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                raise RuntimeError(f"Could not determine account or region for cleanup of {resource.rtdname}")

            log_suffix = f" in account {account.dname} region {region.name}"
            resource.log("Trying to clean up")
            log.debug(f"Trying to clean up {resource.rtdname}{log_suffix}")
            try:
                if deleted := resource.delete(graph):
                    resource._cleaned = True
                    resource.log("Successfully cleaned up")
                    log.info(f"Successfully cleaned up {resource.rtdname}{log_suffix}")
            except Exception as e:
                resource.log("An error occurred during clean up", exception=e)
                log.exception(f"An error occurred during clean up {resource.rtdname}{log_suffix}")
                cloud = resource.cloud(graph)
                metrics_resource_cleanup_exceptions.labels(
                    cloud=cloud.name,
                    account=account.dname,
                    region=region.name,
                    kind=resource.kind,
                ).inc()
                return False
            if not deleted:
                raise RuntimeError(f"Failed to clean up {resource.rtdname}{log_suffix}")
            return True

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")


def authenticated(account: AwsAccount, core_feedback: CoreFeedback) -> bool:
    try:
        add_log_str = ""
        if account.role:
            add_log_str += f" role {account.role}"
        if account.profile:
            add_log_str += f" profile {account.profile}"
        if account.partition:
            add_log_str += f" partition {account.partition}"
        log.debug(f"AWS testing credentials for {account.rtdname}{add_log_str}")
        session = aws_session(
            account=account.id, role=account.role, profile=account.profile, partition=account.partition
        )
        _ = (
            session.client("sts", region_name=global_region_by_partition(account.partition))
            .get_caller_identity()
            .get("Account")
        )
    except botocore.exceptions.NoCredentialsError:
        core_feedback.error(f"No AWS credentials found for {account.rtdname}", log)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AuthFailure":
            core_feedback.error(f"Unable to validate the provided access credentials for {account.rtdname}", log)
        elif e.response["Error"]["Code"] == "InvalidClientTokenId":
            core_feedback.error(f"Unable to validate the provided security token for {account.rtdname}", log)
        elif e.response["Error"]["Code"] == "ExpiredToken":
            core_feedback.error(f"Security token included in the request is expired for {account.rtdname}", log)
        elif e.response["Error"]["Code"] == "AccessDenied":
            core_feedback.error(f"Access Denied to {account.rtdname}: {e}", log)
        elif e.response["Error"]["Code"] == "SignatureDoesNotMatch":
            core_feedback.error(f"Token signature does not match {account.rtdname}: {e}", log)
        else:
            raise
        return False
    return True


def current_account_id(profile: Optional[str] = None) -> str:
    account_id, _ = current_account_id_and_partition(profile)
    return account_id


def probe_partition(account: Optional[str] = None, role: Optional[str] = None, profile: Optional[str] = None) -> str:
    for region in GLOBAL_REGIONS:
        partition = arn_partition_by_region(region)
        try:
            session = aws_session(account=account, role=role, profile=profile, partition=partition)
            _ = session.client("sts", region_name=region).get_caller_identity().get("Account")
        except Exception:
            pass
        else:
            return partition
    return "aws"


def current_account_id_and_partition(profile: Optional[str] = None) -> Tuple[str, str]:
    interesting_exception = None
    add_log_str = ""
    if profile:
        add_log_str = f" with profile {profile}"
    log.debug(f"Trying to determine current account id and partition{add_log_str}")
    for region in GLOBAL_REGIONS:
        partition = arn_partition_by_region(region)
        log.debug(f"Probing region {region}")
        try:
            if profile:
                account_id = (
                    boto3.session.Session(region_name=region, profile_name=profile)
                    .client("sts")
                    .get_caller_identity()
                    .get("Account")
                )
            else:
                account_id = (
                    boto3.session.Session(
                        region_name=region,
                        aws_access_key_id=Config.aws.access_key_id,
                        aws_secret_access_key=Config.aws.secret_access_key,
                    )
                    .client("sts")
                    .get_caller_identity()
                    .get("Account")
                )
            log.debug(f"Determined partition for account {account_id} to be {partition}")
            return account_id, partition
        except botocore.exceptions.ClientError as e:
            log.debug(f"Got an exception when probing partition {partition}: {e}")
            if e.response["Error"]["Code"] != "InvalidClientTokenId":
                interesting_exception = e
        except Exception as e:
            log.debug(f"Got an exception when probing partition {partition}: {e}")
            interesting_exception = e
    if interesting_exception:
        raise interesting_exception
    else:
        raise botocore.exceptions.NoCredentialsError()


def set_account_names(accounts: List[AwsAccount], core_feedback: CoreFeedback) -> None:
    def set_account_name(account: AwsAccount) -> None:
        def set_name_from_account_alias() -> bool:
            try:
                account_aliases = (
                    aws_session(
                        account=account.id, role=account.role, profile=account.profile, partition=account.partition
                    )
                    .client("iam")
                    .list_account_aliases()
                    .get("AccountAliases", [])
                )
                if len(account_aliases) > 0:
                    account.name = account_aliases[0]
                    log.debug(f"Set name for {account.kdname} from account alias")
                    return True
            except Exception:
                pass
            return False

        def set_name_from_org() -> bool:
            try:
                scrape_org_role_arn = Config.aws.scrape_org_role_arn
                if scrape_org_role_arn is not None and len(str(scrape_org_role_arn).strip()) == 0:
                    scrape_org_role_arn = None
                account_name = (
                    aws_session(profile=account.profile, partition=account.partition, role_arn=scrape_org_role_arn)
                    .client("organizations")
                    .describe_account(AccountId=account.id)["Account"]["Name"]
                )
                account.name = account_name
                log.debug(f"Set name for {account.kdname} from organization")
                return True
            except Exception:
                pass
            return False

        def set_name_from_profile() -> bool:
            if account.profile:
                account.name = account.profile
                log.debug(f"Set name for {account.kdname} from profile")
                return True
            return False

        # if we prefer the profile name and we have a profile
        # we set the name from the profile and return immediately
        if Config.aws.prefer_profile_as_account_name:
            if Config.aws.scrape_org:
                core_feedback.error(
                    "Possible misconfiguration: setting prefer_profile_as_account_name"
                    " with scrape_org enabled is likely not what you want",
                    log,
                )
            if set_name_from_profile():
                return

        # otherwise we try to set the name from the account alias
        # or the organization - depending on the configuration
        # and what permissions we have
        if Config.aws.prefer_account_alias_as_name:
            if not set_name_from_account_alias():
                set_name_from_org()
        else:
            if not set_name_from_org():
                set_name_from_account_alias()

        # if we still don't have a name, we try
        # to set it from the profile if one is set
        if account.name is None and not Config.aws.scrape_org:
            set_name_from_profile()

    if len(accounts) == 0:
        return

    max_workers = len(accounts) if len(accounts) < Config.aws.account_pool_size else Config.aws.account_pool_size
    with futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="aws_account_name_finder") as executor:
        executor.map(set_account_name, accounts)


def get_accounts(core_feedback: CoreFeedback) -> List[AwsAccount]:
    accounts = []
    profiles: Sequence[Optional[str]] = [None]
    config: AwsConfig = Config.aws

    if config.assume_current and not config.do_not_scrape_current:
        msg = (
            "You specified assume_current but not do_not_scrape_current! "
            "This will result in the same account being collected twice and is likely not what you want."
        )
        core_feedback.error(msg, log)
        raise ValueError(msg)

    if isinstance(config.profiles, list) and len(config.profiles) > 0:
        log.debug("Using specified AWS profiles")
        profiles = config.profiles
        if config.account and len(config.profiles) > 1:
            msg = (
                "You specified both a list of accounts and more than one profile! "
                "This will result in the attempt to collect the same accounts for "
                "every profile and is likely not what you want."
            )
            core_feedback.error(msg, log)
            raise ValueError(msg)
    elif not config.account and not config.access_key_id and not os.environ.get("AWS_ACCESS_KEY_ID"):
        log.debug("Extracting AWS profiles from shared credentials file")
        try:
            profiles = boto3.Session().available_profiles
            log.debug(f"Discovered the following profiles: {profiles}")
        except Exception:
            msg = "AWS Credentials file could not be parsed."
            core_feedback.error(msg, log)

    if len(profiles) == 0:
        # If we have no profiles, we still try to let boto3 do its default auth code path.
        profiles = [None]

    for profile in profiles:
        if profile is not None:
            log.debug(f"Finding accounts for profile {profile}")

        try:
            if config.role and config.scrape_org:
                log.debug("Role and scrape_org are both set")
                account_id, partition = current_account_id_and_partition(profile=profile)
                accounts.extend(
                    [
                        AwsAccount(id=aws_account_id, role=config.role, profile=profile, partition=partition)
                        for aws_account_id in get_org_accounts(
                            filter_current_account=not config.assume_current,
                            profile=profile,
                            core_feedback=core_feedback,
                            partition=partition,
                        )
                        if aws_account_id not in config.scrape_exclude_account
                    ]
                )
                if not config.do_not_scrape_current:
                    accounts.append(AwsAccount(id=account_id, partition=partition))
            elif config.role and config.account:
                log.debug("Both, role and list of accounts specified")
                for aws_account_id in config.account:
                    partition = probe_partition(aws_account_id, profile=profile)
                    accounts.append(
                        AwsAccount(id=aws_account_id, role=config.role, profile=profile, partition=partition)
                    )
            else:
                account_id, partition = current_account_id_and_partition(profile=profile)
                accounts.extend([AwsAccount(id=account_id, profile=profile, partition=partition)])
        except botocore.exceptions.NoCredentialsError:
            core_feedback.error(f"No AWS credentials found for {profile}", log)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AuthFailure":
                core_feedback.error(f"Unable to validate the provided access credentials for {profile}", log)
            elif e.response["Error"]["Code"] == "InvalidClientTokenId":
                core_feedback.error(f"Unable to validate the provided security token for {profile}", log)
            elif e.response["Error"]["Code"] == "ExpiredToken":
                core_feedback.error(f"AWS security token included in the request is expired for {profile}", log)
            elif e.response["Error"]["Code"] == "AccessDenied":
                core_feedback.error(f"Access denied for profile {profile}", log)
            elif e.response["Error"]["Code"] == "SignatureDoesNotMatch":
                core_feedback.error(f"Token signature does not match for {profile}", log)
            else:
                core_feedback.error(f"AWS client error for profile {profile}: {e}", log)
                raise
        except botocore.exceptions.BotoCoreError as e:
            core_feedback.error(f"Unable to get accounts for profile {profile}: {e}", log)

    set_account_names(accounts, core_feedback)
    return accounts


def get_org_accounts(
    filter_current_account: bool, profile: Optional[str], core_feedback: CoreFeedback, partition: Optional[str] = None
) -> List[str]:
    scrape_org_role_arn = Config.aws.scrape_org_role_arn
    if scrape_org_role_arn is not None and len(str(scrape_org_role_arn).strip()) == 0:
        scrape_org_role_arn = None
    session = aws_session(profile=profile, partition=partition, role_arn=scrape_org_role_arn)
    client = session.client("organizations")
    accounts = []
    try:
        response = client.list_accounts()
        accounts = response.get("Accounts", [])
        while response.get("NextToken") is not None:
            response = client.list_accounts(NextToken=response["NextToken"])
            accounts.extend(response.get("Accounts", []))
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            core_feedback.error(f"Missing permissions to list organization accounts: {e}", log)
        else:
            raise
    filter_account_id = current_account_id(profile=profile) if filter_current_account else -1
    accounts = [aws_account["Id"] for aws_account in accounts if aws_account["Id"] != filter_account_id]
    for account in accounts:
        log.debug(f"AWS found org account {account}")
    log.info(f"AWS found a total of {len(accounts)} org accounts")
    return accounts


def all_regions(profile: Optional[str] = None, partition: str = "aws") -> List[str]:
    session = aws_session(profile=profile, partition=partition)
    ec2 = session.client("ec2", region_name=global_region_by_partition(partition))
    regions = ec2.describe_regions()
    return [r["RegionName"] for r in regions["Regions"]]


@log_runtime
def collect_account(
    account: AwsAccount,
    regions: List[str],
    args: Namespace,
    running_config: RunningConfig,
    feedback: CoreFeedback,
    cloud: Cloud,
    task_data: Json,
) -> Optional[Graph]:
    collector_name = f"aws_{account.id}"
    fixlib.proc.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args
        setup_logger("fixworker-aws", force=True, level=getattr(args, "log_level", None))

    if running_config is not None:
        Config.running_config.apply(running_config)

    if not authenticated(account, feedback):
        feedback.error(f"Skipping account {account.rtdname}. Reason: authentication failure.", log)
        return None

    log.debug(f"Starting new collect process for account {account.dname}")

    aac = AwsAccountCollector(Config.aws, cloud, account, regions, feedback, task_data)
    try:
        aac.collect()
    except botocore.exceptions.ClientError as e:
        feedback.error(
            f"Ignore account {account.dname}. Reason: An AWS {e.response['Error']['Code']} error occurred.", log
        )
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None
    except Exception as ex:
        feedback.error(f"Ignore account {account.dname}. Reason: unhandled error occurred: {ex}", log)
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None

    return aac.graph


def collect_account_proxy(*args, queue: multiprocessing.Queue, **kwargs) -> None:  # type: ignore
    fixlib.proc.collector_initializer()
    queue.put(collect_account(*args, **kwargs))


def collect_in_process(*args, **kwargs) -> Optional[Graph]:  # type: ignore
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    kwargs["queue"] = queue
    process = ctx.Process(target=collect_account_proxy, args=args, kwargs=kwargs)
    process.start()
    graph = queue.get()
    process.join()
    return graph  # type: ignore
