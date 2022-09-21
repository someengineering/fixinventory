import logging
import multiprocessing
from concurrent import futures
from contextlib import suppress
from typing import List, Optional, Union

import botocore.exceptions
from botocore.model import OperationModel
from jsons import pascalcase
from prometheus_client import Summary, Counter

import resotolib.logger
import resotolib.proc
from resoto_plugin_aws.aws_client import AwsClient
from resotolib.args import ArgumentParser
from resotolib.args import Namespace
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.baseresources import (
    BaseResource,
    metrics_resource_cleanup_exceptions,
    BaseAccount,
    BaseRegion,
    metrics_resource_pre_cleanup_exceptions,
)
from resotolib.baseresources import Cloud
from resotolib.config import Config, RunningConfig
from resotolib.graph import Graph
from resotolib.logger import log, setup_logger
from resotolib.plugin_task_handler import execute_command_on_resource
from resotolib.types import Json, JsonElement
from resotolib.utils import log_runtime, chunks
from .collector import AwsAccountCollector
from .config import AwsConfig
from .resource.base import AwsAccount, AwsResource
from .utils import aws_session

logging.getLogger("boto").setLevel(logging.CRITICAL)

metrics_collect = Summary("resoto_plugin_aws_collect_seconds", "Time it took the collect() method")
metrics_unhandled_account_exceptions = Counter(
    "resoto_plugin_aws_unhandled_account_exceptions_total",
    "Unhandled AWS Plugin Account Exceptions",
    ["account"],
)


class AWSCollectorPlugin(BaseCollectorPlugin):
    cloud = "aws"

    def __init__(self) -> None:
        super().__init__()
        self.__regions: List[str] = []

    @staticmethod
    def add_config(cfg: Config) -> None:
        cfg.add_config(AwsConfig)

    @metrics_collect.time()  # type: ignore
    def collect(self) -> None:
        log.debug("plugin: AWS collecting resources")

        accounts = get_accounts()
        if len(accounts) == 0:
            log.error("No accounts found")
            return
        for account in accounts:
            add_str = ""
            if account.role:
                add_str += f" role {account.role}"
            if account.profile:
                add_str += f" profile {account.profile}"
            log.debug(f"Found {account.rtdname}{add_str}")

        max_workers = len(accounts) if len(accounts) < Config.aws.account_pool_size else Config.aws.account_pool_size
        pool_args = {"max_workers": max_workers}
        if Config.aws.fork_process:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.proc.initializer
            pool_executor = futures.ProcessPoolExecutor
        else:
            pool_executor = futures.ThreadPoolExecutor  # type: ignore

        with pool_executor(**pool_args) as executor:
            wait_for = [
                executor.submit(
                    collect_account,
                    account,
                    self.regions(profile=account.profile),
                    ArgumentParser.args,
                    Config.running_config,
                )
                for account in accounts
            ]
            for future in futures.as_completed(wait_for):
                account_graph = future.result()
                if not isinstance(account_graph, Graph):
                    log.debug(f"Skipping account graph of invalid type {type(account_graph)}")
                    continue
                self.graph.merge(account_graph)

    def regions(self, profile: Optional[str] = None) -> List[str]:
        if len(self.__regions) == 0:
            if not Config.aws.region or (isinstance(Config.aws.region, list) and len(Config.aws.region) == 0):
                log.debug("AWS region not specified, assuming all regions")
                self.__regions = all_regions(profile=profile)
            else:
                self.__regions = list(Config.aws.region)
        return self.__regions

    @execute_command_on_resource(
        name="aws",
        info="Execute aws commands on AWS resources",
        args_description={
            "--account-id": "[Optional] The AWS account id.",
            "--role": "[Optional] The AWS role.",
            "--profile": "[Optional] The AWS profile to use.",
            "--region": "[Optional] The AWS region.",
            "service": "Defines the AWS service, like ec2, s3, iam, etc.",
            "operation": "Defines the operation to execute.",
            "operation_args": "Defines the arguments for the operation. The parameters depend on the operation.",
        },
        description="By default the operation runs with the same credentials as during the collect process.\n"
        "You can override the credentials by providing the account-id, profile and region arguments.\n\n"
        "## Examples\n\n"
        "```shell\n"
        "> search is(aws_ec2_volume) | aws ec2 describe-volume-attribute --volume-id {id} --attribute autoEnableIO\n"
        "```\n\n",
        allowed_on_kind="aws_resource",
    )
    def call_aws_function(self, resource: BaseResource, args: List[str]) -> Union[JsonElement, BaseResource]:
        # impossible to call the aws resource without service and function name
        if len(args) < 2:
            raise AttributeError("Not enough parameters! aws <service-name> <function-name> [function-args].")
        service_name = args[0]
        function_name = args[1]

        # args have the form: --xxx yyy
        func_args = {}
        for single_arg in chunks(args[2:], 2):
            arg, value = single_arg
            func_args[pascalcase(arg.removeprefix("--"))] = value

        # create the client
        client = get_client(Config, resource)  # type: ignore

        # try to get the output shape of the function
        output_shape: Optional[str] = None
        with suppress(Exception):
            service_model = client.service_model(service_name)
            operation: OperationModel = service_model.operation_model(pascalcase(function_name))
            output_shape = operation.output_shape.type_name

        result: List[Json] = client.call_single(service_name, function_name, None, **func_args)  # type: ignore
        # Remove the "ResponseMetadata" from the result
        for elem in result:
            if isinstance(elem, dict):
                elem.pop("ResponseMetadata", None)
        return (result[0] if len(result) == 1 else None) if output_shape == "structure" else result

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
                log.error(f"Resource {resource.rtdname} is protected - refusing modification")
                resource.log(("Modification was requested even though resource is protected" " - refusing"))
                return False

            if resource.phantom:
                raise RuntimeError(f"Can't cleanup phantom resource {resource.rtdname}")

            if resource.cleaned:
                log.debug(f"Resource {resource.rtdname} has already been cleaned up")
                return True

            account = resource.account(graph)
            region = resource.region(graph)
            if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                log.error(("Could not determine account or region for pre cleanup of" f" {resource.rtdname}"))
                return False

            log_suffix = f" in account {account.dname} region {region.name}"
            resource.log("Trying to run pre clean up")
            log.debug(f"Trying to run pre clean up {resource.rtdname}{log_suffix}")
            try:
                if not getattr(resource, "pre_delete_resource")(client, graph):
                    resource.log("Failed to run pre clean up")
                    log.error(f"Failed to run pre clean up {resource.rtdname}{log_suffix}")
                    return False
                resource.log("Successfully ran pre clean up")
                log.info(f"Successfully ran pre clean up {resource.rtdname}{log_suffix}")
            except Exception as e:
                resource.log("An error occurred during pre clean up", exception=e)
                log.exception(f"An error occurred during pre clean up {resource.rtdname}{log_suffix}")
                cloud = resource.cloud(graph)
                metrics_resource_pre_cleanup_exceptions.labels(
                    cloud=cloud.name,
                    account=account.dname,
                    region=region.name,
                    kind=resource.kind,
                ).inc()
                return False
            return True

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")

    @staticmethod
    def cleanup(config: Config, resource: BaseResource, graph: Graph) -> bool:
        if isinstance(resource, AwsResource):

            client = get_client(config, resource)

            if resource.phantom:
                raise RuntimeError(f"Can't cleanup phantom resource {resource.rtdname}")

            if resource.cleaned:
                log.debug(f"Resource {resource.rtdname} has already been cleaned up")
                return True

            if resource.protected:
                log.error(f"Resource {resource.rtdname} is protected - refusing modification")
                resource.log(("Modification was requested even though resource is protected" " - refusing"))
                return False

            resource._changes.add("cleaned")
            if graph is None:
                graph = resource._graph

            account = resource.account(graph)
            region = resource.region(graph)
            if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                log.error(f"Could not determine account or region for cleanup of {resource.rtdname}")
                return False

            log_suffix = f" in account {account.dname} region {region.name}"
            resource.log("Trying to clean up")
            log.debug(f"Trying to clean up {resource.rtdname}{log_suffix}")
            try:
                if not resource.delete_resource(client):
                    resource.log("Failed to clean up")
                    log.error(f"Failed to clean up {resource.rtdname}{log_suffix}")
                    return False
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
            return True

        raise RuntimeError(f"Unsupported resource type: {resource.rtdname}")


def authenticated(account: AwsAccount) -> bool:
    try:
        log.debug(f"AWS testing credentials for {account.rtdname}")
        session = aws_session(account.id, account.role, account.profile)
        _ = session.client("sts").get_caller_identity().get("Account")
    except botocore.exceptions.NoCredentialsError:
        log.error(f"No AWS credentials found for {account.rtdname}")
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AuthFailure":
            log.error(f"AWS was unable to validate the provided access credentials for {account.rtdname}")
        elif e.response["Error"]["Code"] == "InvalidClientTokenId":
            log.error(f"AWS was unable to validate the provided security token for {account.rtdname}")
        elif e.response["Error"]["Code"] == "ExpiredToken":
            log.error(f"AWS security token included in the request is expired for {account.rtdname}")
        elif e.response["Error"]["Code"] == "AccessDenied":
            log.error(f"AWS denied access to {account.rtdname}")
        else:
            raise
        return False
    return True


def get_client(config: Config, resource: BaseResource) -> AwsClient:
    account = resource.account()
    assert isinstance(account, AwsAccount)
    return AwsClient(config.aws, account.id, role=account.role, profile=account.profile, region=resource.region().name)


def current_account_id(profile: Optional[str] = None) -> str:
    session = aws_session(profile=profile)
    return session.client("sts").get_caller_identity().get("Account")  # type: ignore


def get_accounts() -> List[AwsAccount]:
    accounts = []
    profiles = [None]

    if Config.aws.assume_current and not Config.aws.do_not_scrape_current:
        raise ValueError(
            "You specified assume_current but not do_not_scrape_current! "
            "This will result in the same account being collected twice and is likely not what you want."
        )

    if isinstance(Config.aws.profiles, list) and len(Config.aws.profiles) > 0:
        log.debug("Using specified AWS profiles")
        profiles = Config.aws.profiles
        if Config.aws.account and len(Config.aws.profiles) > 1:
            raise ValueError(
                "You specified both a list of accounts and more than one profile! "
                "This will result in the attempt to collect the same accounts for "
                "every profile and is likely not what you want."
            )

    for profile in profiles:
        if profile is not None:
            log.debug(f"Finding accounts for profile {profile}")

        try:
            if Config.aws.role and Config.aws.scrape_org:
                log.debug("Role and scrape_org are both set")
                accounts.extend(
                    [
                        AwsAccount(id=aws_account_id, role=Config.aws.role, profile=profile)
                        for aws_account_id in get_org_accounts(
                            filter_current_account=not Config.aws.assume_current, profile=profile
                        )
                        if aws_account_id not in Config.aws.scrape_exclude_account
                    ]
                )
                if not Config.aws.do_not_scrape_current:
                    accounts.append(AwsAccount(id=current_account_id(profile=profile)))
            elif Config.aws.role and Config.aws.account:
                log.debug("Both, role and list of accounts specified")
                accounts.extend(
                    [
                        AwsAccount(id=aws_account_id, role=Config.aws.role, profile=profile)
                        for aws_account_id in Config.aws.account
                    ]
                )
            else:
                accounts.extend([AwsAccount(id=current_account_id(profile=profile), profile=profile)])
        except botocore.exceptions.NoCredentialsError:
            log.error(f"No AWS credentials found for {profile}")
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AuthFailure":
                log.error(f"AWS was unable to validate the provided access credentials for {profile}")
            elif e.response["Error"]["Code"] == "InvalidClientTokenId":
                log.error(f"AWS was unable to validate the provided security token for {profile}")
            elif e.response["Error"]["Code"] == "ExpiredToken":
                log.error(f"AWS security token included in the request is expired for {profile}")
            elif e.response["Error"]["Code"] == "AccessDenied":
                log.error(f"AWS denied access for {profile}")
            else:
                raise

    return accounts


def get_org_accounts(filter_current_account: bool = False, profile: Optional[str] = None) -> List[str]:
    session = aws_session(profile=profile)
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
            log.error("AWS error - missing permissions to list organization accounts")
        else:
            raise
    filter_account_id = current_account_id(profile=profile) if filter_current_account else -1
    accounts = [aws_account["Id"] for aws_account in accounts if aws_account["Id"] != filter_account_id]
    for account in accounts:
        log.debug(f"AWS found org account {account}")
    log.info(f"AWS found a total of {len(accounts)} org accounts")
    return accounts


def all_regions(profile: Optional[str] = None) -> List[str]:
    session = aws_session(profile=profile)
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions()
    return [r["RegionName"] for r in regions["Regions"]]


@log_runtime
def collect_account(
    account: AwsAccount,
    regions: List[str],
    args: Namespace,
    running_config: RunningConfig,
) -> Optional[Graph]:
    collector_name = f"aws_{account.id}"
    resotolib.proc.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args
        setup_logger("resotoworker-aws")
    if running_config is not None:
        Config.running_config.apply(running_config)

    if not authenticated(account):
        log.error(f"Skipping {account.rtdname} due to authentication failure")
        return None

    log.debug(f"Starting new collect process for account {account.dname}")

    aac = AwsAccountCollector(Config.aws, Cloud(id="aws", name="AWS"), account, regions)
    try:
        aac.collect()
    except botocore.exceptions.ClientError as e:
        log.exception(f"An AWS {e.response['Error']['Code']} error occurred while collecting account {account.dname}")
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None
    except Exception:
        log.exception(f"An unhandled error occurred while collecting AWS account {account.dname}")
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None

    return aac.graph
