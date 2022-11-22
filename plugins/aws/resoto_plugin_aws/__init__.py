import logging
import multiprocessing
from concurrent import futures
from typing import List, Optional, Union, Any, Dict

import botocore.exceptions
from botocore.model import OperationModel, Shape, StringShape, ListShape, StructureShape
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
from resotolib.config import Config, RunningConfig, current_config
from resotolib.core.actions import CoreFeedback
from resotolib.core.custom_command import execute_command_on_resource
from resotolib.graph import Graph
from resotolib.logger import log, setup_logger
from resotolib.types import JsonElement, Json
from resotolib.utils import log_runtime, NoExitArgumentParser
from .collector import AwsAccountCollector
from .configuration import AwsConfig
from .resource.base import AwsAccount, AwsResource, get_client
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
        self.core_feedback: Optional[CoreFeedback] = None

    @staticmethod
    def add_config(cfg: Config) -> None:
        cfg.add_config(AwsConfig)

    @metrics_collect.time()  # type: ignore
    def collect(self) -> None:
        log.debug("plugin: AWS collecting resources")
        assert self.core_feedback, "core_feedback is not set"
        cloud = Cloud(id=self.cloud, name="AWS")

        accounts = get_accounts(self.core_feedback.with_context(cloud.id))
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
                    self.core_feedback.with_context(cloud.id, account.dname),
                    cloud,
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
            "--account": "[Optional] The AWS account identifier.",
            "--role": "[Optional] The AWS role.",
            "--profile": "[Optional] The AWS profile to use.",
            "--region": "[Optional] The AWS region.",
            "service": "Defines the AWS service, like ec2, s3, iam, etc.",
            "operation": "Defines the operation to execute.",
            "operation_args": "Defines the arguments for the operation. The parameters depend on the operation.",
        },
        description="Execute an operation on an AWS resource.\n"
        "For a list of services with respective operations see "
        "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/index.html#available-services\n\n"
        "By default the operation runs with the same credentials as the collect process.\n"
        "You can override the credentials by providing the account, role, profile and region arguments.\n\n"
        "There are two modes of operation:\n"
        "1. Use a search and then pipe the result of the search into the `aws` command. "
        "Every resource matched by the search will invoke this command. "
        "You can use templating parameter to define the exact invocation arguments.\n"
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
        parser = NoExitArgumentParser()
        parser.add_argument("--account")
        parser.add_argument("--role")
        parser.add_argument("--profile")
        parser.add_argument("--region")
        parser.add_argument("service")
        parser.add_argument("operation")
        p, remaining = parser.parse_known_args(args)
        cfg = config.aws

        def adjust_shape(o: str, shape: Optional[Shape]) -> Any:
            if shape is None or isinstance(shape, StringShape):
                return o
            elif isinstance(shape, ListShape):
                return o.split(",")
            else:
                # map and structure types are currently not supported
                raise ValueError(f"Cannot convert {o} to {shape}")

        def coerce_args(fn_args: List[str], om: OperationModel) -> Dict[str, Any]:
            members: Dict[str, Shape] = om.input_shape.members if isinstance(om.input_shape, StructureShape) else {}
            param_name: Optional[str] = None
            param_shape: Optional[Shape] = None
            arg_val: Dict[str, Any] = {}
            for arg in fn_args:
                if arg.startswith("--"):
                    name = pascalcase(arg.removeprefix("--"))
                    param_name = name
                    param_shape = members.get(name)
                    bool_value = True
                    if param_shape is None and arg.startswith("--no-"):
                        name = name[2:]
                        param_name = name
                        param_shape = members.get(name)
                        bool_value = False
                    if param_shape is None:
                        raise ValueError(f"AWS: Unknown parameter {arg}")
                    if param_shape.name == "Boolean" or param_shape.type_name == "Boolean":
                        arg_val[name] = bool_value
                        param_shape = None
                        param_name = None
                elif param_name is not None:
                    arg_val[param_name] = adjust_shape(arg, param_shape)
                    param_name = None
                    param_shape = None
                else:
                    raise ValueError(f"AWS: Unexpected argument {arg}")
            return arg_val

        def create_client() -> AwsClient:
            role = p.role or cfg.role
            region = p.region or (cfg.region[0] if cfg.region else None)
            profile = p.profile or (cfg.profiles[0] if cfg.profiles else None)
            # possibly expensive call: account id is looked up if not provided
            account = p.account or (cfg.account[0] if cfg.account else current_account_id(profile))
            return AwsClient(cfg, account, role=role, profile=profile, region=region)

        client = get_client(current_config(), resource) if resource else create_client()

        # try to get the output shape of the operation
        service_model = client.service_model(p.service)
        op: OperationModel = service_model.operation_model(pascalcase(p.operation))
        output_shape = op.output_shape.type_name
        func_args = coerce_args(remaining, op)

        result: List[Json] = client.call_single(p.service, p.operation, None, **func_args)  # type: ignore
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
                resource.log("Modification was requested even though resource is protected" " - refusing")
                return False

            if resource.phantom:
                log.error(f"Can't cleanup phantom resource {resource.rtdname}")
                return False

            if resource.cleaned:
                log.debug(f"Resource {resource.rtdname} has already been cleaned up")
                return True

            account = resource.account(graph)
            region = resource.region(graph)
            if not isinstance(account, BaseAccount) or not isinstance(region, BaseRegion):
                log.error(f"Could not determine account or region for pre cleanup of {resource.rtdname}")
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
                raise
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
                raise RuntimeError(f"Could not determine account or region for cleanup of {resource.rtdname}")

            log_suffix = f" in account {account.dname} region {region.name}"
            resource.log("Trying to clean up")
            log.debug(f"Trying to clean up {resource.rtdname}{log_suffix}")
            try:
                if deleted := resource.delete_resource(client):
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
        log.debug(f"AWS testing credentials for {account.rtdname}")
        session = aws_session(account.id, account.role, account.profile)
        _ = session.client("sts").get_caller_identity().get("Account")
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
            core_feedback.error(f"Access Denied to {account.rtdname}", log)
        else:
            raise
        return False
    return True


def current_account_id(profile: Optional[str] = None) -> str:
    session = aws_session(profile=profile)
    return session.client("sts").get_caller_identity().get("Account")  # type: ignore


def set_account_names(accounts: List[AwsAccount]) -> None:
    def set_account_name(account: AwsAccount) -> None:
        try:
            account_aliases = (
                aws_session(account.id, account.role, account.profile)
                .client("iam")
                .list_account_aliases()
                .get("AccountAliases", [])
            )
            if len(account_aliases) > 0:
                account.name = account_aliases[0]
        except Exception:
            pass

    if len(accounts) == 0:
        return

    max_workers = len(accounts) if len(accounts) < Config.aws.account_pool_size else Config.aws.account_pool_size
    with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(set_account_name, accounts)


def get_accounts(core_feedback: CoreFeedback) -> List[AwsAccount]:
    accounts = []
    profiles = [None]

    if Config.aws.assume_current and not Config.aws.do_not_scrape_current:
        msg = (
            "You specified assume_current but not do_not_scrape_current! "
            "This will result in the same account being collected twice and is likely not what you want."
        )
        core_feedback.error(msg)
        raise ValueError(msg)

    if isinstance(Config.aws.profiles, list) and len(Config.aws.profiles) > 0:
        log.debug("Using specified AWS profiles")
        profiles = Config.aws.profiles
        if Config.aws.account and len(Config.aws.profiles) > 1:
            msg = (
                "You specified both a list of accounts and more than one profile! "
                "This will result in the attempt to collect the same accounts for "
                "every profile and is likely not what you want."
            )
            core_feedback.error(msg)
            raise ValueError(msg)

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
                            filter_current_account=not Config.aws.assume_current,
                            profile=profile,
                            core_feedback=core_feedback,
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
            else:
                raise
        except botocore.exceptions.BotoCoreError as e:
            core_feedback.error(f"Unable to get accounts for profile {profile}: {e}", log)

    set_account_names(accounts)
    return accounts


def get_org_accounts(filter_current_account: bool, profile: Optional[str], core_feedback: CoreFeedback) -> List[str]:
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
            core_feedback.error("Missing permissions to list organization accounts", log)
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
    feedback: CoreFeedback,
    cloud: Cloud,
) -> Optional[Graph]:
    collector_name = f"aws_{account.id}"
    resotolib.proc.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args
        setup_logger("resotoworker-aws", force=True, level=getattr(args, "log_level", None))

    if running_config is not None:
        Config.running_config.apply(running_config)

    if not authenticated(account, feedback):
        log.error(f"Skipping {account.rtdname} due to authentication failure")
        return None

    log.debug(f"Starting new collect process for account {account.dname}")

    aac = AwsAccountCollector(Config.aws, cloud, account, regions, feedback)
    try:
        aac.collect()
    except botocore.exceptions.ClientError as e:
        feedback.error(
            f"An AWS {e.response['Error']['Code']} error occurred while collecting account {account.dname}", log
        )
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None
    except Exception as ex:
        feedback.error(f"An unhandled error occurred while collecting AWS account {account.dname}. {ex}", log)
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
        return None

    return aac.graph
