import logging

import botocore.exceptions
import multiprocessing
import resotolib.proc
import resotolib.logger
from resotolib.logger import log, setup_logger
from concurrent import futures
from resotolib.args import ArgumentParser
from resotolib.args import Namespace
from resotolib.config import Config, RunningConfig
from resotolib.graph import Graph
from resotolib.utils import log_runtime
from resotolib.baseplugin import BaseCollectorPlugin
from .config import AwsConfig
from .utils import aws_session
from .resources import AWSAccount
from .accountcollector import AWSAccountCollector
from prometheus_client import Summary, Counter
from typing import List


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
        if not self.authenticated:
            log.error("Failed to authenticate - skipping collection")
            return

        if Config.aws.assume_current and not Config.aws.do_not_scrape_current:
            log.warning(
                "You specified assume_current but not do_not_scrape_current! "
                "This will result in the same account being scraped twice and is likely not what you want."
            )

        if Config.aws.role and Config.aws.scrape_org:
            accounts = [
                AWSAccount(id=aws_account_id, tags={}, role=Config.aws.role)
                for aws_account_id in get_org_accounts(filter_current_account=not Config.aws.assume_current)
                if aws_account_id not in Config.aws.scrape_exclude_account
            ]
            if not Config.aws.do_not_scrape_current:
                accounts.append(AWSAccount(id=current_account_id(), tags={}))
        elif Config.aws.role and Config.aws.account:
            accounts = [
                AWSAccount(id=aws_account_id, tags={}, role=Config.aws.role) for aws_account_id in Config.aws.account
            ]
        else:
            accounts = [AWSAccount(id=current_account_id(), tags={})]

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
                    self.regions,
                    ArgumentParser.args,
                    Config.running_config,
                )
                for account in accounts
            ]
            for future in futures.as_completed(wait_for):
                account_graph = future.result()
                if not isinstance(account_graph, Graph):
                    log.error(f"Returned account graph has invalid type {type(account_graph)}")
                    continue
                self.graph.merge(account_graph)

    @property
    def regions(self) -> List[str]:
        if len(self.__regions) == 0:
            if not Config.aws.region or (isinstance(Config.aws.region, list) and len(Config.aws.region) == 0):
                log.debug("AWS region not specified, assuming all regions")
                self.__regions = all_regions()
            else:
                self.__regions = list(Config.aws.region)
        return self.__regions

    @property
    def authenticated(self) -> bool:
        try:
            _ = current_account_id()
        except botocore.exceptions.NoCredentialsError:
            log.error("No AWS credentials found")
            return False
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "AuthFailure":
                log.error("AWS was unable to validate the provided access credentials")
            elif e.response["Error"]["Code"] == "InvalidClientTokenId":
                log.error("AWS was unable to validate the provided security token")
            elif e.response["Error"]["Code"] == "ExpiredToken":
                log.error("AWS security token included in the request is expired")
            else:
                raise
            return False
        return True


def current_account_id() -> str:
    session = aws_session()
    return session.client("sts").get_caller_identity().get("Account")  # type: ignore


def get_org_accounts(filter_current_account: bool = False) -> List[str]:
    session = aws_session()
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
    filter_account_id = current_account_id() if filter_current_account else -1
    accounts = [aws_account["Id"] for aws_account in accounts if aws_account["Id"] != filter_account_id]
    for account in accounts:
        log.debug(f"AWS found org account {account}")
    log.info(f"AWS found a total of {len(accounts)} org accounts")
    return accounts


def all_regions() -> List[str]:
    session = aws_session()
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions()
    return [r["RegionName"] for r in regions["Regions"]]


@log_runtime  # type: ignore
def collect_account(
    account: AWSAccount,
    regions: List[str],
    args: Namespace,
    running_config: RunningConfig,
) -> Graph:
    collector_name = f"aws_{account.id}"
    resotolib.proc.set_thread_name(collector_name)

    if args is not None:
        ArgumentParser.args = args
        setup_logger("resotoworker-aws")
    if running_config is not None:
        Config.running_config.apply(running_config)

    log.debug(f"Starting new collect process for account {account.dname}")

    aac = AWSAccountCollector(regions, account)
    try:
        aac.collect()
    except botocore.exceptions.ClientError as e:
        log.exception(f"An AWS {e.response['Error']['Code']} error occurred while collecting account {account.dname}")
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
    except Exception:
        log.exception(f"An unhandled error occurred while collecting AWS account {account.dname}")
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()

    return aac.graph  # type: ignore
