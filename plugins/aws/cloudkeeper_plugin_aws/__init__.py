import botocore.exceptions
import networkx
import cloudkeeper.logging as logging
import multiprocessing
from threading import current_thread
from concurrent import futures
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import signal_on_parent_exit, log_runtime
from cloudkeeper.baseplugin import BaseCollectorPlugin
from .utils import aws_session
from .resources import AWSAccount
from .accountcollector import AWSAccountCollector
from prometheus_client import Summary, Counter
from typing import List


logging.getLogger('boto').setLevel(logging.CRITICAL)
log = logging.getLogger('cloudkeeper.' + __name__)

metrics_collect = Summary('cloudkeeper_plugin_aws_collect_seconds', 'Time it took the collect() method')
metrics_unhandled_account_exceptions = Counter('cloudkeeper_plugin_aws_unhandled_account_exceptions_total', 'Unhandled AWS Plugin Account Exceptions', ['account'])


class AWSPlugin(BaseCollectorPlugin):
    cloud = 'aws'

    def __init__(self) -> None:
        super().__init__()
        self.__regions = []

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--aws-access-key-id', help='AWS Access Key ID', dest='aws_access_key_id')
        arg_parser.add_argument('--aws-secret-access-key', help='AWS Secret Access Key', dest='aws_secret_access_key')
        arg_parser.add_argument('--aws-role', help='AWS IAM Role', dest='aws_role')
        arg_parser.add_argument('--aws-role-override', help="Override any stored roles (e.g. from remote graphs) (default: False)",
                                dest='aws_role_override', action='store_true', default=False)
        arg_parser.add_argument('--aws-account', help='AWS Account', dest='aws_account', type=str, default=None,
                                nargs='+')
        arg_parser.add_argument('--aws-region', help='AWS Region (default: all)', dest='aws_region', type=str,
                                default=None, nargs='+')
        arg_parser.add_argument('--aws-scrape-org', help='Scrape the entire AWS Org (default: False)',
                                dest='aws_scrape_org', action='store_true')
        arg_parser.add_argument('--aws-fork', help='Use forked process instead of threads (default: False)',
                                dest='aws_fork', action='store_true')
        arg_parser.add_argument('--aws-scrape-exclude-account', help='AWS exclude this Account when scraping the org',
                                dest='aws_scrape_exclude_account', type=str, default=[], nargs='+')
        arg_parser.add_argument('--aws-assume-current', help="Assume role in current account (default: False)",
                                dest='aws_assume_current', action='store_true')
        arg_parser.add_argument('--aws-dont-scrape-current', help="Don't scrape current account (default: False)",
                                dest='aws_scrape_current', action='store_false')
        arg_parser.add_argument('--aws-account-pool-size', help='AWS Account Thread Pool Size (default: 5)',
                                dest='aws_account_pool_size', default=5, type=int)
        arg_parser.add_argument('--aws-region-pool-size', help='AWS Region Thread Pool Size (default: 20)',
                                dest='aws_region_pool_size', default=20, type=int)
        arg_parser.add_argument('--aws-collect', help='AWS services to collect (default: all)', dest='aws_collect', type=str, default=[],
                                nargs='+')
        arg_parser.add_argument('--aws-no-collect', help='AWS services not to collect', dest='aws_no_collect', type=str, default=[],
                                nargs='+')

    @metrics_collect.time()
    def collect(self) -> None:
        log.debug("plugin: AWS collecting resources")
        if not self.authenticated:
            log.error('Failed to authenticate - skipping collection')
            return

        if ArgumentParser.args.aws_assume_current and ArgumentParser.args.aws_scrape_current:
            log.warning('You specified --aws-assume-current but not --aws-dont-scrape-current! '
                        'This will result in the same account being scraped twice and is likely not what you want.')

        if ArgumentParser.args.aws_role and ArgumentParser.args.aws_scrape_org:
            accounts = [AWSAccount(aws_account_id, {}, role=ArgumentParser.args.aws_role) for aws_account_id in
                        get_org_accounts(filter_current_account=not ArgumentParser.args.aws_assume_current) if
                        aws_account_id not in ArgumentParser.args.aws_scrape_exclude_account]
            if ArgumentParser.args.aws_scrape_current:
                accounts.append(AWSAccount(current_account_id(), {}))
        elif ArgumentParser.args.aws_role and ArgumentParser.args.aws_account:
            accounts = [AWSAccount(aws_account_id, {}, role=ArgumentParser.args.aws_role) for aws_account_id in
                        ArgumentParser.args.aws_account]
        else:
            accounts = [AWSAccount(current_account_id(), {})]

        max_workers = len(accounts) if len(accounts) < ArgumentParser.args.aws_account_pool_size else ArgumentParser.args.aws_account_pool_size
        pool_args = {'max_workers': max_workers}
        if ArgumentParser.args.aws_fork:
            pool_args['mp_context'] = multiprocessing.get_context('spawn')
            pool_executor = futures.ProcessPoolExecutor
        else:
            pool_executor = futures.ThreadPoolExecutor

        with pool_executor(**pool_args) as executor:
            wait_for = [
                executor.submit(collect_account, account, self.regions, ArgumentParser.args)
                for account in accounts
            ]
            for future in futures.as_completed(wait_for):
                res = future.result()
                aac_root = res['root']
                aac_graph = res['graph']
                aac_account = res['account']
                log.debug(f'Merging graph of account {aac_account.dname} with {self.cloud} plugin graph')
                self.graph = networkx.compose(self.graph, aac_graph)
                self.graph.add_edge(self.root, aac_root)

    @property
    def regions(self) -> List:
        if len(self.__regions) == 0:
            if not ArgumentParser.args.aws_region:
                log.debug('AWS region not specified, assuming all regions')
                self.__regions = all_regions()
            else:
                self.__regions = ArgumentParser.args.aws_region
        return self.__regions

    @property
    def authenticated(self) -> bool:
        try:
            _ = current_account_id()
        except botocore.exceptions.NoCredentialsError:
            log.error('No AWS credentials found')
            return False
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                log.error('AWS was unable to validate the provided access credentials')
            elif e.response['Error']['Code'] == 'InvalidClientTokenId':
                log.error('AWS was unable to validate the provided security token')
            elif e.response['Error']['Code'] == 'ExpiredToken':
                log.error('AWS security token included in the request is expired')
            else:
                raise
            return False
        return True


def current_account_id():
    session = aws_session()
    return session.client('sts').get_caller_identity().get('Account')


def get_org_accounts(filter_current_account=False):
    session = aws_session()
    client = session.client('organizations')
    accounts = []
    try:
        response = client.list_accounts()
        accounts = response.get('Accounts', [])
        while response.get('NextToken') is not None:
            response = client.list_accounts(NextToken=response['NextToken'])
            accounts.extend(response.get('Accounts', []))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            log.error('AWS error - missing permissions to list organization accounts')
        else:
            raise
    filter_account_id = current_account_id() if filter_current_account else -1
    accounts = [aws_account['Id'] for aws_account in accounts if aws_account['Id'] != filter_account_id]
    for account in accounts:
        log.debug(f'AWS found org account {account}')
    log.info(f'AWS found a total of {len(accounts)} org accounts')
    return accounts


def all_regions() -> List:
    session = aws_session()
    ec2 = session.client('ec2', region_name='us-east-1')
    regions = ec2.describe_regions()
    return [r['RegionName'] for r in regions['Regions']]


@log_runtime
def collect_account(account: AWSAccount, regions: List, args=None):
    signal_on_parent_exit()
    current_thread().name = f'aws_{account.id}'

    if args is not None:
        ArgumentParser.args = args

    log.debug(f'Starting new collect process for account {account.dname}')

    aac = AWSAccountCollector(regions, account)
    try:
        aac.collect()
    except botocore.exceptions.ClientError as e:
        log.exception(f"An AWS {e.response['Error']['Code']} error occurred while collecting account {account.dname}")
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()
    except Exception:
        log.exception(f'An unhandled error occurred while collecting AWS account {account.dname}')
        metrics_unhandled_account_exceptions.labels(account=account.dname).inc()

    return {'root': aac.root, 'graph': aac.graph, 'account': aac.account}
