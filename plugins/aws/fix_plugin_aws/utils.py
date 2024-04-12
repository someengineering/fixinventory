import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, TypeVar
from attrs import frozen

from boto3.session import Session as BotoSession
from botocore.exceptions import ConnectionClosedError, CredentialRetrievalError
from prometheus_client import Counter
from retrying import retry

from fixlib.baseresources import BaseRegion, BaseResource, MetricName, MetricUnit, StatName
from fixlib.config import Config
from fixlib.graph import Graph
from fixlib.json_bender import Bender
from fixlib.types import Json

metrics_session_exceptions = Counter(
    "fix_plugin_aws_session_exceptions_total",
    "Unhandled AWS Plugin Session Exceptions",
)


def retry_on_session_error(e: Exception) -> bool:
    if isinstance(e, (ConnectionClosedError, CredentialRetrievalError)):
        metrics_session_exceptions.inc()
        return True
    return False


@retry(  # type: ignore
    stop_max_attempt_number=10,
    wait_random_min=1000,
    wait_random_max=6000,
    retry_on_exception=retry_on_session_error,
)
def aws_session(
    account: Optional[str] = None,
    role: Optional[str] = None,
    profile: Optional[str] = None,
    partition: Optional[str] = None,
    role_arn: Optional[str] = None,
) -> BotoSession:
    if partition is None:
        partition = "aws"
    global_region = global_region_by_partition(partition)

    if Config.aws.role_override:
        role = Config.aws.role
    if (role and account) or role_arn:
        if role_arn is None:
            role_arn = f"arn:{partition}:iam::{account}:role/{role}"
        if profile:
            session = BotoSession(
                profile_name=profile,
                region_name=global_region,
            )
        else:
            session = BotoSession(
                aws_access_key_id=Config.aws.access_key_id,
                aws_secret_access_key=Config.aws.secret_access_key,
                region_name=global_region,
            )
        sts = session.client("sts")
        token = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"{account}-{str(uuid.uuid4())}")
        credentials = token["Credentials"]
        return BotoSession(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=global_region,
        )
    else:
        if profile:
            return BotoSession(
                profile_name=profile,
                region_name=global_region,
            )
        else:
            return BotoSession(
                aws_access_key_id=Config.aws.access_key_id,
                aws_secret_access_key=Config.aws.secret_access_key,
                region_name=global_region,
            )


def aws_client(resource: BaseResource, service: str, graph: Optional[Graph] = None) -> BotoSession:
    ac = resource.account(graph)
    return aws_session(ac.id, ac.role, ac.profile, ac.partition).client(  # type: ignore
        service, region_name=resource.region(graph).id
    )


def aws_resource(resource: BaseResource, service: str, graph: Optional[Graph] = None) -> BotoSession:
    ac = resource.account(graph)
    return aws_session(ac.id, ac.role, ac.profile, ac.partition).resource(  # type: ignore
        service, region_name=resource.region(graph).id
    )


def paginate(method: Callable[[], List[Any]], **kwargs: Any) -> Iterable[Any]:
    """Get a paginator for a boto3 list/describe method

    Example Usage:
    session = aws_session(self.account.id, self.account.role)
    client = session.client('autoscaling', region_name=region.id)
    for autoscaling_group in paginate(client.describe_auto_scaling_groups):
        print(autoscaling_group)
    """
    client = method.__self__  # type: ignore
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result


def arn_partition(region: BaseRegion) -> str:
    return arn_partition_by_region(region.id)


def arn_partition_by_region(region: str) -> str:
    arn_partition = "aws"
    if region.startswith("cn-"):
        arn_partition = "aws-cn"
    elif region.startswith("us-gov-"):
        arn_partition = "aws-us-gov"
    return arn_partition


def global_region_by_arn(arn: str) -> str:
    if arn.startswith("arn:aws-us-gov:"):
        return "us-gov-west-1"
    elif arn.startswith("arn:aws-cn:"):
        return "cn-north-1"
    else:
        return "us-east-1"


def global_region_by_partition(partition: str) -> str:
    if partition == "aws":
        return "us-east-1"
    elif partition == "aws-us-gov":
        return "us-gov-west-1"
    elif partition == "aws-cn":
        return "cn-north-1"
    else:
        return "us-east-1"


def global_region_by_region(region: str) -> str:
    if region.startswith("us-gov-"):
        return "us-gov-west-1"
    elif region.startswith("cn-"):
        return "cn-north-1"
    else:
        return "us-east-1"


def tags_as_dict(tags: List[Json]) -> Dict[str, Optional[str]]:
    return {tag["Key"]: tag["Value"] for tag in tags or []}


class ToDict(Bender):
    def __init__(self, key: str = "Key", value: str = "Value") -> None:
        self.key = key
        self.value = value

    def execute(self, source: List[Json]) -> Dict[str, str]:
        return {k.get(self.key, self.key): k.get(self.value, "") for k in source}


class TagsValue(Bender):
    def __init__(self, name: str) -> None:
        self.name = name

    def execute(self, source: List[Json]) -> Optional[str]:
        for k in source:
            if k.get("Key") == self.name:
                return k.get("Value", "")  # type: ignore
        return None


T = TypeVar("T")


def identity(x: T) -> T:
    return x


# by default, take the first value, and don't include a stat name
# so the default metric stat is used
def take_first(x: List[T]) -> List[Tuple[T, Optional[StatName]]]:
    return [(x[0], None)]


@frozen(kw_only=True)
class MetricNormalization:
    metric_name: MetricName
    unit: MetricUnit
    stat_map: Dict[str, StatName] = {
        "Minimum": StatName.min,
        "Average": StatName.avg,
        "Maximum": StatName.max,
    }
    normalize_value: Callable[[float], float] = identity
    # function to derive stats from a list of values
    # the default is to take the first value and use the default stat name
    compute_stats: Callable[[List[float]], List[Tuple[float, Optional[StatName]]]] = take_first
