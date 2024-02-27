import logging
import threading
import time
import uuid
from datetime import timedelta
from fnmatch import fnmatch
from functools import lru_cache
from typing import Any, Callable, ClassVar, Dict, List, Optional, Type

from attrs import define, field, fields_dict
from boto3.session import Session as BotoSession
from botocore.client import BaseClient
from botocore.config import Config as BotoConfig

from fixlib.durations import parse_duration
from fixlib.json import from_json as from_js
from fixlib.proc import num_default_threads
from fixlib.types import Json

from .utils import global_region_by_partition

log = logging.getLogger("fix.plugins.aws")


@define(hash=True, slots=False)
class AwsSessionHolder:
    access_key_id: Optional[str]
    secret_access_key: Optional[str]
    role: Optional[str] = None
    role_override: bool = False
    # Only here to override in tests
    session_class_factory: Type[BotoSession] = BotoSession
    kind: ClassVar[str] = "aws_session_holder"
    session_lock: threading.Lock = threading.Lock()

    # noinspection PyUnusedLocal
    @lru_cache(maxsize=128)
    def __direct_session(self, profile: Optional[str], partition: str) -> BotoSession:
        global_region = global_region_by_partition(partition)
        if profile:
            return self.session_class_factory(profile_name=profile, region_name=global_region)
        else:
            return self.session_class_factory(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=global_region,
            )

    # noinspection PyUnusedLocal
    @lru_cache(maxsize=128)
    def __sts_session(
        self, aws_account: str, aws_role: str, profile: Optional[str], partition: str, cache_key: int
    ) -> BotoSession:
        global_region = global_region_by_partition(partition)
        role = self.role if self.role_override else aws_role
        role_arn = f"arn:{partition}:iam::{aws_account}:role/{role}"
        if profile:
            session = self.session_class_factory(
                profile_name=profile,
                region_name=global_region,
            )
        else:
            session = self.session_class_factory(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=global_region,
            )
        sts = session.client("sts")
        log.info(f"Create AWS session by assuming role: {role_arn}.")
        token = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"{aws_account}-{str(uuid.uuid4())}",
            DurationSeconds=3600,  # 1 hour
        )
        credentials = token["Credentials"]
        return self.session_class_factory(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=global_region,
        )

    def _session(
        self,
        aws_account: str,
        aws_role: Optional[str] = None,
        aws_profile: Optional[str] = None,
        aws_partition: str = "aws",
    ) -> BotoSession:
        """
        Note: the session is not thread safe - caller needs to synchronize access.
        Consider using the client() and resource() methods instead.
        """
        if aws_role is None:
            return self.__direct_session(aws_profile, aws_partition)
        else:
            # Use sts to create a temporary token for the given account and role
            # Sts session is at least valid for 900 seconds (default 1 hour)
            # let's renew the session after 10 minutes
            return self.__sts_session(aws_account, aws_role, aws_profile, aws_partition, int(time.time() / 600))

    def client(
        self,
        aws_account: str,
        aws_role: Optional[str],
        aws_profile: Optional[str],
        aws_service: str,
        region_name: Optional[str] = None,
        config: Optional[BotoConfig] = None,
        aws_partition: str = "aws",
    ) -> BaseClient:
        with self.session_lock:
            session = self._session(aws_account, aws_role, aws_profile, aws_partition)
            return session.client(aws_service, region_name=region_name, config=config)

    def resource(
        self,
        aws_account: str,
        aws_role: Optional[str],
        aws_profile: Optional[str],
        aws_service: str,
        region_name: Optional[str] = None,
        config: Optional[BotoConfig] = None,
        aws_partition: str = "aws",
    ) -> Any:
        with self.session_lock:
            session = self._session(aws_account, aws_role, aws_profile, aws_partition)
            return session.resource(aws_service, region_name=region_name, config=config)

    def purge_caches(self) -> None:
        self.__direct_session.cache_clear()
        self.__sts_session.cache_clear()


@define(slots=False)
class AwsConfig:
    kind: ClassVar[str] = "aws"
    access_key_id: Optional[str] = field(
        default=None,
        metadata={"description": "AWS Access Key ID (null to load from env - recommended)"},
    )
    secret_access_key: Optional[str] = field(
        default=None,
        metadata={"description": "AWS Secret Access Key (null to load from env - recommended)"},
    )
    role: Optional[str] = field(default=None, metadata={"description": "IAM role name to assume"})
    role_override: bool = field(
        default=False,
        metadata={"description": "Override any stored role names (e.g. from remote graphs)"},
    )
    profiles: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of AWS profiles to collect"},
    )
    account: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of AWS Account ID(s) to collect (null for all if scrape_org is true)"},
    )
    region: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of AWS Regions to collect (null for all)"},
    )
    scrape_org: bool = field(default=False, metadata={"description": "Scrape the entire AWS organization"})
    scrape_org_role_arn: Optional[str] = field(
        default=None,
        metadata={
            "description": "Role ARN to assume when listing AWS org accounts. If set to null Fix will use the"
            " default credentials it was started with to call organizations:ListAccounts"
        },
    )
    prefer_account_alias_as_name: bool = field(
        default=True,
        metadata={
            "description": "Prefer the account alias as the account name instead of organization."
            " If set to false, Fix will try to use the organization name. If scrape_org_role_arn is defined,"
            " the role will be assumed when calling organizations:DescribeAccount."
        },
    )
    prefer_profile_as_account_name: bool = field(
        default=False,
        metadata={"description": "Prefer the profile name as the account name, if a profile was used."},
    )
    fork_process: bool = field(
        default=True,
        metadata={
            "description": "Fork collector process instead of using threads. "
            "Recommended if you want to scrape many accounts in parallel."
        },
    )
    scrape_exclude_account: List[str] = field(
        factory=list,
        metadata={"description": "List of accounts to exclude when scraping the org"},
    )
    assume_current: bool = field(default=False, metadata={"description": "Assume given role in current account"})
    do_not_scrape_current: bool = field(default=False, metadata={"description": "Do not scrape current account"})
    account_pool_size: int = field(
        default=num_default_threads(2),
        metadata={
            "description": "Number of accounts to scrape in parallel. "
            "For a large number of accounts we recommend to increase this number and use fork_process."
            "Note: increasing this number will result in increased cpu and memory usage."
        },
    )
    resource_pool_size: int = field(
        default=64,
        metadata={"description": "Number of shared threads available per account."},
    )
    resource_pool_tasks_per_service_default: int = field(
        default=20,
        metadata={
            "description": "Number of collector threads to run in parallel per service and region.\n"
            "Note that the total number of collector threads is limited by resource_pool_size.\n"
            "A value greater than the resource_pool_size does not have any effect."
        },
    )
    resource_pool_tasks_per_service: Optional[Dict[str, int]] = field(
        factory=lambda: {"sagemaker": 6, "elb": 6},
        metadata={
            "description": "Define the number of collector threads allowed for an individual service.\n"
            "If the service is not defined here, the default value is used.\n"
            'Example: {"ec2": 10, "rds": 5}'
        },
    )
    collect: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "List of AWS services to collect (default: all).\n"
                "You can use GLOB patterns like ? and * to match multiple services."
            )
        },
    )
    no_collect: List[str] = field(
        factory=list,
        metadata={
            "description": (
                "List of AWS services to exclude (default: none).\n"
                "You can use GLOB patterns like ? and * to match multiple services."
            )
        },
    )
    cloudwatch_metrics_for_atime_mtime_period: str = field(
        default="60d",
        metadata={
            "type_hint": "duration",
            "description": "This value is used to look up atime and mtime for volumes and rds instances.\n"
            "It defines how long Fix should look back for CloudWatch metrics.\n"
            "If no metric is found, now-period is used as atime and mtime. Defaults to 60 days.",
        },
    )
    cloudwatch_metrics_for_atime_mtime_granularity: str = field(
        default="1h",
        metadata={
            "type_hint": "duration",
            "description": "Granularity of atime and mtime.\n"
            "Higher precision is more expensive: Fix will fetch period * granularity data points.\n"
            "Defaults to 1 hour.",
        },
    )
    discard_account_on_resource_error: bool = field(
        default=False,
        metadata={
            "description": "Fail the whole account if collecting a resource fails. "
            "If false, the error is logged and the resource is skipped."
        },
    )
    collect_usage_metrics: Optional[bool] = field(
        default=True,
        metadata={"description": "Collect resource usage metrics via CloudWatch, enabled by default"},
    )

    @staticmethod
    def from_json(json: Json) -> "AwsConfig":
        valid_fields = fields_dict(AwsConfig).keys()
        for field_name in json.copy().keys():
            if field_name not in valid_fields:
                del json[field_name]
        return from_js(json, AwsConfig)

    def atime_mtime_period(self) -> timedelta:
        return parse_duration(self.cloudwatch_metrics_for_atime_mtime_period)

    def atime_mtime_granularity(self) -> timedelta:
        return parse_duration(self.cloudwatch_metrics_for_atime_mtime_granularity)

    def should_collect(self, name: str) -> bool:
        # no_collect has precedence over collect
        if self.no_collect and any(fnmatch(name, p) for p in self.no_collect):
            return False
        if self.collect:
            return any(fnmatch(name, p) for p in self.collect)
        return True

    def shared_tasks_per_key(self, regions: List[str]) -> Callable[[str], int]:
        # some services have known lower limits, the predefined limits can be overridden
        defined = self.resource_pool_tasks_per_service or {}
        tpk = {region + ":" + service: num for region in regions for service, num in defined.items()}

        def shared_tasks_per_key(key: str) -> int:
            value = tpk.get(key) or self.resource_pool_tasks_per_service_default
            # make sure that tasks_per_key is at least 1 and not more than shared_pool_parallelism
            return max(min(value, self.resource_pool_tasks_per_service_default), 1)

        return shared_tasks_per_key

    _lock: threading.RLock = field(factory=threading.RLock)
    _holder: Optional[AwsSessionHolder] = field(default=None)

    def __getstate__(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d.pop("_lock", None)
        d.pop("_holder", None)
        return d

    def __setstate__(self, d: Dict[str, Any]) -> None:
        d["_lock"] = threading.RLock()
        d["_holder"] = None
        self.__dict__.update(d)

    def sessions(self) -> AwsSessionHolder:
        if self._holder is None:
            with self._lock:
                if self._holder is None:
                    log.debug("Creating a new AWS session holder")
                    self._holder = AwsSessionHolder(
                        access_key_id=self.access_key_id,
                        secret_access_key=self.secret_access_key,
                        role=self.role,
                        role_override=self.role_override,
                    )
        return self._holder
