import logging
import threading
import time
import uuid
from datetime import timedelta

from resotolib.types import Json
from attrs import define, field, fields_dict
from functools import lru_cache
from typing import List, ClassVar, Optional, Type, Any, Dict

from resotolib.json import from_json as from_js
from boto3.session import Session as BotoSession

from resotolib.durations import parse_duration
from resotolib.proc import num_default_threads

log = logging.getLogger("resoto.plugins.aws")


@define(hash=True, slots=False)
class AwsSessionHolder:
    access_key_id: Optional[str]
    secret_access_key: Optional[str]
    role: Optional[str] = None
    role_override: bool = False
    # Only here to override in tests
    session_class_factory: Type[BotoSession] = BotoSession
    kind: ClassVar[str] = "aws_session_holder"

    # noinspection PyUnusedLocal
    @lru_cache(maxsize=128)
    def __direct_session(self, profile: Optional[str], thread_id: Any) -> BotoSession:
        if profile:
            return self.session_class_factory(profile_name=profile)
        else:
            return self.session_class_factory(
                aws_access_key_id=self.access_key_id, aws_secret_access_key=self.secret_access_key
            )

    # noinspection PyUnusedLocal
    @lru_cache(maxsize=512)
    def __sts_session(
        self, aws_account: str, aws_role: str, profile: Optional[str], thread_id: Any, cache_key: int
    ) -> BotoSession:
        role = self.role if self.role_override else aws_role
        role_arn = f"arn:aws:iam::{aws_account}:role/{role}"
        if profile:
            session = self.session_class_factory(
                profile_name=profile,
                region_name="us-east-1",
            )
        else:
            session = self.session_class_factory(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name="us-east-1",
            )
        sts = session.client("sts")
        token = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"{aws_account}-{str(uuid.uuid4())}")
        credentials = token["Credentials"]
        return self.session_class_factory(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

    def session(
        self, aws_account: str, aws_role: Optional[str] = None, aws_profile: Optional[str] = None
    ) -> BotoSession:
        # sessions should not be shared across threads
        # https://boto3.amazonaws.com/v1/documentation/api/1.14.31/guide/session.html#multithreading-or-multiprocessing-with-sessions
        thread_id = threading.current_thread().ident
        if aws_role is None:
            return self.__direct_session(aws_profile, thread_id)
        else:
            # Use sts to create a temporary token for the given account and role
            # Sts session is at least valid for 900 seconds (default 1 hour)
            # let's renew the session after 10 minutes
            return self.__sts_session(aws_account, aws_role, aws_profile, thread_id, int(time.time() / 600))


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
    fork_process: bool = field(
        default=True,
        metadata={"description": "Fork collector process instead of using threads"},
    )
    scrape_exclude_account: List[str] = field(
        factory=list,
        metadata={"description": "List of accounts to exclude when scraping the org"},
    )
    assume_current: bool = field(default=False, metadata={"description": "Assume given role in current account"})
    do_not_scrape_current: bool = field(default=False, metadata={"description": "Do not scrape current account"})
    account_pool_size: int = field(
        factory=num_default_threads,
        metadata={"description": "Account thread/process pool size"},
    )
    region_pool_size: int = field(default=128, metadata={"description": "Region thread pool size"})
    shared_pool_size: int = field(
        default=128,
        metadata={"description": "Number of threads available shared for all regions"},
    )
    region_resources_pool_size: int = field(
        default=2, metadata={"description": "Number of threads to collect a single region"}
    )
    collect: List[str] = field(
        factory=list,
        metadata={"description": "List of AWS services to collect (default: all)"},
    )
    no_collect: List[str] = field(
        factory=list,
        metadata={"description": "List of AWS services to exclude (default: none)"},
    )
    cloudwatch_metrics_for_atime_mtime_period: str = field(
        default="60d",
        metadata={
            "type_hint": "duration",
            "description": "This value is used to look up atime and mtime for volumes and rds instances.\n"
            "It defines how long Resoto should look back for CloudWatch metrics.\n"
            "If no metric is found, now-period is used as atime and mtime. Defaults to 60 days.",
        },
    )
    cloudwatch_metrics_for_atime_mtime_granularity: str = field(
        default="1h",
        metadata={
            "type_hint": "duration",
            "description": "Granularity of atime and mtime.\n"
            "Higher precision is more expensive: Resoto will fetch period * granularity data points.\n"
            "Defaults to 1 hour.",
        },
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
        if self.collect:
            return name in self.collect
        if self.no_collect:
            return name not in self.no_collect
        return True

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
                    log.info("Create a new AWS session holder")
                    self._holder = AwsSessionHolder(
                        access_key_id=self.access_key_id,
                        secret_access_key=self.secret_access_key,
                        role=self.role,
                        role_override=self.role_override,
                    )
        return self._holder
