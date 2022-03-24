from dataclasses import dataclass, field
from typing import List, ClassVar, Optional


@dataclass
class AwsConfig:
    kind: ClassVar[str] = "aws"
    access_key_id: Optional[str] = field(
        default=None, metadata={"description": "AWS Access Key ID"}
    )
    secret_access_key: Optional[str] = field(
        default=None, metadata={"description": "AWS Secret Access Key"}
    )
    role: Optional[str] = field(default=None, metadata={"description": "AWS IAM Role"})
    role_override: Optional[bool] = field(
        default=False,
        metadata={"description": "Override any stored roles (e.g. from remote graphs)"},
    )
    account: Optional[List[str]] = field(
        default=None, metadata={"description": "List of AWS Account ID(s) to collect"}
    )
    region: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of AWS Regions to collect (default: all)"},
    )
    scrape_org: Optional[bool] = field(
        default=False, metadata={"description": "Scrape the entire AWS Org"}
    )
    fork: Optional[bool] = field(
        default=False,
        metadata={"description": "Forked collector process instead of threads"},
    )
    scrape_exclude_account: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of accounts to exclude when scraping the org"},
    )
    assume_current: Optional[bool] = field(
        default=False, metadata={"description": "Assume role in current account"}
    )
    do_not_scrape_current: Optional[bool] = field(
        default=False, metadata={"description": "Do not scrape current account"}
    )
    account_pool_size: Optional[int] = field(
        default=5, metadata={"description": "Account thread/process pool size"}
    )
    region_pool_size: Optional[int] = field(
        default=20, metadata={"description": "Region thread/process pool size"}
    )
    collect: Optional[List[str]] = field(
        default=None,
        metadata={"description": "List of AWS services to collect (default: all)"},
    )
    no_collect: Optional[List[str]] = field(
        default_factory=list,
        metadata={"description": "List of AWS services to exclude (default: none)"},
    )
