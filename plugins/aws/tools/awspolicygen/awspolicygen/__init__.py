import os
import logging
from argparse import ArgumentParser, Namespace

"""
Fix AWS policy generator and uploader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script generates the required AWS access policy and uploads it to the CDN.
:copyright: © 2023 Some Engineering Inc.
:license: AGPL-3.0, see LICENSE for more details.
"""

__title__ = "awspolicygen"
__description__ = "Fix AWS policy generator and uploader."
__author__ = "Some Engineering Inc."
__license__ = "AGPL-3.0"
__copyright__ = "Copyright © 2024 Some Engineering Inc."
__version__ = "0.0.1"


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s",
)
log = logging.getLogger("awspolicygen")
log.setLevel(logging.INFO)


def get_arg_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Fix AWS policy generator and uploader")
    parser.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )
    return parser


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--api-token",
        help="DigitalOcean API token - to purge the CDN cache",
        dest="api_token",
        default=os.getenv("API_TOKEN", None),
    )
    arg_parser.add_argument(
        "--spaces-key",
        help="DigitalOcean Spaces Key",
        dest="spaces_key",
        default=os.getenv("SPACES_KEY", None),
    )
    arg_parser.add_argument(
        "--spaces-secret",
        help="DigitalOcean Spaces Secret",
        dest="spaces_secret",
        default=os.getenv("SPACES_SECRET", None),
    )
    arg_parser.add_argument(
        "--spaces-region",
        help="DigitalOcean Spaces Region",
        dest="spaces_region",
        default=os.getenv("SPACES_REGION", None),
    )
    arg_parser.add_argument(
        "--spaces-name",
        help="DigitalOcean Spaces name - the bucket name",
        dest="spaces_name",
        default=os.getenv("SPACES_NAME", None),
    )
    arg_parser.add_argument(
        "--spaces-path",
        help="DigitalOcean Spaces UI path - path where the UI is stored",
        dest="spaces_path",
        default=os.getenv("SPACES_PATH", None),
    )
    arg_parser.add_argument(
        "--github-ref",
        help="Github Ref",
        dest="github_ref",
        default=os.getenv("GITHUB_REF", None),
    )
    arg_parser.add_argument(
        "--github-ref-type",
        help="Github Ref Type",
        dest="github_ref_type",
        default=os.getenv("GITHUB_REF_TYPE", None),
    )
    arg_parser.add_argument(
        "--github-event-name",
        help="Github Event Name",
        dest="github_event_name",
        default=os.getenv("GITHUB_EVENT_NAME", None),
    )
    arg_parser.add_argument(
        "--aws-s3-bucket",
        help="AWS S3 Bucket",
        dest="aws_s3_bucket",
        default=os.getenv("AWS_S3_BUCKET", None),
    )
    arg_parser.add_argument(
        "--aws-s3-bucket-path",
        help="AWS S3 Bucket Path",
        dest="aws_s3_bucket_path",
        default=os.getenv("AWS_S3_BUCKET_PATH", None),
    )
    arg_parser.add_argument(
        "--aws-access-key-id",
        help="AWS Access Key ID",
        dest="aws_access_key_id",
        default=os.getenv("AWS_ACCESS_KEY_ID", None),
    )
    arg_parser.add_argument(
        "--aws-secret-access-key",
        help="AWS Secret Access Key",
        dest="aws_secret_access_key",
        default=os.getenv("AWS_SECRET_ACCESS_KEY", None),
    )


def verify_args(args: Namespace) -> None:
    if None in (
        args.api_token,
        args.spaces_key,
        args.spaces_secret,
        args.spaces_name,
        args.spaces_path,
        args.spaces_region,
        args.aws_s3_bucket,
        args.aws_s3_bucket_path,
        args.aws_access_key_id,
        args.aws_secret_access_key,
    ):
        raise ValueError("missing required argument")
    if not str(args.spaces_path).endswith("/"):
        raise ValueError(f"spaces path {args.spaces_path} must end with a slash")
    if str(args.spaces_path).startswith("/"):
        raise ValueError(f"spaces path {args.spaces_path} must not start with a slash")
    if not str(args.aws_s3_bucket_path).endswith("/"):
        raise ValueError(f"bucket path {args.aws_s3_bucket_path} must end with a slash")
    if str(args.aws_s3_bucket_path).startswith("/"):
        raise ValueError(f"bucket path {args.aws_s3_bucket_path} must not start with a slash")
