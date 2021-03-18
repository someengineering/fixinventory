#!/usr/bin/env python
import sys
from prompt_toolkit.shortcuts import button_dialog
from cloudkeeper_plugin_aws.utils import aws_session
from cloudkeeper_plugin_aws.resources import AWSAccount
from cloudkeeper_plugin_aws import AWSPlugin, current_account_id
from cloudkeeper.utils import make_valid_timestamp
from cloudkeeper.args import get_arg_parser, ArgumentParser
import cloudkeeper.logging
import re
from datetime import datetime

cloudkeeper.logging.getLogger("cloudkeeper.cmd").setLevel(cloudkeeper.logging.INFO)
log = cloudkeeper.logging.getLogger("cloudkeeper.cmd")

argv = sys.argv[1:]
if "-v" in argv or "--verbose" in argv:
    cloudkeeper.logging.getLogger("cloudkeeper.cmd").setLevel(cloudkeeper.logging.DEBUG)
log.info("Cloudkeeper S3 object purger")


def add_args(arg_parser: ArgumentParser) -> None:
    AWSPlugin.add_args(arg_parser)
    arg_parser.add_argument(
        "--aws-s3-bucket",
        help="AWS S3 Bucket (default: None)",
        dest="aws_s3_bucket",
        required=True,
        default=None,
    )
    arg_parser.add_argument(
        "--aws-s3-prefix",
        help="AWS S3 Prefix (default: None)",
        dest="aws_s3_prefix",
        type=str,
        default="",
    )
    arg_parser.add_argument(
        "--aws-s3-mtime",
        help="AWS S3 Mtime (default: None)",
        dest="aws_s3_mtime",
        type=str,
        default=None,
    )
    arg_parser.add_argument(
        "--aws-s3-pattern",
        help="AWS S3 Pattern (default: None)",
        dest="aws_s3_pattern",
        type=str,
        default=None,
    )
    arg_parser.add_argument(
        "--aws-s3-yes",
        help="AWS S3 delete without asking (default: False)",
        dest="aws_s3_yes",
        action="store_true",
        default=False,
    )


arg_parser = get_arg_parser()
add_args(arg_parser)
arg_parser.parse_args()


def main():
    if ArgumentParser.args.aws_role and ArgumentParser.args.aws_account:
        accounts = [
            AWSAccount(aws_account_id, {}, role=ArgumentParser.args.aws_role)
            for aws_account_id in ArgumentParser.args.aws_account
        ]
    else:
        accounts = [AWSAccount(current_account_id(), {})]

    if len(accounts) != 1:
        log.error("This tool only supports a single account at a time")
        sys.exit(1)

    account = accounts[0]
    session = aws_session(account.id, account.role)
    client = session.client("s3")
    Bucket = ArgumentParser.args.aws_s3_bucket
    Prefix = ArgumentParser.args.aws_s3_prefix

    mtime = (
        make_valid_timestamp(datetime.fromisoformat(ArgumentParser.args.aws_s3_mtime))
        if ArgumentParser.args.aws_s3_mtime
        else None
    )

    IsTruncated = True
    MaxKeys = 500
    KeyMarker = None
    VersionIdMarker = None

    while IsTruncated == True:
        if KeyMarker and VersionIdMarker:
            version_list = client.list_object_versions(
                Bucket=Bucket,
                MaxKeys=MaxKeys,
                Prefix=Prefix,
                KeyMarker=KeyMarker,
                VersionIdMarker=VersionIdMarker,
            )
        elif KeyMarker:
            version_list = client.list_object_versions(
                Bucket=Bucket, MaxKeys=MaxKeys, Prefix=Prefix, KeyMarker=KeyMarker
            )
        else:
            version_list = client.list_object_versions(
                Bucket=Bucket, MaxKeys=MaxKeys, Prefix=Prefix
            )
        IsTruncated = version_list.get("IsTruncated", False)
        KeyMarker = version_list.get("NextKeyMarker")
        VersionIdMarker = version_list.get("NextVersionIdMarker")

        delete_objects = []
        versions = version_list.get("Versions", [])
        versions.extend(version_list.get("DeleteMarkers", []))
        for v in versions:
            object_version = v["VersionId"]
            object_key = v["Key"]
            # object_size = v["Size"]
            object_mtime = make_valid_timestamp(v["LastModified"])

            if mtime and object_mtime > mtime:
                log.debug(
                    f"Object {object_key} with mtime {object_mtime} newer than mtime {mtime}"
                )
                continue
            if (
                ArgumentParser.args.aws_s3_pattern
                and bool(re.search(ArgumentParser.args.aws_s3_pattern, str(object_key)))
                is False
            ):
                log.debug(
                    f"Object {object_key} does not match {ArgumentParser.args.aws_s3_pattern}"
                )
                continue
            log.info(
                f"Object {object_key} with version {object_version} and mtime {object_mtime} matches {ArgumentParser.args.aws_s3_pattern}"
            )
            delete_objects.append({"VersionId": object_version, "Key": object_key})
        try:
            if len(delete_objects) > 0:
                str_delete_objects = "\n".join([do["Key"] for do in delete_objects])
                if ArgumentParser.args.aws_s3_yes is True:
                    confirm_delete = True
                else:
                    confirm_delete = button_dialog(
                        title=f"Delete {len(delete_objects)} S3 objects?",
                        text=f"Really delete these objects?\n{str_delete_objects}",
                        buttons=[("Yes", True), ("No", False), ("Abort", None)],
                    ).run()

                if confirm_delete is None:
                    sys.exit(0)
                elif confirm_delete is True:
                    response = client.delete_objects(
                        Bucket=Bucket, Delete={"Objects": delete_objects}
                    )
                    log.info(f"Delete response {response}")
        except Exception:
            log.exception(f"Something went wrong trying to delete")


if __name__ == "__main__":
    main()
