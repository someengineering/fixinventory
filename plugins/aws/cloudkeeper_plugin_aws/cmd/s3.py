import botocore.exceptions
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    PrimaryKeyConstraint,
)
import cloudkeeper.logging
from cloudkeeper.args import get_arg_parser, ArgumentParser
from sqlalchemy.sql.sqltypes import Date
from cloudkeeper_plugin_aws.utils import aws_session
from cloudkeeper_plugin_aws.resources import AWSAccount
from cloudkeeper_plugin_aws import current_account_id, AWSPlugin, get_org_accounts

cloudkeeper.logging.getLogger("cloudkeeper.cmd").setLevel(cloudkeeper.logging.INFO)
log = cloudkeeper.logging.getLogger("cloudkeeper.cmd")

argv = sys.argv[1:]
if "-v" in argv or "--verbose" in argv:
    cloudkeeper.logging.getLogger("cloudkeeper").setLevel(cloudkeeper.logging.DEBUG)
log.info("Cloudkeeper S3 bucket collector")

def add_args(arg_parser: ArgumentParser) -> None:
    AWSPlugin.add_args(arg_parser)
    arg_parser.add_argument(
        "--aws-s3-cache",
        help="AWS S3 Cache",
        dest="aws_s3_cache",
        default=":memory:",
    )
    arg_parser.add_argument(
        "--aws-s3-bucket",
        help="AWS S3 Bucket",
        dest="aws_s3_bucket",
        default=None,
    )
    arg_parser.add_argument(
        "--aws-s3-skip-checks",
        help="Skip SQL exists checks",
        dest="skip_checks",
        action="store_true",
        default=False,
    )


arg_parser = get_arg_parser()
add_args(arg_parser)
arg_parser.parse_args()
engine = create_engine(f"sqlite:///{ArgumentParser.args.aws_s3_cache}", echo=False)
Base = declarative_base(bind=engine)
Session = sessionmaker()


class Bucket(Base):
    __tablename__ = "buckets"
    __table_args__ = (PrimaryKeyConstraint("account", "name"),)

    account = Column(String, index=True)
    name = Column(String, index=True)
    ctime = Column(DateTime, index=True)

    def __repr__(self):
        return "<Bucket(account='%s', name='%s', ctime='%s')>" % (
            self.account,
            self.name,
            self.ctime,
        )


class BucketObject(Base):
    __tablename__ = "bucketobject"
    __table_args__ = (PrimaryKeyConstraint("account", "bucket_name", "name"),)

    account = Column(String, index=True)
    bucket_name = Column(String, index=True)
    name = Column(String, index=True)
    size = Column(Integer, index=True)
    mtime = Column(DateTime, index=True)

    def __repr__(self):
        return "<BucketObject(account= '%s', bucket_name='%s', name='%s', size='%s', mtime='%s')>" % (
            self.account,
            self.bucket_name,
            self.name,
            self.size,
            self.mtime,
        )


Base.metadata.create_all()


def main() -> None:
    accounts = get_accounts()
    for account in accounts:
        if not ArgumentParser.args.aws_s3_bucket:
            try:
                buckets = collect_buckets(account)
            except Exception:
                log.error(f"Failed to collect buckets in {account.rtdname}")
                continue
            for bucket in buckets:
                try:
                    collect_bucket(account, bucket.name)
                except Exception:
                    log.error(f"Failed to collect bucket {bucket.name} in {account.rtdname}")
                    continue
        else:
            try:
                collect_bucket(account, ArgumentParser.args.aws_s3_bucket)
            except Exception:
                log.error(f"Failed to collect bucket {ArgumentParser.args.aws_s3_bucket} in {account.rtdname}")
                continue


def collect_bucket(account: AWSAccount, bucket_name):
    session = aws_session(account.id, account.role)
    s3 = session.resource("s3")
    dbs = Session()

    log.info(f"Collecting all objects in AWS S3 bucket {bucket_name} in {account.rtdname}")
    bucket = s3.Bucket(bucket_name)
    for bucket_object in bucket.objects.all():
        # TODO: this could be highly optimized via batching
        if (
            not ArgumentParser.args.skip_checks
            and
            dbs.query(BucketObject)
            .filter_by(
                account=account.id, bucket_name=bucket_name, name=bucket_object.key
            )
            .scalar()
            is not None
        ):
            continue

        bo = BucketObject(
            account=account.id,
            bucket_name=bucket_name,
            name=bucket_object.key,
            size=bucket_object.size,
            mtime=bucket_object.last_modified,
        )
        dbs.add(bo)
    dbs.commit()


def collect_buckets(account: AWSAccount):
    session = aws_session(account.id, account.role)
    client = session.client("s3")
    dbs = Session()
    response = client.list_buckets()
    buckets = response.get("Buckets", [])

    log.info(f"Collecting all buckets in {account.rtdname}")

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        bucket_ctime = bucket.get("CreationDate")

        if (
            not ArgumentParser.args.skip_checks
            and
            dbs.query(Bucket).filter_by(account=account.id, name=bucket_name).scalar()
            is not None
        ):
            continue

        b = Bucket(account=account.id, name=bucket_name, ctime=bucket_ctime)
        log.info(f"Found bucket {bucket_name} in {account.rtdname}")
        dbs.add(b)
    dbs.commit()

    return dbs.query(Bucket)


def authenticated() -> bool:
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


def get_accounts():
    if not authenticated():
        log.error("Failed to authenticate")
        return []

    if (
        ArgumentParser.args.aws_assume_current
        and ArgumentParser.args.aws_scrape_current
    ):
        log.warning(
            "You specified --aws-assume-current but not --aws-dont-scrape-current! "
            "This will result in the same account being scraped twice and is likely not what you want."
        )

    if ArgumentParser.args.aws_role and ArgumentParser.args.aws_scrape_org:
        accounts = [
            AWSAccount(aws_account_id, {}, role=ArgumentParser.args.aws_role)
            for aws_account_id in get_org_accounts(
                filter_current_account=not ArgumentParser.args.aws_assume_current
            )
            if aws_account_id not in ArgumentParser.args.aws_scrape_exclude_account
        ]
        if ArgumentParser.args.aws_scrape_current:
            accounts.append(AWSAccount(current_account_id(), {}))
    elif ArgumentParser.args.aws_role and ArgumentParser.args.aws_account:
        accounts = [
            AWSAccount(aws_account_id, {}, role=ArgumentParser.args.aws_role)
            for aws_account_id in ArgumentParser.args.aws_account
        ]
    else:
        accounts = [AWSAccount(current_account_id(), {})]

    return accounts


if __name__ == "__main__":
    main()
