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
from cloudkeeper_plugin_aws import current_account_id

cloudkeeper.logging.getLogger("cloudkeeper.cmd").setLevel(cloudkeeper.logging.INFO)
log = cloudkeeper.logging.getLogger("cloudkeeper.cmd")

argv = sys.argv[1:]
if "-v" in argv or "--verbose" in argv:
    cloudkeeper.logging.getLogger("cloudkeeper").setLevel(cloudkeeper.logging.DEBUG)
log.info("Cloudkeeper S3 bucket collector")

def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--aws-access-key-id", help="AWS Access Key ID", dest="aws_access_key_id"
    )
    arg_parser.add_argument(
        "--aws-secret-access-key",
        help="AWS Secret Access Key",
        dest="aws_secret_access_key",
    )
    arg_parser.add_argument("--aws-role", help="AWS IAM Role", dest="aws_role")
    arg_parser.add_argument(
        "--aws-s3-bucket", help="AWS S3 Bucket", dest="aws_s3_bucket"
    )
    arg_parser.add_argument(
        "--aws-s3-cache",
        help="AWS S3 Cache",
        dest="aws_s3_cache",
        default=":memory:",
    )
    arg_parser.add_argument(
        "--aws-role-override",
        help="Override any stored roles (e.g. from remote graphs) (default: False)",
        dest="aws_role_override",
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
    # Add cli args

    if not ArgumentParser.args.aws_s3_bucket:
        for bucket in collect_buckets():
            collect_bucket(bucket.name)
    else:
        collect_bucket(ArgumentParser.args.aws_s3_bucket)


def collect_bucket(bucket_name):
    session = aws_session()
    account_id = current_account_id()
    s3 = session.resource("s3")
    dbs = Session()

    log.info(f"Collecting all objects in AWS S3 bucket {bucket_name}")
    bucket = s3.Bucket(bucket_name)
    for bucket_object in bucket.objects.all():
        if (
            dbs.query(BucketObject)
            .filter_by(
                account=account_id, bucket_name=bucket_name, name=bucket_object.key
            )
            .scalar()
            is not None
        ):
            continue

        bo = BucketObject(
            account=account_id,
            bucket_name=bucket_name,
            name=bucket_object.key,
            size=bucket_object.size,
            mtime=bucket_object.last_modified,
        )
        dbs.add(bo)
    dbs.commit()


def collect_buckets():
    session = aws_session()
    account_id = current_account_id()
    client = session.client("s3")
    dbs = Session()
    response = client.list_buckets()
    buckets = response.get("Buckets", [])

    log.info(f"Collecting all buckets in AWS account {account_id}")

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        bucket_ctime = bucket.get("CreationDate")

        if (
            dbs.query(Bucket).filter_by(account=account_id, name=bucket_name).scalar()
            is not None
        ):
            continue

        b = Bucket(account=account_id, name=bucket_name, ctime=bucket_ctime)
        log.info(f"Found bucket {bucket_name}")
        dbs.add(b)
    dbs.commit()

    return dbs.query(Bucket)


if __name__ == "__main__":
    main()
