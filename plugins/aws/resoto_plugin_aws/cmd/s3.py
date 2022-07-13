import botocore.exceptions
import sys
import inspect
import pathlib
from typing import Iterable
from collections import deque
from itertools import islice
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    PrimaryKeyConstraint,
)
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter
import resotolib.logger
from resotov1.cli import replace_placeholder
from resotolib.utils import split_esc, iec_size_format
from resotolib.args import get_arg_parser, ArgumentParser
from resoto_plugin_aws.utils import aws_session
from resoto_plugin_aws.resources import AWSAccount
from resoto_plugin_aws import current_account_id, AWSPlugin, get_org_accounts

resotolib.logger.getLogger("resoto.cmd").setLevel(resotolib.logger.INFO)
log = resotolib.logger.getLogger("resoto.cmd")

argv = sys.argv[1:]
if "-v" in argv or "--verbose" in argv:
    resotolib.logger.getLogger("resoto.cmd").setLevel(resotolib.logger.DEBUG)
log.info("resoto S3 bucket collector")


def add_args(arg_parser: ArgumentParser) -> None:
    AWSPlugin.add_args(arg_parser)
    arg_parser.add_argument(
        "--aws-s3-db",
        help="Path to local AWS S3 database file",
        dest="aws_s3_db",
        default=":memory:",
    )
    arg_parser.add_argument(
        "--aws-s3-db-debug",
        help="Debug SQL queries (default: False)",
        dest="aws_s3_db_debug",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--aws-s3-bucket",
        help="AWS S3 Bucket to collect (default: all)",
        dest="aws_s3_bucket",
        default=None,
    )
    arg_parser.add_argument(
        "--aws-s3-skip-checks",
        help="Skip SQL exists checks (default: False)",
        dest="aws_s3_skip_checks",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--aws-s3-collect",
        help="Collect from S3 (default: False)",
        dest="aws_s3_collect",
        action="store_true",
        default=False,
    )
    default_history_file = pathlib.Path.home() / ".resoto_s3_history"
    cli_history_default = None
    if default_history_file.exists():
        cli_history_default = str(default_history_file)
    arg_parser.add_argument(
        "--aws-s3-cli-history",
        help=("Path to AWS S3 CLI history file" " (default: None or ~/.resoto_s3_history if exists)"),
        dest="aws_s3_cli_history",
        type=str,
        default=cli_history_default,
    )


arg_parser = get_arg_parser()
add_args(arg_parser)
arg_parser.parse_args()
engine_args = ""
engine = create_engine(
    f"sqlite:///{ArgumentParser.args.aws_s3_db}",
    echo=ArgumentParser.args.aws_s3_db_debug,
)
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
    __tablename__ = "bucketobjects"
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
    if ArgumentParser.args.aws_s3_collect:
        collect()
    cli()


def cli():
    session = PromptSession(history=None)
    history = None
    if ArgumentParser.args.aws_s3_cli_history:
        history = FileHistory(ArgumentParser.args.aws_s3_cli_history)
    session = PromptSession(history=history)
    dbs = Session()
    pwd = "/"
    while True:
        completer = WordCompleter(CliHandler(dbs, pwd).valid_commands)
        try:
            cli_input = session.prompt(f"{pwd} > ", completer=completer)
            if cli_input == "":
                continue

            ch = CliHandler(dbs, pwd)
            for item in ch.evaluate_cli_input(cli_input):
                print(item)
            pwd = ch.pwd

        except KeyboardInterrupt:
            pass
        except EOFError:
            CliHandler.quit("Keyboard Shutdown")
        except (RuntimeError, ValueError) as e:
            log.error(e)
        except Exception:
            log.exception("Caught unhandled exception while processing CLI command")


def collect():
    accounts = get_accounts()
    for account in accounts:
        if not ArgumentParser.args.aws_s3_bucket:
            try:
                buckets = collect_buckets(account)
            except Exception:
                log.exception(f"Failed to collect buckets in {account.rtdname}")
            else:
                for bucket in buckets:
                    try:
                        collect_bucket(account, bucket.name)
                    except Exception:
                        log.exception(f"Failed to collect bucket {bucket.name} in {account.rtdname}")
        else:
            try:
                collect_bucket(account, ArgumentParser.args.aws_s3_bucket)
            except Exception:
                log.exception(f"Failed to collect bucket {ArgumentParser.args.aws_s3_bucket} in {account.rtdname}")


def collect_bucket(account: AWSAccount, bucket_name):
    session = aws_session(account.id, account.role)
    s3 = session.resource("s3")
    dbs = Session()

    log.info(f"Collecting all objects in AWS S3 bucket {bucket_name} in {account.rtdname}")
    bucket = s3.Bucket(bucket_name)
    for bucket_object in bucket.objects.all():
        # TODO: this could be highly optimized via batching
        if (
            not ArgumentParser.args.aws_s3_skip_checks
            and dbs.query(BucketObject)
            .filter_by(account=account.id, bucket_name=bucket_name, name=bucket_object.key)
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
            not ArgumentParser.args.aws_s3_skip_checks
            and dbs.query(Bucket).filter_by(account=account.id, name=bucket_name).scalar() is not None
        ):
            continue

        b = Bucket(account=account.id, name=bucket_name, ctime=bucket_ctime)
        log.info(f"Found bucket {bucket_name} in {account.rtdname}")
        dbs.add(b)
    dbs.commit()

    return dbs.query(Bucket).filter_by(account=account.id)


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

    if ArgumentParser.args.aws_assume_current and not ArgumentParser.args.aws_dont_scrape_current:
        log.warning(
            "You specified --aws-assume-current but not --aws-dont-scrape-current! "
            "This will result in the same account being scraped twice and is likely not what you want."
        )

    if ArgumentParser.args.aws_role and ArgumentParser.args.aws_scrape_org:
        accounts = [
            AWSAccount(id=aws_account_id, tags={}, role=ArgumentParser.args.aws_role)
            for aws_account_id in get_org_accounts(filter_current_account=not ArgumentParser.args.aws_assume_current)
            if aws_account_id not in ArgumentParser.args.aws_scrape_exclude_account
        ]
        if not ArgumentParser.args.aws_dont_scrape_current:
            accounts.append(AWSAccount(id=current_account_id(), tags={}))
    elif ArgumentParser.args.aws_role and ArgumentParser.args.aws_account:
        accounts = [
            AWSAccount(id=aws_account_id, tags={}, role=ArgumentParser.args.aws_role)
            for aws_account_id in ArgumentParser.args.aws_account
        ]
    else:
        accounts = [AWSAccount(id=current_account_id(), tags={})]

    return accounts


class CliHandler:
    def __init__(self, dbs, pwd) -> None:
        self.dbs = dbs
        self.commands = {}
        self.pwd = pwd
        self.current_directories = []
        self.current_files = []
        for f, m in inspect.getmembers(self, predicate=inspect.ismethod):
            if f.startswith("cmd_"):
                self.commands[f[4:]] = m
        self.valid_commands = sorted(self.commands.keys())

    def evaluate_cli_input(self, cli_input: str) -> Iterable:
        cli_input = replace_placeholder(cli_input)
        for cmd_chain in split_esc(cli_input, ";"):
            cmds = (cmd.strip() for cmd in split_esc(cmd_chain, "|"))
            items = ()
            for cmd in cmds:
                args = ""
                if " " in cmd:
                    cmd, args = cmd.split(" ", 1)
                if cmd in self.commands:
                    items = self.commands[cmd](items, args)
                else:
                    items = (f"Unknown command: {cmd}",)
                    break
            for item in items:
                yield item

    @staticmethod
    def quit(reason=None):
        log.info(f"Shutting down: {reason}")
        sys.exit(0)

    def cmd_quit(self, items: Iterable, args: str) -> Iterable:
        """Usage: quit

        Quit resoto.
        """
        self.quit("Shutdown requested by CLI input")
        return ()

    def cmd_echo(self, items: Iterable, args: str) -> Iterable:
        """Usage: echo [string]

        Echo a string to the console.

        Can be used for testing string substitution.
        E.g. echo @TODAY@
        """
        yield args

    def cmd_help(self, items: Iterable, args: str) -> Iterable:
        """Usage: help <command>

        Show help text for a command.
        """
        extra_doc = ""
        if args == "":
            args = "help"
            valid_commands = "\n    ".join(self.valid_commands)
            placeholder_help = inspect.getdoc(replace_placeholder)
            extra_doc = f"""\n
{placeholder_help}

Valid commands are:
    {valid_commands}

Note that you can pipe commands using the pipe character (|)
and chain multipe commands using the semicolon (;).
            """
        if args in self.commands:
            doc = inspect.getdoc(self.commands[args])
            if doc is None:
                doc = f"Command {args} has no help text."
        else:
            doc = f"Unknown command: {args}"
        doc += extra_doc
        return (doc,)

    def cmd_head(self, items: Iterable, args: str) -> Iterable:
        """Usage: | head <num> |

        Returns the first num lines.
        """
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return islice(items, num)

    def cmd_tail(self, items: Iterable, args: str) -> Iterable:
        """Usage: | tail <num> |

        Returns the last num lines.
        """
        num = int(args) if len(args) > 0 else 10
        if num < 0:
            num *= -1
        return deque(items, num)

    def cmd_accounts(self, items: Iterable, args: str) -> Iterable:
        """Usage: accounts |

        Returns all known accounts.
        """
        for result in self.dbs.query(Bucket.account).distinct().all():
            yield result.account

    def cmd_buckets(self, items: Iterable, args: str) -> Iterable:
        """Usage: buckets |

        Returns all known buckets.
        """
        for result in self.dbs.query(Bucket).all():
            yield result.name

    def cmd_ls(self, items: Iterable, args: str) -> Iterable:
        """Usage: ls [-t|-S] |

        List buckets.
            -t order by mtime
            -S order by size
        """
        if args == "-t":
            order_by = "mtime"
        elif args == "-S":
            order_by = "size"
        else:
            order_by = "dname"
        components = self.pwd.split("/", 3)
        if len(components) == 2:
            account = components[1]
            if account == "":
                account = None
            bucket = None
            s3object = None
        elif len(components) == 3:
            account = components[1]
            bucket = components[2]
            s3object = None
        elif len(components) == 4:
            account = components[1]
            bucket = components[2]
            s3object = components[3] + "/"

        yield f"{'type':<8} {'size':>10} {'modification date':>22} {'name':>40}"
        if account is None:
            for result in list_accounts(self.dbs, order_by=order_by):
                yield self.fprint_result("account", result.size, result.mtime, result.dname)
        elif bucket is None:
            for result in list_buckets(self.dbs, account, order_by=order_by):
                yield self.fprint_result("bucket", result.size, result.mtime, result.dname)
        else:
            for result in list_directories(self.dbs, account, bucket, s3object, order_by=order_by):
                if result.dname == "":
                    directory = "."
                else:
                    directory = result.dname
                yield self.fprint_result("dir", result.size, result.mtime, directory)
            for result in list_objects(self.dbs, account, bucket, s3object, order_by=order_by):
                if len(result.dname) > 0:
                    yield self.fprint_result("file", result.size, result.mtime, result.dname)

    @staticmethod
    def fprint_result(obj_type, obj_size, obj_date, obj_name):
        obj_size = iec_size_format(obj_size)
        return f"{obj_type:<8} {obj_size:>10} {str(obj_date):>22} {obj_name:>40}"

    def cmd_cd(self, items: Iterable, args: str) -> Iterable:
        """Usage: cd <directory>

        Change directory
        """
        if args != "/":
            args = args.rstrip("/")
        if args == ".":
            return ()
        elif args == "..":
            self.pwd = "/".join(self.pwd.split("/")[:-1])
            if self.pwd == "":
                self.pwd = "/"
        elif args.startswith("/"):
            self.pwd = args
        else:
            if self.pwd == "/":
                self.pwd = self.pwd + args
            else:
                self.pwd = self.pwd + "/" + args
        return ()

    def cmd_pwd(self, items: Iterable, args: str) -> Iterable:
        """Usage: pwd

        Show current rirectory
        """
        yield self.pwd

    def cmd_sql(self, items: Iterable, args: str) -> Iterable:
        """Usage: sql <SQL QUERY>

        Execute a raw SQL query
        """
        for row in engine.execute(args):
            yield row


def list_accounts(dbs, order_by="dname"):
    results = (
        dbs.query(
            BucketObject.account.label("dname"),
            func.sum(BucketObject.size).label("size"),
            func.max(BucketObject.mtime).label("mtime"),
        )
        .group_by(BucketObject.account)
        .order_by(order_by)
    )
    return results


def list_buckets(dbs, account, order_by="dname"):
    results = (
        dbs.query(
            BucketObject.account,
            BucketObject.bucket_name.label("dname"),
            func.sum(BucketObject.size).label("size"),
            func.max(BucketObject.mtime).label("mtime"),
        )
        .filter_by(account=account)
        .group_by(BucketObject.account, BucketObject.bucket_name)
        .order_by(order_by)
    )
    return results


def list_objects(dbs, account, bucket_name, dirname, limit=10000, order_by="dname"):
    if dirname is None:
        dirname = ""
    dirname_len = len(dirname) + 1
    results = (
        dbs.query(
            BucketObject.account,
            BucketObject.bucket_name,
            func.substr(BucketObject.name, dirname_len).label("dname"),
            BucketObject.size.label("size"),
            BucketObject.mtime.label("mtime"),
        )
        .filter_by(account=account, bucket_name=bucket_name)
        .filter(BucketObject.name.like(dirname + "%"))
        .filter(func.substr(BucketObject.name, dirname_len).notlike("%/%"))
        .order_by(order_by)
        .limit(limit)
    )
    return results


def list_directories(dbs, account, bucket_name, dirname, order_by="dname"):
    if dirname is None:
        dirname = ""
    dirname_len = len(dirname) + 1

    results = (
        dbs.query(
            BucketObject.account,
            BucketObject.bucket_name,
            func.substr(
                BucketObject.name,
                dirname_len,
                func.instr(func.substr(BucketObject.name, dirname_len), "/"),
            ).label("dname"),
            func.sum(BucketObject.size).label("size"),
            func.max(BucketObject.mtime).label("mtime"),
        )
        .filter_by(account=account, bucket_name=bucket_name)
        .filter(BucketObject.name.like(dirname + "%"))
        .group_by(BucketObject.account, BucketObject.bucket_name, "dname")
        .order_by(order_by)
    )
    return results


if __name__ == "__main__":
    main()
