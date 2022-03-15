from datetime import timedelta

from arango import ArangoClient
from arango.database import StandardDatabase

from resotocore.analytics import NoEventSender
from resotocore.db.db_access import DbAccess
from resotocore.dependencies import parse_args, empty_config
from resotocore.model.adjust_node import NoAdjust

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import test_db, system_db, local_client


def test_already_existing(test_db: StandardDatabase) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust(), empty_config())

    # test db and user already exist
    testdb = ["--graphdb-username", "test", "--graphdb-password", "test", "--graphdb-database", "test"]
    access.connect(parse_args(testdb), timedelta(seconds=0.01), sleep_time=0.01)


def test_not_existing(system_db: StandardDatabase, test_db: StandardDatabase) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust(), empty_config())

    # foo db and pass does not exist
    foodb = ["--graphdb-username", "foo", "--graphdb-password", "test", "--graphdb-database", "foo"]
    system_db.delete_user("foo", ignore_missing=True)
    system_db.delete_database("foo", ignore_missing=True)
    access.connect(parse_args(foodb), timedelta(seconds=5), sleep_time=0.1)
    assert system_db.has_user("foo")
    assert system_db.has_database("foo")


def test_not_existing_and_default_root_account(
    local_client: ArangoClient, system_db: StandardDatabase, test_db: StandardDatabase
) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust(), empty_config())
    # foo db and pass does not exist
    foodb = ["--graphdb-username", "foo", "--graphdb-password", "bombproof", "--graphdb-database", "foo"]
    system_db.delete_user("foo", ignore_missing=True)
    system_db.delete_database("foo", ignore_missing=True)
    access.connect(parse_args(foodb), timedelta(seconds=5), sleep_time=0.1)

    # The default root account is used and a valid password is given -> also the root account uses this password
    changed_root = local_client.db(username="root", password="bombproof")
    # Rest the password to the default one, to reset the state before the test
    changed_root.replace_user("root", "", True)
