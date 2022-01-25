from datetime import timedelta

import pytest
from arango import ArangoClient
from arango.database import StandardDatabase

from core.analytics import NoEventSender
from core.db.db_access import DbAccess
from core.dependencies import parse_args
from core.model.adjust_node import NoAdjust

# noinspection PyUnresolvedReferences
from tests.core.db.graphdb_test import test_db, system_db


def test_already_existing(test_db: StandardDatabase) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust())

    # test db and user already exist
    testdb = ["--graphdb-username", "test", "--graphdb-password", "test", "--graphdb-database", "test"]
    access.connect(parse_args(testdb), timedelta(seconds=0.01), sleep_time=0.01)


def test_not_existing(system_db: StandardDatabase, test_db: StandardDatabase) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust())

    # foo db and pass does not exist
    foodb = ["--graphdb-username", "foo", "--graphdb-password", "test", "--graphdb-database", "foo"]
    system_db.delete_user("foo", ignore_missing=True)
    system_db.delete_database("foo", ignore_missing=True)
    access.connect(parse_args(foodb), timedelta(seconds=5), sleep_time=0.1)
    assert system_db.has_user("foo")
    assert system_db.has_database("foo")

    # accessing the foodb with wrong password fails
    foodb_wrong = ["--graphdb-username", "foo", "--graphdb-password", "bla", "--graphdb-database", "foo"]
    with pytest.raises(SystemExit):
        access.connect(parse_args(foodb_wrong), timedelta(seconds=0.1), sleep_time=0.1)


def test_not_existing_and_default_root_account(system_db: StandardDatabase, test_db: StandardDatabase) -> None:
    access = DbAccess(test_db, NoEventSender(), NoAdjust())
    # foo db and pass does not exist
    foodb = ["--graphdb-username", "foo", "--graphdb-password", "bombproof", "--graphdb-database", "foo"]
    system_db.delete_user("foo", ignore_missing=True)
    system_db.delete_database("foo", ignore_missing=True)
    access.connect(parse_args(foodb), timedelta(seconds=5), sleep_time=0.1)

    # The default root account is used and a valid password is given -> also the root account uses this password
    changed_root = ArangoClient(hosts="http://localhost:8529").db(username="root", password="bombproof")
    # Rest the password to the default one, to reset the state before the test
    changed_root.replace_user("root", "", True)
