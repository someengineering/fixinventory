from datetime import timedelta

from arango.client import ArangoClient
from arango.database import StandardDatabase

from fixcore.analytics import NoEventSender
from fixcore.db.db_access import DbAccess
from fixcore.system_start import parse_args, empty_config
from fixcore.model.adjust_node import NoAdjust
from fixcore.ids import GraphName

import pytest


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


@pytest.mark.asyncio
async def test_delete_graph(test_db: StandardDatabase) -> None:
    db_access = DbAccess(test_db, NoEventSender(), NoAdjust(), empty_config())
    graph_name = GraphName("test_graph_delete")
    await db_access.create_graph(
        graph_name,
        validate_name=False,
    )
    assert db_access.graph_dbs.get(graph_name)
    await db_access.delete_graph(graph_name)
    assert db_access.graph_dbs.get(graph_name) is None
