import asyncio
from datetime import timedelta

import pytest

from fixcore.db.lockdb import LockDB, LockAcquisitionError
from fixcore.types import Json


async def test_lock_db_access(lock_db: LockDB) -> None:
    secured_data: Json = dict(count=0)

    async def perform_action() -> None:
        async with lock_db.lock(
            "test_lock",
            get_lock=timedelta(seconds=5),
            lock_for=timedelta(seconds=1),
            retry_interval=timedelta(seconds=0.001),
        ):
            assert secured_data.get("access") is None
            secured_data["access"] = "test"
            secured_data["count"] += 1
            await asyncio.sleep(0.001)
            del secured_data["access"]

    tasks = [asyncio.create_task(perform_action()) for _ in range(10)]
    await asyncio.gather(*tasks)


async def test_lock_db_acquired_failed(lock_db: LockDB) -> None:
    async with lock_db.lock(
        "test_lock",
        get_lock=timedelta(seconds=5),
        lock_for=timedelta(seconds=5),
        retry_interval=timedelta(seconds=0.001),
    ):
        with pytest.raises(LockAcquisitionError):
            async with lock_db.lock(
                "test_lock",
                get_lock=timedelta(seconds=0.001),
                lock_for=timedelta(seconds=1),
                retry_interval=timedelta(seconds=0.001),
            ):
                pass
