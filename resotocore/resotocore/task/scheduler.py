import warnings
from datetime import datetime
from typing import Callable, Any, List

from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.job import Job
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from resotolib.utils import get_local_tzinfo


warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)


class Scheduler:
    def __init__(self) -> None:
        self.scheduler = AsyncIOScheduler(
            jobstores={"default": MemoryJobStore()},
            executors={"default": AsyncIOExecutor()},
            # coalesce: run once instead of many times if the job should be run more than once in succession
            # max_instances: allowed parallel instances for one job
            # misfire_grace_time: seconds after the designated runtime that the job is still allowed to be run
            job_defaults={"coalesce": True, "max_instances": 32, "misfire_grace_time": 3600},
            timezone=get_local_tzinfo(),
        )

    async def start(self) -> None:
        self.scheduler.start()

    async def stop(self) -> None:
        self.scheduler.remove_all_jobs()

    def cron(
        self, job_id: str, name: str, cron_string: str, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Job:
        trigger = CronTrigger.from_crontab(cron_string)
        return self.scheduler.add_job(func, trigger, args, kwargs, job_id, name)

    def at(self, job_id: str, name: str, dt: datetime, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Job:
        return self.scheduler.add_job(func, "date", args, kwargs, job_id, name, run_date=dt)

    def interval(
        self, job_id: str, name: str, every_second: int, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Job:
        return self.scheduler.add_job(func, "interval", args, kwargs, job_id, name, seconds=every_second)

    def list_jobs(self) -> List[Job]:
        return self.scheduler.get_jobs(jobstore="default")  # type: ignore
