from abc import ABC, abstractmethod

from typing import Optional

from core.task.task_description import Job


class JobHandler(ABC):
    @abstractmethod
    async def list_jobs(self) -> list[Job]:
        pass

    @abstractmethod
    async def add_job(self, job: Job) -> None:
        pass

    @abstractmethod
    async def delete_job(self, job_id: str) -> Optional[Job]:
        pass

    @abstractmethod
    async def parse_job_line(self, source: str, line: str, mutable: bool = True) -> Job:
        pass
