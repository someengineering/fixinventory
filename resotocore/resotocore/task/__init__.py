from abc import ABC, abstractmethod
from typing import Optional, List

from resotocore.task.task_description import Job, RunningTask, Workflow


class TaskHandler(ABC):
    @abstractmethod
    async def list_workflows(self) -> List[Workflow]:
        pass

    @abstractmethod
    async def list_jobs(self) -> List[Job]:
        pass

    @abstractmethod
    async def add_job(self, job: Job) -> None:
        pass

    @abstractmethod
    async def delete_job(self, job_id: str) -> Optional[Job]:
        pass

    @abstractmethod
    async def start_task_by_descriptor_id(self, uid: str) -> Optional[RunningTask]:
        pass

    @abstractmethod
    async def running_tasks(self) -> List[RunningTask]:
        pass
