from abc import ABC, abstractmethod
from typing import Optional, List

from attr import define

from resotocore.task.task_description import Job, RunningTask, Workflow
from resotocore.ids import TaskDescriptorId


@define(frozen=True)
class RunningTaskInfo:
    running_task: RunningTask
    scheduled_next: bool = False


class TaskHandler(ABC):
    @abstractmethod
    async def list_workflows(self) -> List[Workflow]:
        pass

    @abstractmethod
    async def list_jobs(self) -> List[Job]:
        pass

    @abstractmethod
    async def add_job(self, job: Job, validate_name: bool = True) -> None:
        """
        Add a job to the task handler. If validate_name is True, the name of the job will be validated and exception
        will be thrown in case the job name contains invalid characters.

        Make sure to always validate the name if the job is added by the user.
        """

    @abstractmethod
    async def delete_job(self, job_id: str) -> Optional[Job]:
        pass

    @abstractmethod
    async def start_task_by_descriptor_id(self, uid: TaskDescriptorId) -> Optional[RunningTaskInfo]:
        pass

    @abstractmethod
    async def running_tasks(self) -> List[RunningTask]:
        pass
