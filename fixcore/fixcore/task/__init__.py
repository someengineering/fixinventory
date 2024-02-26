from abc import ABC, abstractmethod
from typing import Optional, List

from attr import define

from fixcore.task.task_description import Job, RunningTask, Workflow
from fixcore.ids import TaskDescriptorId, TaskId


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
    async def add_job(self, job: Job, force: bool = False) -> None:
        """
        Add a job to the task handler. If force is True, the job name validations and other checks will be ignored.
        Used for system jobs that are added by fix itself.

        Make sure to never use the force parameter if the job is added by the user.
        """

    @abstractmethod
    async def delete_job(self, job_id: str, force: bool = False) -> Optional[Job]:
        """
        Delete a job from the task handler. If force is True, the job name validations
        and other checks will be ignored.
        Used for system jobs that are added by fix itself.

        Make sure to never use the force parameter if the job is added by the user.
        """

    @abstractmethod
    async def start_task_by_descriptor_id(self, uid: TaskDescriptorId) -> Optional[RunningTaskInfo]:
        pass

    @abstractmethod
    async def running_tasks(self) -> List[RunningTask]:
        pass

    @abstractmethod
    async def stop_task(self, uid: TaskId) -> Optional[RunningTask]:
        pass
