from typing import List, Optional, Dict

from fixcore.task import TaskHandler, RunningTaskInfo
from fixcore.task.task_description import RunningTask, Job, Workflow
from fixcore.ids import TaskDescriptorId, TaskId
from fixcore.util import first


class InMemJobHandler(TaskHandler):
    def __init__(self) -> None:
        self.jobs: List[Job] = []
        self.started_tasks: List[TaskDescriptorId] = []

    async def stop_task(self, uid: TaskId) -> Optional[RunningTask]:
        return None

    async def list_jobs(self) -> List[Job]:
        return self.jobs

    async def list_workflows(self) -> List[Workflow]:
        return []

    async def add_job(
        self,
        job: Job,
        force: bool = False,
    ) -> None:
        self.jobs.append(job)

    async def delete_job(self, job_id: str, force: bool = False) -> Optional[Job]:
        job: Optional[Job] = first(lambda j: j.id == job_id, self.jobs)
        if job:
            self.jobs.remove(job)
            return job
        else:
            return None

    async def parse_job_line(
        self, source: str, line: str, env: Optional[Dict[str, str]] = None, mutable: bool = True
    ) -> Job:
        raise NotImplementedError()

    async def start_task_by_descriptor_id(self, uid: TaskDescriptorId) -> Optional[RunningTaskInfo]:
        self.started_tasks.append(uid)
        return None

    async def running_tasks(self) -> List[RunningTask]:
        raise NotImplementedError()
