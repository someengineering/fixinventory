from abc import ABC, abstractmethod

from core.task.task_description import Job


class JobHandler(ABC):
    @abstractmethod
    def list_jobs(self) -> list[Job]:
        pass

    @abstractmethod
    def add_job(self, job: Job) -> None:
        pass

    @abstractmethod
    def delete_job(self, job: Job) -> None:
        pass
