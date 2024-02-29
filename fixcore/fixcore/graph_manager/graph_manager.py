import logging
import re
from datetime import timedelta
from typing import List, Optional, Tuple

from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.core_config import SnapshotsScheduleConfig, FixCoreSnapshotsConfigId, CoreConfig
from fixcore.db.db_access import DbAccess, GraphOperations
from fixcore.ids import TaskDescriptorId
from fixcore.model.typed_model import from_js
from fixcore.task import TaskHandler
from fixcore.task.task_description import Job, ExecuteCommand, TimeTrigger
from fixcore.util import Periodic

log = logging.getLogger(__name__)


class GraphManager(GraphOperations):
    def __init__(
        self,
        db_access: DbAccess,
        config: CoreConfig,
        config_handler: CoreConfigHandler,
        task_handler: TaskHandler,
    ) -> None:
        super().__init__(db_access)
        self.task_handler = task_handler
        self.config = config
        self.config_handler = config_handler
        self.snapshot_cleanup_worker: Optional[Periodic] = None

    async def __setup_cleanup_old_snapshots_worker(self, snapshots_config: SnapshotsScheduleConfig) -> None:
        if self.snapshot_cleanup_worker:
            await self.snapshot_cleanup_worker.stop()

        self.snapshot_cleanup_worker = Periodic(
            "snapshot_cleanup_worker", lambda: self._clean_outdated_snapshots(snapshots_config), timedelta(seconds=60)
        )
        await self.snapshot_cleanup_worker.start()

    async def _clean_outdated_snapshots(self, snapshots_config: SnapshotsScheduleConfig) -> None:
        # get all existing snapshots
        existing_snapshots = await self.list("snapshot-.*")

        snapshots_to_keep: List[Tuple[str, int]] = []
        for label, schedule in snapshots_config.snapshots.items():
            regex = rf"snapshot-\w+-{label}-.*"
            snapshots_to_keep.append((regex, schedule.retain))

        # delete all snapshots that are outdated
        for regex, retain in snapshots_to_keep:
            snapshots = [snapshot for snapshot in existing_snapshots if re.match(regex, snapshot)]
            snapshots.sort(reverse=True)
            for snapshot in snapshots[retain:]:
                await self.delete(snapshot)

    async def _on_config_updated(self, config_id: str) -> None:
        if config_id == FixCoreSnapshotsConfigId:
            job_prefix = "fix:snapshots:"
            # get the new config or use the default
            snapshots_config = SnapshotsScheduleConfig()
            try:
                new_config = await self.config_handler.config_handler.get_config(FixCoreSnapshotsConfigId)
                if new_config:
                    snapshots_config = from_js(new_config.config, SnapshotsScheduleConfig)
            except Exception as e:
                log.error(f"Can not parse snapshot schedule. Fall back to defaults. Reason: {e}", exc_info=e)

            # recreate the cleanup worker according to the new schedule
            await self.__setup_cleanup_old_snapshots_worker(snapshots_config)

            # cancel all existing snapshot jobs
            existing_jobs = [job for job in await self.task_handler.list_jobs() if job.id.startswith(job_prefix)]
            for job in existing_jobs:
                await self.task_handler.delete_job(job.id, force=True)

            # schedule new snapshot jobs for the current graph
            for label, schedule in snapshots_config.snapshots.items():
                job = Job(
                    uid=TaskDescriptorId(f"{job_prefix}{label}"),
                    command=ExecuteCommand(f"graph snapshot {label}"),
                    timeout=timedelta(minutes=5),
                    trigger=TimeTrigger(schedule.schedule),
                )

                await self.task_handler.add_job(job, force=True)

    async def start(self) -> None:
        await super().start()
        if not self.config.multi_tenant_setup and not self.config.no_scheduling:
            # initialize the snapshot schedule
            await self._on_config_updated(FixCoreSnapshotsConfigId)
            await self.__setup_cleanup_old_snapshots_worker(self.config.snapshots)
        # subscribe to config updates to update the snapshot schedule
        self.config_handler.add_callback(self._on_config_updated)

    async def stop(self) -> None:
        if self.snapshot_cleanup_worker:
            await self.snapshot_cleanup_worker.stop()
            self.snapshot_cleanup_worker = None
        await super().stop()
