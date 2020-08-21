import threading
import re
import cloudkeeper.logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError
from apscheduler.job import Job
from typing import Iterable
from cloudkeeper.cli import register_cli_action, cli_event_handler
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener

log = cloudkeeper.logging.getLogger(__name__)


class Scheduler(threading.Thread):
    def __init__(self, gc) -> None:
        super().__init__()
        self.name = 'scheduler'
        self.exit = threading.Event()
        self.gc = gc
        self._sched = BackgroundScheduler(daemon=True)
        self._event_prefixes = tuple((f'{e.name.lower()}:' for e in EventType))
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self):
        self._sched.start()
        if ArgumentParser.args.scheduler_config:
            self.read_config(ArgumentParser.args.scheduler_config)
        self.exit.wait()

    def shutdown(self, event: Event):
        log.debug(f'Received request to shutdown scheduler {event.event_type}')
        if self._sched.running:
            self._sched.shutdown(wait=False)
        self.exit.set()

    def read_config(self, config_file: str) -> None:
        log.debug(f'Reading scheduler configuration file {config_file}')
        try:
            with open(config_file, 'r') as fp:
                for line in fp:
                    line = line.strip()
                    if not line.startswith('#') and len(line) > 0:
                        self.add_job(line)
        except Exception:
            log.exception(f'Failed to read scheduler configuration file {config_file}')

    def scheduled_command(self, command):
        log.debug(f'Running scheduled command {command}')
        return cli_event_handler(command, graph=self.gc.graph)

    def add_job(self, args: str) -> Job:
        args = args.strip()
        cron = re.split(r'\s+', args, 5)
        if len(cron) != 6:
            raise ValueError(f'Invalid job {args}')
        minute, hour, day, month, day_of_week, command = cron
        if str(command).startswith(self._event_prefixes):
            event, cmd = command.split(':', 1)
            log.debug(f'Scheduling to register command "{cmd}" for event {event} at minute={minute}, hour={hour}, day={day}, month={month}, day_of_week={day_of_week}')
            job = self._sched.add_job(register_cli_action, 'cron', args=[command, True], minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
        else:
            log.debug(f'Scheduling command "{command}" at minute={minute}, hour={hour}, day={day}, month={month}, day_of_week={day_of_week}')
            job = self._sched.add_job(self.scheduled_command, 'cron', args=[command], minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
        return job

    def remove_job(self, job_id: str) -> bool:
        try:
            self._sched.remove_job(job_id)
        except JobLookupError:
            log.error(f"Couldn't find job with id {job_id}")
        else:
            return True
        return False

    def get_jobs(self) -> Iterable:
        for job in self._sched.get_jobs():
            if isinstance(job.trigger, CronTrigger):
                trigger_map = {}
                for field in job.trigger.fields:
                    trigger_map[field.name] = str(field)
                cron_line = (f"{job.id}: {trigger_map.get('minute')} {trigger_map.get('hour')} {trigger_map.get('day')}"
                             f" {trigger_map.get('month')} {trigger_map.get('day_of_week')} {job.args[0]}")
                yield cron_line

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--scheduler-config', help='Scheduler config in crontab format', default=None, dest='scheduler_config', type=str)
