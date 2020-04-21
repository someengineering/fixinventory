import threading
import logging
import re
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from cloudkeeper.cli import register_cli_action, cli_event_handler
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger(__name__)


class Scheduler(threading.Thread):
    def __init__(self, gc) -> None:
        super().__init__()
        self.name = 'scheduler'
        self.exit = threading.Event()
        self.gc = gc
        self._sched = BackgroundScheduler(daemon=True)
        self._event_prefix = tuple((e.name.lower() for e in EventType))
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self):
        self._sched.start()
        if ArgumentParser.args.scheduler_conf:
            self.read_config(ArgumentParser.args.scheduler_conf)
        self.exit.wait()

    def shutdown(self, event: Event):
        log.debug(f'Received request to shutdown scheduler {event.event_type}')
        self._sched.shutdown()
        self.exit.set()

    def read_config(self, config_file: str) -> None:
        pass

    def scheduled_command(self, command):
        log.debug(f'Running scheduled command {command}')
        return cli_event_handler(command, graph=self.gc.graph)

    def add_job(self, args: str) -> None:
        cron = re.split(r'\s+', args, 5)
        if len(cron) != 6:
            raise ValueError(f'Invalid job {args}')
        minute, hour, day, month, day_of_week, command = cron
        if str(command).startswith(self._event_prefix):
            event, cmd = command.split(':', 1)
            log.debug(f'Scheduling to register command "{cmd}" for event {event} at minute={minute}, hour={hour}, day={day}, month={month}, day_of_week={day_of_week}')
            self._sched.add_job(register_cli_action, 'cron', args=[command, True], minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
        else:
            log.debug(f'Scheduling command "{command}" at minute={minute}, hour={hour}, day={day}, month={month}, day_of_week={day_of_week}')
            self._sched.add_job(self.scheduled_command, 'cron', args=[command], minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)

    def get_jobs(self) -> None:
        for job in self._sched.get_jobs():
            if isinstance(job.trigger, CronTrigger):
                trigger_map = {}
                for field in job.trigger.fields:
                    trigger_map[field.name] = str(field)
                yield f"{trigger_map.get('minute')} {trigger_map.get('hour')} {trigger_map.get('day')} {trigger_map.get('month')} {trigger_map.get('day_of_week')} {job.args[0]}"

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--scheduler-conf', help='Scheduler Config', default=None, dest='scheduler_conf', type=str)
