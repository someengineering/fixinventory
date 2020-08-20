import os
import time
import sys
import threading
import multiprocessing
import setproctitle
import cloudkeeper.logging as logging
from cloudkeeper.utils import get_child_process_info
from ctypes import CDLL
from signal import signal, Signals, SIGKILL, SIGTERM, SIGINT, SIGUSR1
from cloudkeeper.event import dispatch_event, Event, EventType


PR_SET_PDEATHSIG = 1
PR_SET_NAME = 15
log = logging.getLogger('cloudkeeper.' + __name__)
parent_pid = None


def delayed_exit(delay: int = 3) -> None:
    time.sleep(delay)
    os._exit(0)


def handler(sig, frame) -> None:
    """Handles Ctrl+c by letting the Collector() know to shut down"""
    current_pid = os.getpid()
    if current_pid == parent_pid:
        if sig != SIGUSR1:
            reason = f'Received shutdown signal {sig}'
            log.debug(f'Parent caught signal {sig} - dispatching shutdown event')
            # Dispatch shutdown event in parent process which also causes SIGUSR1 to be sent to
            # the process group and in turn causes the shutdown event in all child processes.
            dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}))
        else:
            log.debug('Parent received SIGUSR1 and ignoring it')
    else:
        if sig != SIGUSR1:
            reason = f'Received unexpected shutdown signal {sig} of unknown origin - OOM killer?'
            log.error(reason)
        else:
            reason = f'Received shutdown signal {sig} from parent process'
        log.debug(f"Shutting down child process {current_pid} - you might see exceptions from interrupted worker threads")
        # Child's threads have 3s to shut down before the following thread will shut them down hard.
        kt = threading.Thread(target=delayed_exit, name='shutdown')
        kt.start()
        # Dispatch shutdown event in child process
        dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': False}), blocking=False)
        sys.exit(0)


def initializer() -> None:
    signal(SIGINT, handler)
    signal(SIGTERM, handler)
    signal(SIGUSR1, handler)


def on_parent_exit(signal: Signals = SIGKILL) -> bool:
    log.debug(f"Setting PR_SET_PDEATHSIG to {signal.name} for current process")
    try:
        libc = CDLL('libc.so.6')
        res = libc.prctl(PR_SET_PDEATHSIG, signal)
    except Exception:
        log.exception("An error occured when trying to set PR_SET_PDEATHSIG")
    else:
        return res == 0
    return False


def set_proc_name(proc_name: str = 'cloudkeeper') -> None:
    multiprocessing.current_process().name = proc_name
    libc = CDLL('libc.so.6')
    proc_name = bytes(proc_name, 'utf-8')
    libc.prctl(PR_SET_NAME, proc_name, None, None, None)


def set_proc_title(proc_name: str = 'cloudkeeper') -> None:
    setproctitle.setproctitle(proc_name)


def set_thread_name(thread_name: str = 'cloudkeeper') -> None:
    threading.current_thread().name = thread_name


def kill_children(signal: Signals = SIGKILL, pid: int = None) -> None:
    if pid is None:
        pid = parent_pid
    if pid is None:
        pid = os.getpid()

    for child_pid in get_child_process_info(pid).keys():
        log.debug(f'Sending signal {signal.name} to child with pid {child_pid}')
        os.kill(child_pid, signal)
