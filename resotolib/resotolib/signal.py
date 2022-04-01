import os
import time
import sys
import fcntl
import psutil
import threading
import subprocess
from resotolib.logging import log
from resotolib.event import dispatch_event, Event, EventType
from signal import signal, Signals, SIGTERM, SIGINT


parent_pid = None
initial_dir = os.getcwd()


def restart() -> None:
    python_args = []
    if not getattr(sys, "frozen", False):
        python_args = subprocess._args_from_interpreter_flags()
    args = python_args + sys.argv

    path_prefix = "." + os.pathsep
    python_path = os.environ.get("PYTHONPATH", "")
    if sys.path[0] == "" and not python_path.startswith(path_prefix):
        os.environ["PYTHONPATH"] = path_prefix + python_path

    kill_children(SIGTERM, ensure_death=True)

    try:
        open_max = os.sysconf("SC_OPEN_MAX")
    except AttributeError:
        open_max = 1024

    for fd in range(3, open_max):
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        except IOError:
            continue
        fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

    os.chdir(initial_dir)
    os.execv(sys.executable, [sys.executable] + args)


def delayed_exit(delay: int = 3) -> None:
    time.sleep(delay)
    os._exit(0)


def handler(sig, frame) -> None:
    """Handles Ctrl+c by letting the Collector() know to shut down"""
    current_pid = os.getpid()
    if current_pid == parent_pid:
        reason = f"Received shutdown signal {sig}"
        log.debug(f"Parent caught signal {sig} - dispatching shutdown event")
        # Dispatch shutdown event in parent process which also causes SIGTERM to be sent
        # to the process group and in turn causes the shutdown event in all child
        # processes.
        dispatch_event(
            Event(EventType.SHUTDOWN, {"reason": reason, "emergency": False})
        )
    else:
        reason = f"Received shutdown signal {sig} from parent process"
        log.debug(
            f"Child with PID {current_pid} shutting down"
            " - you might see exceptions from interrupted worker threads"
        )
        # Child's threads have 3s to shut down before the following thread will
        # shut them down hard.
        kt = threading.Thread(target=delayed_exit, name="shutdown")
        kt.start()
        # Dispatch shutdown event in child process
        dispatch_event(
            Event(EventType.SHUTDOWN, {"reason": reason, "emergency": False}),
            blocking=False,
        )
        sys.exit(0)


def initializer() -> None:
    signal(SIGINT, handler)
    signal(SIGTERM, handler)


def set_thread_name(thread_name: str = "resoto") -> None:
    threading.current_thread().name = thread_name


def emergency_shutdown(reason: str = "") -> None:
    log.fatal(f"EMERGENCY SHUTDOWN: {reason}")
    for p in psutil.Process().children(recursive=True):
        p.kill()
    psutil.Process().kill()


def kill_children(
    signal: Signals = SIGTERM, ensure_death: bool = False, timeout: int = 3
) -> None:
    procs = psutil.Process().children(recursive=True)
    num_children = len(procs)
    if num_children == 0:
        return
    elif num_children == 1:
        log_suffix = ""
    else:
        log_suffix = "ren"

    log.debug(f"Sending {signal.name} to {num_children} child{log_suffix}.")
    for p in procs:
        if signal == SIGTERM:
            p.terminate()
        else:
            p.send_signal(signal)

    if ensure_death:
        _, alive = psutil.wait_procs(procs, timeout=timeout)
        for p in alive:
            log.debug(f"Child with PID {p.pid} is still alive, sending SIGKILL")
            p.kill()
