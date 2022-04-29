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

    try:
        close_fds()
    except Exception:
        log.exception("Failed to FD_CLOEXEC all file descriptors")

    kill_children(SIGTERM, ensure_death=True)

    os.chdir(initial_dir)
    os.execv(sys.executable, [sys.executable] + args)
    log.fatal("Failed to restart - exiting")
    os._exit(1)


def delayed_exit(delay: int = 3) -> None:
    time.sleep(delay)
    os._exit(0)


def close_fds() -> None:
    open_max = 0
    if sys.platform == "linux":
        try:
            for fd in os.listdir(os.path.join("/proc", str(os.getpid()), "fd")):
                if not fd.isnumeric():
                    continue
                fd = int(fd)
                if fd > open_max:
                    open_max = fd
            # We have a race between reading /proc and setting
            # FD_CLOEXEC so we're adding some safety margin in
            # case some thread opened new fds in between.
            open_max += 1024
        except Exception:
            open_max = 1024
    else:
        try:
            # This can return really big numbers so it's better to have
            # an OS specific implementation like the Linux one above.
            open_max = os.sysconf("SC_OPEN_MAX")
        except AttributeError:
            open_max = 1024

    if open_max > 65536:
        # SC_OPEN_MAX can be 1 billion or more. In that case we log a warning
        # but still try to close all possible file descriptors rather than leaking
        # them. This can delay restarting by several minutes.
        log.warning(f"High SC_OPEN_MAX: {open_max}, restart will take longer")
    for fd in range(3, open_max):
        fd_cloexec(fd)


def fd_cloexec(fd: int) -> None:
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    except IOError:
        return
    fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)


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
