import os
import time
import sys
import psutil
import threading
import cloudkeeper.logging
from cloudkeeper.event import dispatch_event, Event, EventType
from signal import signal, Signals, SIGTERM, SIGINT


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)
parent_pid = None


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
            (
                f"Child with PID {current_pid} shutting down"
                " - you might see exceptions from interrupted worker threads"
            )
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


def set_thread_name(thread_name: str = "cloudkeeper") -> None:
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
