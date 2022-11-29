import gc
import os
import re
import time
import sys
from typing import Optional, Dict, List

import psutil
import threading
import subprocess
from resotolib.logger import log
from resotolib.event import dispatch_event, Event, EventType
from signal import signal, Signals, SIGTERM, SIGINT

from resotolib.utils import iec_size_format

try:
    import resource
    import fcntl
except ImportError:
    pass

try:
    from psutil import cpu_count
except ImportError:
    from os import cpu_count


parent_pid: Optional[int] = None
initial_dir: str = os.getcwd()


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


def close_fds(safety_margin: int = 1024) -> None:
    """Set FD_CLOEXEC on all file descriptors except stdin, stdout, stderr

    Since there is a race between determining the max number of fds to close
    and actually closing them we are adding a safety margin.
    """
    if sys.platform == "win32":
        return

    open_fds = [f.fd for f in psutil.Process().open_files()]
    if len(open_fds) == 0:
        return

    num_open = max(open_fds)

    try:
        sc_open_max = os.sysconf("SC_OPEN_MAX")
    except AttributeError:
        sc_open_max = 1024

    num_close = min(num_open + safety_margin, sc_open_max)

    for fd in range(3, num_close):
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
        dispatch_event(Event(EventType.SHUTDOWN, {"reason": reason, "emergency": False}))
    else:
        reason = f"Received shutdown signal {sig} from parent process"
        log.debug(
            f"Child with PID {current_pid} shutting down" " - you might see exceptions from interrupted worker threads"
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


def kill_children(signal: Signals = SIGTERM, ensure_death: bool = False, timeout: int = 3) -> None:
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


def increase_limits() -> None:
    if sys.platform != "linux":
        return
    for limit_name in ("RLIMIT_NOFILE", "RLIMIT_NPROC"):
        soft_limit, hard_limit = resource.getrlimit(getattr(resource, limit_name))
        log.debug(f"Current {limit_name} soft: {soft_limit} hard: {hard_limit}")
        try:
            if soft_limit < hard_limit:
                log.debug(f"Increasing {limit_name} {soft_limit} -> {hard_limit}")
                resource.setrlimit(getattr(resource, limit_name), (hard_limit, hard_limit))
        except (ValueError):
            log.error(f"Failed to increase {limit_name} {soft_limit} -> {hard_limit}")


def num_default_threads(num_min_threads: int = 4) -> int:
    count = num_min_threads
    try:
        # try to get the number of usable cores first
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        try:
            count = cpu_count()
        except Exception:
            pass
    if not isinstance(count, int):
        count = num_min_threads
    return max(count, num_min_threads)


def get_process_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    process_info = {}
    try:
        with open(os.path.join(proc, str(pid), "status"), "r") as status:
            for line in status:
                k, v = line.split(":", 1)
                v = re.sub("[ \t]+", " ", v.strip())
                process_info[k.lower()] = v
        for limit_name in ("NOFILE", "NPROC"):
            process_info[f"RLIMIT_{limit_name}".lower()] = resource.getrlimit(getattr(resource, f"RLIMIT_{limit_name}"))
    except (PermissionError, FileNotFoundError):
        pass
    return process_info


def get_file_descriptor_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    pid = str(pid)
    file_descriptor_info = {}
    try:
        for entry in os.listdir(os.path.join(proc, pid, "fd")):
            entry_path = os.path.join(proc, pid, "fd", entry)
            if os.path.islink(entry_path):
                file_descriptor_info[entry] = {}
                target = os.readlink(entry_path)
                file_descriptor_info[entry]["target"] = target
    except (PermissionError, FileNotFoundError):
        pass
    return file_descriptor_info


def get_pid_list(proc: str = "/proc") -> List:
    if sys.platform != "linux":
        return []
    pids = []
    for entry in os.listdir(proc):
        try:
            if os.path.isdir(os.path.join(proc, entry)) and entry.isdigit():
                pids.append(int(entry))
        except (PermissionError, FileNotFoundError):
            pass
    return pids


def get_all_process_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    process_info = {}
    process_info["parent"] = get_process_info(pid)
    process_info["parent"]["file_descriptors"] = get_file_descriptor_info(pid, proc)
    process_info["parent"]["num_file_descriptors"] = len(process_info["parent"]["file_descriptors"])
    process_info["children"] = get_child_process_info(pid, proc)
    for pid in process_info["children"]:
        process_info["children"][pid]["file_descriptors"] = get_file_descriptor_info(pid, proc)
        process_info["children"][pid]["num_file_descriptors"] = len(process_info["children"][pid]["file_descriptors"])
    return process_info


def get_child_process_info(pid: int = None, proc: str = "/proc") -> Dict:
    if sys.platform != "linux":
        return {}
    if pid is None:
        pid = os.getpid()
    child_process_info = {}
    for pid in get_pid_list(proc):
        process_info = get_process_info(pid)
        if process_info.get("ppid") == str(pid):
            child_process_info[pid] = dict(process_info)
    return child_process_info


def get_stats() -> Dict:
    try:
        stats = {
            "active_threads": threading.active_count(),
            "thread_names": [thread.name for thread in threading.enumerate()],
            "garbage_collector": gc.get_stats(),
            "process": get_all_process_info(),
        }
        if sys.platform == "linux":
            stats.update(
                {
                    "maxrss_parent_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                    "maxrss_children_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024,
                }
            )
        else:
            stats.update({"maxrss_parent_bytes": 0, "maxrss_children_bytes": 0})
        stats["maxrss_total_bytes"] = stats["maxrss_parent_bytes"] + stats["maxrss_children_bytes"]
        num_fds_parent = stats["process"].get("parent", {}).get("num_file_descriptors", 0)
        num_fds_children = sum([v["num_file_descriptors"] for v in stats["process"].get("children", {}).values()])
        stats.update(
            {
                "maxrss_parent_human_readable": iec_size_format(stats["maxrss_parent_bytes"]),
                "maxrss_children_human_readable": iec_size_format(stats["maxrss_children_bytes"]),
                "maxrss_total_human_readable": iec_size_format(stats["maxrss_total_bytes"]),
                "num_fds_parent": num_fds_parent,
                "num_fds_children": num_fds_children,
                "num_fds_total": num_fds_parent + num_fds_children,
            }
        )
    except Exception:
        log.exception("Error while trying to get stats")
        return {}
    else:
        return stats


def log_stats(graph=None, garbage_collector_stats: bool = False) -> None:
    stats = get_stats()
    try:
        log.debug(
            f"Stats: max rss parent: {stats['maxrss_parent_human_readable']},"
            f" children: {stats['maxrss_children_human_readable']},"
            f" fds: {stats['num_fds_total']}/"
            f"{stats['process'].get('parent', {}).get('rlimit_nofile', [0])[0]}"
            f" active threads {stats['active_threads']}:"
            f" {', '.join([thread for thread in stats['thread_names']])}"
        )
        if graph:
            log.debug(f"Graph Stats: {stats['graph_size_human_readable']}")
        if garbage_collector_stats:
            gc_stats = " | ".join(
                [
                    (
                        f"Gen {i}: collections {data.get('collections')}, "
                        f"collected {data.get('collected')}, "
                        f"uncollectable {data.get('uncollectable')}"
                    )
                    for i, data in enumerate(stats["garbage_collector"])
                ]
            )
            log.debug(f"Garbage Collector Stats: {gc_stats}")
    except Exception:
        log.exception("Error while trying to log stats")
