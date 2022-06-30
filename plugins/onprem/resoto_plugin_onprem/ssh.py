import resotolib.logger
from collections import defaultdict
from paramiko import SSHClient
from .resources import OnpremInstance
from resotolib.baseresources import InstanceStatus

log = resotolib.logger.getLogger("resoto." + __name__)


instance_status_map = {
    "running": InstanceStatus.RUNNING,
}


def instance_from_ssh(
    hostname: str,
    port: int = 22,
    username: str = None,
    password: str = None,
    pkey: str = None,
    key_filename: str = None,
    auth_timeout: float = 10,
    timeout: float = 10,
    allow_agent: bool = True,
    look_for_keys: bool = True,
    passphrase: str = None,
):
    log.debug(f"Establishing SSH connection to {hostname}")
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(
        hostname,
        port=port,
        username=username,
        password=password,
        pkey=pkey,
        passphrase=passphrase,
        key_filename=key_filename,
        timeout=timeout,
        auth_timeout=auth_timeout,
        allow_agent=allow_agent,
        look_for_keys=look_for_keys,
    )
    meminfo = get_proc_meminfo(client)
    cpuinfo = get_proc_cpuinfo(client)
    netdev, ip4, ip6 = get_net_info(client)
    client.close()

    s = OnpremInstance(
        id=hostname,
        instance_cores=len(cpuinfo),
        instance_memory=round(meminfo.get("MemTotal", 0) / 1024**2),
        instance_status=instance_status_map.get("running", InstanceStatus.UNKNOWN),
        instance_type=cpuinfo.get("0", {}).get("model name"),
        network_device=netdev,
        network_ip4=ip4,
        network_ip6=ip6,
    )
    return s


def get_proc_meminfo(client: SSHClient):
    log.debug("Getting memory information")
    cmd = "cat /proc/meminfo"
    out, err = client_exec(client, cmd)
    if err:
        raise RuntimeError(f"Error while executing {cmd}: {err}")
    meminfo = {i[0].rstrip(":"): int(i[1]) for i in [line.split() for line in str(out).splitlines()]}
    return meminfo


def get_proc_cpuinfo(client: SSHClient):
    log.debug("Getting CPU information")
    cmd = "cat /proc/cpuinfo"
    out, err = client_exec(client, cmd)
    if err:
        raise RuntimeError(f"Error while executing {cmd}: {err}")
    cpuinfo = defaultdict(dict)
    num_core = "0"
    for line in str(out).splitlines():
        if len(line) == 0:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k == "processor":
            num_core = v
        else:
            cpuinfo[num_core][k] = v
    return dict(cpuinfo)


def get_net_info(client: SSHClient):
    log.debug("Getting network information")
    dst4 = "8.8.8.8"
    dst6 = "2001:4860:4860::8888"
    ip4 = None
    ip6 = None
    dev = None
    for dst in [dst4, dst6]:
        cmd = f"ip r g {dst}"
        out, err = client_exec(client, cmd)
        if err:
            log.error(f"Error while executing {cmd}: {err}")
            continue
        src = None
        for line in str(out).splitlines():
            line = line.strip()
            if line.startswith(dst) and "dev" in line and "src" in line:
                line = line.split()
                dev = line[line.index("dev") + 1]
                src = line[line.index("src") + 1]
                break
        if dev is None or src is None:
            raise RuntimeError("Unable to determine IP interface")
        cmd = f"ip a s dev {dev}"
        out, err = client_exec(client, cmd)
        if err:
            raise RuntimeError(f"Error while executing {cmd}: {err}")
        ip = None
        for line in str(out).splitlines():
            line = line.strip()
            if line.startswith("inet") and src in line:
                line = line.split()
                ip = line[1]
                break
        if ip is None:
            raise RuntimeError("Unable to determine IP address")
        if "." in ip:
            ip4 = ip
        elif ":" in ip:
            ip6 = ip
        else:
            raise RuntimeError(f"Unable to parse IP {ip}")
    return (dev, ip4, ip6)


def client_exec(client: SSHClient, command: str, timeout: float = None):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return (out, err)
