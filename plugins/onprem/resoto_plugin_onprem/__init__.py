from resotolib.baseresources import BaseResource
import resotolib.logger
import socket
import multiprocessing
import resotolib.proc
from concurrent import futures
from resotolib.baseplugin import BaseCollectorPlugin
from argparse import Namespace
from resotolib.args import ArgumentParser
from resotolib.config import Config, RunningConfig
from .resources import OnpremLocation, OnpremRegion, OnpremNetwork
from .ssh import instance_from_ssh
from .config import OnpremConfig
from paramiko import ssh_exception
from typing import Dict

log = resotolib.logger.getLogger("resoto." + __name__)


class OnpremCollectorPlugin(BaseCollectorPlugin):
    cloud = "onprem"

    def collect(self) -> None:
        log.debug("plugin: collecting on-prem resources")

        if len(Config.onprem.server) == 0:
            log.debug("No On-Prem servers specified")
            return

        default_location = OnpremLocation(id=Config.onprem.location)
        self.graph.add_resource(self.graph.root, default_location)

        default_region = OnpremRegion(id=Config.onprem.region)
        self.graph.add_resource(default_location, default_region)

        servers = []
        for server in Config.onprem.server:
            location = region = network = None
            srv = {}
            if "%" in server:
                server_location, server = server.split("%", 1)
                location = self.graph.search_first_all({"id": server_location, "kind": "onprem_location"})
                if location is None:
                    location = OnpremLocation(id=server_location, tags={})
                    self.graph.add_resource(self.graph.root, location)
                    srv.update({"location": location})
                log.debug(f"Location for {server} is {location.rtdname}")
            if "%" in server:
                server_region, server = server.split("%", 1)
                region = self.graph.search_first_all({"id": server_region, "kind": "onprem_region"})
                if region is None:
                    region = OnpremRegion(id=server_region, tags={})
                    self.graph.add_resource(location, region)
                    srv.update({"region": region})
                log.debug(f"Region for {server} is {region.rtdname}")
            if "%" in server:
                server_network, server = server.split("%", 1)
                network = self.graph.search_first_all({"id": server_network, "kind": "onprem_network"})
                if network is None:
                    network = OnpremNetwork(id=server_network, tags={})
                    self.graph.add_resource(region, network)
                    srv.update({"network": network})
                log.debug(f"Network for {server} is {network.rtdname}")
            srv.update({"hostname": server})
            servers.append(srv)

        max_workers = len(servers) if len(servers) < Config.onprem.pool_size else Config.onprem.pool_size
        pool_args = {"max_workers": max_workers}
        if Config.onprem.fork_process:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.proc.initializer
            pool_executor = futures.ProcessPoolExecutor
            collect_args = {
                "args": ArgumentParser.args,
                "running_config": Config.running_config,
            }
        else:
            pool_executor = futures.ThreadPoolExecutor
            collect_args = {}

        with pool_executor(**pool_args) as executor:
            wait_for = [
                executor.submit(
                    collect_server,
                    srv,
                    **collect_args,
                )
                for srv in servers
            ]
            for future in futures.as_completed(wait_for):
                (src, s) = future.result()
                if src is None:
                    src = default_region
                if not isinstance(src, BaseResource) or not isinstance(s, BaseResource):
                    log.error(f"Skipping invalid server {type(s)}")
                    continue
                self.graph.add_resource(src, s)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(OnpremConfig)


def collect_server(srv: Dict, args: Namespace = None, running_config: RunningConfig = None) -> Dict:
    if args is not None:
        ArgumentParser.args = args
    if running_config is not None:
        Config.running_config.apply(running_config)

    hostname: str = srv.get("hostname")
    username = None
    port = 22
    if "@" in hostname:
        username, hostname = hostname.split("@", 1)
    if ":" in hostname:
        hostname, port = hostname.split(":", 1)

    collector_name = f"onprem_{hostname}"
    resotolib.proc.set_thread_name(collector_name)
    try:
        s = instance_from_ssh(
            hostname,
            username=username,
            port=port,
            key_filename=Config.onprem.ssh_key,
            passphrase=Config.onprem.ssh_key_pass,
        )
        src = srv.get("network", srv.get("region", srv.get("location", None)))
    except (socket.timeout, ssh_exception.PasswordRequiredException):
        log.exception(f"Failed to collect {hostname}")
    else:
        log.debug(f"onprem: collected {s.rtdname}")
        return (src, s)
