from resotolib.baseresources import BaseResource
import resotolib.logging
import socket
import multiprocessing
import resotolib.signal
from concurrent import futures
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.args import ArgumentParser
from .resources import OnpremLocation, OnpremRegion, OnpremNetwork
from .ssh import instance_from_ssh
from paramiko import ssh_exception
from typing import Dict

log = resotolib.logging.getLogger("cloudkeeper." + __name__)


class OnpremCollectorPlugin(BaseCollectorPlugin):
    cloud = "onprem"

    def collect(self) -> None:
        log.debug("plugin: collecting on-prem resources")

        if len(ArgumentParser.args.onprem_server) == 0:
            log.debug("No On-Prem servers specified")
            return

        default_location = OnpremLocation(ArgumentParser.args.onprem_location)
        self.graph.add_resource(self.graph.root, default_location)

        default_region = OnpremRegion(ArgumentParser.args.onprem_region)
        self.graph.add_resource(default_location, default_region)

        servers = []
        for server in ArgumentParser.args.onprem_server:
            location = region = network = None
            srv = {}
            if "%" in server:
                server_location, server = server.split("%", 1)
                location = self.graph.search_first_all(
                    {"id": server_location, "kind": "onprem_location"}
                )
                if location is None:
                    location = OnpremLocation(server_location, {})
                    self.graph.add_resource(self.graph.root, location)
                    srv.update({"location": location})
                log.debug(f"Location for {server} is {location.rtdname}")
            if "%" in server:
                server_region, server = server.split("%", 1)
                region = self.graph.search_first_all(
                    {"id": server_region, "kind": "onprem_region"}
                )
                if region is None:
                    region = OnpremRegion(server_region, {})
                    self.graph.add_resource(location, region)
                    srv.update({"region": region})
                log.debug(f"Region for {server} is {region.rtdname}")
            if "%" in server:
                server_network, server = server.split("%", 1)
                network = self.graph.search_first_all(
                    {"id": server_network, "kind": "onprem_network"}
                )
                if network is None:
                    network = OnpremNetwork(server_network, {})
                    self.graph.add_resource(region, network)
                    srv.update({"network": network})
                log.debug(f"Network for {server} is {network.rtdname}")
            srv.update({"hostname": server})
            servers.append(srv)

        max_workers = (
            len(servers)
            if len(servers) < ArgumentParser.args.onprem_pool_size
            else ArgumentParser.args.onprem_pool_size
        )
        pool_args = {"max_workers": max_workers}
        if ArgumentParser.args.onprem_fork:
            pool_args["mp_context"] = multiprocessing.get_context("spawn")
            pool_args["initializer"] = resotolib.signal.initializer
            pool_executor = futures.ProcessPoolExecutor
            collect_args = {"args": ArgumentParser.args}
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
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--onprem-location",
            help="On-Prem default location",
            dest="onprem_location",
            type=str,
            default="Default location",
        )
        arg_parser.add_argument(
            "--onprem-region",
            help="On-Prem default region",
            dest="onprem_region",
            type=str,
            default="Default region",
        )
        arg_parser.add_argument(
            "--onprem-ssh-user",
            help="On-Prem SSH User",
            dest="onprem_ssh_user",
            type=str,
            default="root",
        )
        arg_parser.add_argument(
            "--onprem-ssh-key",
            help="On-Prem SSH Key",
            dest="onprem_ssh_key",
            type=str,
            default=None,
        )
        arg_parser.add_argument(
            "--onprem-ssh-key-pass",
            help="On-Prem SSH Key Passphrase",
            dest="onprem_ssh_key_pass",
            type=str,
            default=None,
        )
        arg_parser.add_argument(
            "--onprem-server",
            help="On-Prem Server",
            dest="onprem_server",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--onprem-pool-size",
            help="On-Prem Thread Pool Size (default: 5)",
            dest="onprem_pool_size",
            default=5,
            type=int,
        )
        arg_parser.add_argument(
            "--onprem-fork",
            help="On-Prem use forked process instead of threads (default: False)",
            dest="onprem_fork",
            action="store_true",
        )


def collect_server(srv: Dict, args=None) -> Dict:
    if args is not None:
        ArgumentParser.args = args
    hostname: str = srv.get("hostname")
    username = None
    port = 22
    if "@" in hostname:
        username, hostname = hostname.split("@", 1)
    if ":" in hostname:
        hostname, port = hostname.split(":", 1)

    collector_name = f"onprem_{hostname}"
    resotolib.signal.set_thread_name(collector_name)
    try:
        s = instance_from_ssh(
            hostname,
            username=username,
            port=port,
            key_filename=ArgumentParser.args.onprem_ssh_key,
            passphrase=ArgumentParser.args.onprem_ssh_key_pass,
        )
        src = srv.get("network", srv.get("region", srv.get("location", None)))
    except (socket.timeout, ssh_exception.PasswordRequiredException):
        log.exception(f"Failed to collect {hostname}")
    else:
        log.debug(f"onprem: collected {s.rtdname}")
        return (src, s)
