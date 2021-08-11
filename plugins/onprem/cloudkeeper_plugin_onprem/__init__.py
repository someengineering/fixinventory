import cloudkeeper.logging
import socket
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.args import ArgumentParser
from .resources import OnpremLocation, OnpremRegion, OnpremNetwork
from .ssh import instance_from_ssh
from paramiko import ssh_exception

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class OnpremCollectorPlugin(BaseCollectorPlugin):
    cloud = "onprem"

    def collect(self) -> None:
        log.debug("plugin: collecting on-prem resources")

        default_location = OnpremLocation("Default location", {})
        self.graph.add_resource(self.graph.root, default_location)

        default_region = OnpremRegion("Default region", {})
        self.graph.add_resource(default_location, default_region)

        servers = []
        if len(ArgumentParser.args.onprem_server) > 0:
            for server in ArgumentParser.args.onprem_server:
                location = region = network = None
                srv = {}
                if "%" in server:
                    server_location, server = server.split("%", 1)
                    location = self.graph.search_first_all(
                        {"id": server_location, "resource_type": "onprem_location"}
                    )
                    if location is None:
                        location = OnpremLocation(server_location, {})
                        self.graph.add_resource(self.graph.root, location)
                        srv.update({"location": location})
                    log.debug(f"Location for {server} is {location.rtdname}")
                if "%" in server:
                    server_region, server = server.split("%", 1)
                    region = self.graph.search_first_all(
                        {"id": server_region, "resource_type": "onprem_region"}
                    )
                    if region is None:
                        region = OnpremRegion(server_region, {})
                        self.graph.add_resource(location, region)
                        srv.update({"region": region})
                    log.debug(f"Region for {server} is {region.rtdname}")
                if "%" in server:
                    server_network, server = server.split("%", 1)
                    network = self.graph.search_first_all(
                        {"id": server_network, "resource_type": "onprem_network"}
                    )
                    if network is None:
                        network = OnpremNetwork(server_network, {})
                        self.graph.add_resource(region, network)
                        srv.update({"network": network})
                    log.debug(f"Network for {server} is {network.rtdname}")
                srv.update({"hostname": server})
                servers.append(srv)

        for srv in servers:
            try:
                s = instance_from_ssh(
                    srv.get("hostname"),
                    key_filename=ArgumentParser.args.onprem_ssh_key,
                    passphrase=ArgumentParser.args.onprem_ssh_key_pass,
                )
                src = srv.get(
                    "network", srv.get("region", srv.get("location", default_region))
                )
            except (socket.timeout, ssh_exception.PasswordRequiredException):
                log.exception(f'Failed to collect {srv.get("hostname")}')
            else:
                log.debug(f"onprem: collected {s.rtdname}")
                self.graph.add_resource(src, s)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--onprem-location",
            help="On-Prem Location",
            dest="onprem_location",
            type=str,
            default=None,
            nargs="+",
        )
        arg_parser.add_argument(
            "--onprem-subnet",
            help="On-Prem Subnet",
            dest="onprem_subnet",
            type=str,
            default=None,
            nargs="+",
        )
        arg_parser.add_argument(
            "--onprem-user",
            help="On-Prem User",
            dest="onprem_user",
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
