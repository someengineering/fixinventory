import cloudkeeper.logging
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.graph import Graph
from cloudkeeper.args import ArgumentParser
from .resources import OnpremLocation, OnpremRegion, OnpremNetwork, OnpremInstance

from paramiko import SSHClient

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class OnpremCollectorPlugin(BaseCollectorPlugin):
    cloud = "onprem"

    def collect(self) -> None:
        log.debug("plugin: collecting on-prem resources")

        account = OnpremLocation("Onprem Location", {})
        self.graph.add_resource(self.graph.root, account)

        region = OnpremRegion("onprem-region", {"Some Tag": "Some Value"})
        self.graph.add_resource(account, region)

        if len(ArgumentParser.args.onprem_server) > 0:
            for server in ArgumentParser.args.onprem_server:
                log.debug(f"onprem: collecting {server}")
                client = SSHClient()
                client.load_system_host_keys()
                client.connect(server)
                stdin, stdout, stderr = client.exec_command("ls -al /")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                client.close()

                log.debug(f"OUT: {out} {err}")
                s = OnpremInstance(server, {})
                self.graph.add_resource(region, s)

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
            default="~/.ssh/id_rsa",
        )
        arg_parser.add_argument(
            "--onprem-server",
            help="On-Prem Server",
            dest="onprem_server",
            type=str,
            default=[],
            nargs="+",
        )
