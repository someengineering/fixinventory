import resotolib.logging
from datetime import datetime
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.graph import EdgeType
from resotolib.args import ArgumentParser

log = resotolib.logging.getLogger("resoto." + __name__)


class DigitalOceanCollectorPlugin(BaseCollectorPlugin):
    cloud = "digitalocean"

    def collect(self) -> None:
        """This method is being called by resoto whenever the collector runs

        It is responsible for querying the cloud APIs for remote resources and adding
        them to the plugin graph.
        The graph root (self.graph.root) must always be followed by one or more
        accounts. An account must always be followed by a region.
        A region can contain arbitrary resources.
        """
        log.debug("plugin: collecting DigitalOcean resources")

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--digitalocean-region",
            help="DigitalOcean Region",
            dest="digitalocean_region",
            type=str,
            default=None,
            nargs="+",
        )
