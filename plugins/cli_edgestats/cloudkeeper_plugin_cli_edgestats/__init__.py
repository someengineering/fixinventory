import cloudkeeper.logging
from typing import Iterable
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.baseplugin import BaseCliPlugin
from cloudkeeper.args import ArgumentParser
from dataclasses import dataclass

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


@dataclass
class Edge:
    src: BaseResource
    dst: BaseResource

    @property
    def srcdstrt(self) -> str:
        return f"{self.src.kind}->{self.dst.kind}"


class CliEdgestatsPlugin(BaseCliPlugin):
    def cmd_edges(self, items: Iterable, args: str) -> Iterable:
        """Usage: edges

        Get all graph edges.
        Example: edges | count srcdstrt
                 edges | count src.kind
        """
        with self.graph.lock.read_access:
            for edge in self.graph.edges:
                if len(edge) == 2:
                    src = edge[0]
                    dst = edge[1]
                    if isinstance(src, BaseResource) and isinstance(dst, BaseResource):
                        e = Edge(src=src, dst=dst)
                        yield e

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass
