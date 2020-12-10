import cloudkeeper.logging
import pickle
import requests
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.baseresources import GraphRoot
from cloudkeeper.graph import Graph, sanitize
from cloudkeeper.args import ArgumentParser


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class RemotePlugin(BaseCollectorPlugin):
    """Fetches a Graph from a remote endpoint.

    The remote plugin fetches another cloudkeeper instances /remote endpoint and loads the returned
    Graph into the local Graph. Extra care has to be taken when using this plugin as it loads a pickled
    remote object. I.e. it executes code retrieved from a remote machine. If the communication was intercepted
    or replaced malicious code could be executed on the local machine!
    """

    cloud = "remote"

    def __init__(self) -> None:
        super().__init__()
        self.graph = Graph(root=GraphRoot(self.cloud, {}))

    def collect(self) -> None:
        log.debug("plugin: collecting remote resources")
        for endpoint in ArgumentParser.args.remote_endpoint:
            log.info(f"Collecting {endpoint}")
            if endpoint.startswith("file://"):
                endpoint = endpoint[7:]
                with open(endpoint, mode="rb") as local_graph:
                    pickled_graph = local_graph.read()
            else:
                r = requests.get(endpoint)
                pickled_graph = r.content
            # todo: implement better (or any) security and authentication of the remote endpoint
            remote_graph = pickle.loads(pickled_graph)
            if not isinstance(remote_graph, Graph):
                log.error("Downloaded remote graph is not of type Graph() - skipping")
                continue

            if not isinstance(getattr(remote_graph, "root", None), GraphRoot):
                log.error(
                    "Downloaded remote graph root is not of type GraphRoot() - skipping"
                )
                continue

            log.debug("Adding remote graph to local plugin graph")
            self.graph.merge(remote_graph)
            sanitize(self.graph)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--remote-endpoint",
            help="Remote Endpoint",
            dest="remote_endpoint",
            type=str,
            default=[],
            nargs="+",
        )
