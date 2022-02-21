import resotolib.logging
from prometheus_client import Summary
from retrying import retry
from .resources import DigitalOceanProject
from resotolib.graph import Graph

log = resotolib.logging.getLogger("resoto." + __name__)


class DigitalOceanProjectCollector:
    """Collects a single DigitalOcean project
    
    
    Responsible for collecting all the resources of an individual project.
    Builds up its own local graph which is then taken by collect_project()
    and merged with the plugin graph.
    
    This way we can have many instances of DigitalOceanCollectorPlugin running in parallel.
    All building up indivetual graphs which in the end are merged to a final graph containing
    all DigitalOcean resources
    """

    def __init__(self, project: DigitalOceanProject) -> None:
        self.project = project
        
        self.graph = Graph(root=self.project)

    @retry
    def collect(self) -> None:
        """Runs the actual resource collection across all resource collectors.

        Resource collectors add their resources to the local `self.graph` graph.
        """
        self.graph = Graph(root=self.project)
        log.info("Collecting DigitalOcean resources for project %s", self.project.id)

        