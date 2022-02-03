from resotolib.logging import log
from resotolib.args import ArgumentParser
from resotolib.core.query import CoreGraph
from resotolib.cleaner import Cleaner


def cleanup():
    """Run resource cleanup"""

    log.info("Running cleanup")

    cg = CoreGraph()

    query_filter = ""
    if ArgumentParser.args.collector and len(ArgumentParser.args.collector) > 0:
        clouds = '["' + '", "'.join(ArgumentParser.args.collector) + '"]'
        query_filter = f"and /ancestors.cloud.reported.id in {clouds} "
    query = (
        f"desired.clean == true and metadata.cleaned == false {query_filter}<-[0:]->"
    )

    graph = cg.graph(query)
    cleaner = Cleaner(graph)
    cleaner.cleanup()
    cg.patch_nodes(graph)


def add_args(arg_parser: ArgumentParser) -> None:
    Cleaner.add_args(arg_parser)
