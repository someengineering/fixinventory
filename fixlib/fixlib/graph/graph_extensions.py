from typing import List, Any, Generator, Hashable

from networkx import MultiDiGraph, DiGraph, connected_components


def dependent_node_iterator(
    in_graph: DiGraph,
) -> Generator[List[Any], None, None]:
    """
    Create a generator that produces a list of nodes.
    Each generation of nodes only depend on previously generated nodes.
    """

    def successor_it(g: DiGraph) -> Generator[List[Any], None, None]:
        visited = set()
        # start with all roots of the sub-graph
        to_emit = {n for n, d in g.in_degree if d == 0}

        # make sure a node is only selected if it is not visited already
        # and all predecessors have been visited already
        def allowed(nid: Hashable) -> bool:
            pred = g.predecessors(nid)
            req = [n for n in pred if n != nid and n not in visited]
            return nid not in visited and not req

        while to_emit:
            # emit the related node
            yield [nid for nid in to_emit]
            # add all nodes as visited
            visited.update(to_emit)
            # get all successors
            to_emit = {succ for nid in to_emit for succ in g.successors(nid) if allowed(succ)}

    if isinstance(in_graph, MultiDiGraph):
        raise RuntimeError("MultiDiGraph not supported")
    # reverse the directed graph -> a leaf becomes a root
    graph = in_graph.reverse()
    # find all islands and create a generator per island
    generators = [
        successor_it(graph.subgraph(island_nodes))
        for island_nodes in connected_components(graph.to_undirected(as_view=True))
    ]
    # concatenate the result of the generators
    while generators:
        nxt = []
        for e in generators:
            try:
                nxt.extend(next(e))
            except StopIteration:
                generators.remove(e)
        if nxt:
            yield nxt
