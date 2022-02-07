from __future__ import annotations

import asyncio
import json
import logging
import os.path
import re
import shutil
import tarfile
import tempfile
from abc import abstractmethod, ABC
from asyncio import Future, Task
from asyncio.subprocess import Process
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import (
    Dict,
    List,
    Tuple,
    Optional,
    Any,
    AsyncIterator,
    Hashable,
    Iterable,
    Union,
    Callable,
    Awaitable,
    cast,
    Set,
)
from urllib.parse import urlparse, urlunparse

import aiofiles
import jq
from aiohttp import ClientTimeout, JsonPayload
from aiostream import stream
from aiostream.aiter_utils import is_async_iterable
from aiostream.core import Stream
from parsy import Parser, string

from core.async_extensions import run_async
from core.cli import (
    key_values_parser,
    strip_quotes,
    is_node,
    JsGen,
    NoExitArgumentParser,
    is_edge,
    args_parts_unquoted_parser,
    args_parts_parser,
)
from core.cli.model import (
    CLICommand,
    CLIContext,
    EmptyContext,
    CLIAction,
    CLISource,
    CLIFlow,
    InternalPart,
    OutputTransformer,
    PreserveOutputFormat,
    MediaType,
    CLIFileRequirement,
    CLIDependencies,
    ParsedCommand,
)
from core.db.model import QueryModel
from core.dependencies import system_info
from core.error import CLIParseError, ClientError, CLIExecutionError
from core.model.graph_access import Section, EdgeType
from core.model.model import Model, Kind, ComplexKind, DictionaryKind, SimpleKind
from core.model.resolve_in_graph import NodePath
from core.model.typed_model import to_json, to_js
from core.parse_util import (
    double_quoted_or_simple_string_dp,
    space_dp,
    make_parser,
    variable_dp,
    literal_dp,
    comma_p,
)
from core.query.model import Query, P, Template, NavigateUntilRoot, IsTerm
from core.query.query_parser import parse_query
from core.query.template_expander import tpl_props_p
from core.task.task_description import Job, TimeTrigger, EventTrigger, ExecuteCommand
from core.types import Json, JsonElement
from core.util import (
    uuid_str,
    value_in_path_get,
    value_in_path,
    utc,
    shutdown_process,
    if_set,
    duration,
    identity,
    rnd_str,
)
from core.web.content_renderer import (
    respond_ndjson,
    respond_json,
    respond_text,
    respond_graphml,
    respond_dot,
    respond_yaml,
    respond_cytoscape,
)
from core.worker_task_queue import WorkerTask

log = logging.getLogger(__name__)


# A QueryPart is a command that can be used on the command line.
# Such a part is not executed, but builds a query, which is executed.
# Therefore, the parse method is implemented in a dummy fashion here.
# The real interpretation happens in CLI.create_query.
class QueryPart(CLICommand, ABC):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        return CLISource.empty()


class QueryAllPart(QueryPart):
    """

    ```shell
    query [--include-edges] [--explain] <query>
    ```

    This command allows to query the graph using filters, traversals, functions and aggregates.

    ## Options

    - `--include-edges`: Return edges in addition to nodes.
    - `--explain`: Instead of executing the query, analyze its cost.

    ## Parameters

    - `query` [mandatory]: The query to execute.


    ### Filters

    Filters have the form `path op value`.
    - `path` is the complete path of names in the json structure combined with a dot (e.g. reported.cpu_count).

      In case the path contains elements, that are not json conform,
      they can be put into backticks (e.g. foo.bla.\\`:-)\\`.baz).
    - `operator` is one of: `<=`, `>=`, `>`, `<`, `==`, `!=`, `=~`, `!~`, `in`, `not in`.

      Note:  `=` is the same as `==` and `~` is the same as `=~`.
    - value is a json literal (e.g. `"test"`, `23`, `[1, 2, 3]`, `true`, `{"a": 12}`).

      Note: the query parser allows to omit the parentheses for strings most of the time.
      In case the string contains whitespace or a special character, you should
      put the string into parentheses.

    Example:
    ```shell
    reported.cpu_count >= 4, name!="test", title in ["first", "second"]
    ```

    Filters can be combined with `and` and `or` and use parentheses.
    Example:
    ```shell
    (cpu_count>=4 and name!="test") or (title in ["first", "second"] and name=="test")
    ```

    ### Traversals

    Outbound traversals are traversals from a node in direction of the edge to another node, while
    inbound traversals walk the graph in opposite direction.
    Assuming 2 nodes with one connecting directed edge: `NodeA ---> NodeB`,
    traversing outbound from `NodeA` will yield `NodeB`, while traversing inbound from `NodeB` will yield `NodeA`.

    The syntax for outbound traversals is `-->` and for inbound traversals is `<--`.
    A traversal can be refined and allows to define the number of levels to walk in the graph:

    - `-[1:1]->` (shorthand for `-->`) starts from the current node and selects all nodes that can be reached by walking
      exactly one step outbound.
    - `-[0:1]->` starts (and includes) the current node and selects all nodes that can be reached by walking exactly
      one step outbound.
    - `-[<x>:<y>]->` walks from the current node to all nodes that can be reached with x steps outbound.
      From here all nodes are selected including all nodes that can be reached in y steps outbound
      relative to the starting node.
    - `-[<x>]->` shorthand `-[<x>:<x>]->`
    - `-[<x>:]->`  walks from the current node to all nodes that can be reached with x steps outbound.
      From here all nodes to the graph leafs are selected.


    The same logic is used for inbound traversals (`<--`, `<-[0:1]-`, `<-[2]-`, `<-[2:]-`).

    ### Functions

    There are predefined functions that can be used in combination with any filter.
    - is(<kind>): selects all nodes that are of type <kind> or any subtype of <kind>.
      Example: is(volume) will select all GCP disks and all AWS EC2 volumes, since both types inherit from
      base type volume.
    - id(<identifier>): selects the node with the given node identifier <identifier>.
      Example: id(foo) will select the node with id foo. The id is a synthetic id created by the collector
      and usually does not have a meaning, other than identifying a node uniquely.
    - has_key(<path>): tests if the specified name is defined in the json object.
      Example: is(volume) and has_key(tags, owner)

    ### Aggregations

    Aggregate data by using on of the following functions: `sum`, `avg`, `min`, `max` and `count`.
    Multiple aggregation functions can be applied to the result set by separating them by comma.
    Each aggregation function can be named via an optional `as <name>` clause.

    Aggregation functions can be grouped using aggregation values.
    Multiple grouping values can be defined by separating them via comma.
    Each grouping variable can be renamed via an optional `as <name>` clause.

    Examples:
    ```shell
    > query aggregate(kind: sum(1)): is(volume)
    > query aggregate(kind as kind: sum(1) as count): is(volume)
    > query aggregate(kind, volume_type: sum(1) as count): is(volume)
    > query aggregate(kind: sum(volume_size) as summed, sum(1) as count): is(volume)
    > query aggregate(sum(volume_size) as summed, sum(1) as count): is(volume)
    ```

    ### Sort and Limit

    The number of query results can be limited to a defined number by using limit <limit>
    and sorted by using sort <sort_column> [asc, desc].
    Limit and sort is allowed before a traversal and as last statement to the query result.
    Example: query is(volume) sort volume_size desc limit 3 <-[2]- sort name limit 1

    Use --explain to understand the cost of a query. A query explanation has this form (example):

    ```json
    {
        "available_nr_items": 142670,
        "estimated_cost": 61424,
        "estimated_nr_items": 1,
        "full_collection_scan": false,
        "rating": "Simple"
    }
    ```

    - `available_nr_items` describe the number of all available nodes in the graph.
    - `estimated_cost shows` the absolute cost of this query. See rating for an interpreted number.
    - `estimated_nr_items` estimated number of items returned for this query.
       It is computed based on query statistics and heuristics and does not reflect the real number.
    - `full_collection_scan` indicates, if a full collection scan is required.
       In case this is true, the query does not take advantage of any indexes.
    - `rating` The more general rating of this query.
       Simple: The estimated cost is fine - the query will most probably run smoothly.
       Complex: The estimated cost is quite high. Check other properties. Maybe an index can be used?
       Bad: The estimated cost is very high. It will most probably run long and/or will take a lot of resources.


    ## Examples

    ```shell
    # Query all volumes with state available
    > query is(volume) and volume_status=available
    kind=gcp_disk, id=71, name=gke-1, volume_status=available, age=5mo26d, cloud=gcp, account=dev, region=us-central1
    kind=gcp_disk, id=12, name=pvc-2, volume_status=available, age=4mo15d, cloud=gcp, account=eng, region=us-west1
    kind=gcp_disk, id=17, name=pvc-2, volume_status=available, age=9mo29d, cloud=gcp, account=eng, region=us-west1

    # Other sections than reported, need to be defined from the root /
    > query is(volume) and /desired.cleanup=true

    # Sort and limit the number of results
    > query is(volume) sort name asc limit 3
    kind=aws_ec2_volume, id=vol-1, name=adf-image-1, age=2mo1d, cloud=aws, account=general-support, region=us-west-2
    kind=aws_ec2_volume, id=vol-2, name=adf-image-2, age=2mo1d, cloud=aws, account=general-support, region=us-west-2

    # Emit nodes together with the edges
    > query --include-edges id(root) -[0:1]->
    node_id=root, kind=graph_root, id=root, name=root
    node_id=L_tRxI2tn6iLZdK3e8EQ3w, kind=cloud, id=gcp, name=gcp, age=5d5h, cloud=gcp
    root -> L_tRxI2tn6iLZdK3e8EQ3w
    node_id=WYcfqyMIkPAPoAHiEIIKOw, kind=cloud, id=aws, name=aws, age=5d5h, cloud=aws
    root -> WYcfqyMIkPAPoAHiEIIKOw

    # Aggregate resulting nodes
    > query aggregate(kind as kind: sum(1) as count): is(volume)
    group:
      kind: aws_ec2_volume
    count: 1799
    ---
    group:
      kind: gcp_disk
    count: 1100

    # Do not execute the query, but show an explanation of the query cost.
    > query --explain is(graph_root) -[0:1]->
    available_nr_items: 142670
    estimated_cost: 58569
    estimated_nr_items: 8
    full_collection_scan: false
    rating: simple
    ```

    ## Environment Variables

    - `graph` [default=resoto]: the name of the graph to operate on.
    - `section` [default=reported]: interpret all property paths with respect to this section.
       With section `reported` set, the query `name=~"test"` would be interpreted as `reported.name=~"test"`.
       Note: the resotoshell sets the section to reported by default.
       If you want to quickly override the section on one command line, you can define env vars in from of the
       command line (e.g.: `section=desired query clean==true`). It is possible to use absolute path using `/`,
       so all paths have to be defined from root (e.g.: `query desired.clean==true`)

    See [https://resoto.com/docs/reference/cli/query/](https://resoto.com/docs/reference/cli/query/)
    for a more detailed explanation of query.
    """

    @property
    def name(self) -> str:
        return "query"

    def info(self) -> str:
        return "Query the graph."


class PredecessorPart(QueryPart):
    """
    ```shell
    predecessors [--with-origin] [edge_type]
    ```

    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Examples

    ```shell
    > query is(volume) and volume_status=available | predecessors | query is(volume_type)
    kind=gcp_disk_type, name=pd-standard, age=2yr1mo, cloud=gcp, account=eng, region=us-central1, zone=us-central1-a
    kind=gcp_disk_type, name=pd-standard, age=2yr1mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    kind=aws_ec2_volume_type, name=gp2, age=5d8h, cloud=aws, account=sales, region=us-west-2
    ```
    """

    @property
    def name(self) -> str:
        return "predecessors"

    def info(self) -> str:
        return "Select all predecessors of this node in the graph."

    @staticmethod
    def parse_args(arg: Optional[str] = None) -> Tuple[int, str]:
        def valid_edge_type(name: str) -> str:
            if name in EdgeType.all:
                return name
            else:
                raise AttributeError(f'Given name is not a valid edge type: {name}. {", ".join(EdgeType.all)}')

        parser = NoExitArgumentParser()
        parser.add_argument("--with-origin", dest="origin", default=1, action="store_const", const=0)
        parser.add_argument("edge", default=EdgeType.default, type=valid_edge_type, nargs="?")
        parsed = parser.parse_args(arg.split() if arg else [])
        return parsed.origin, parsed.edge


class SuccessorPart(QueryPart):
    """
    ```shell
    successors [--with-origin] [edge_type]
    ```

    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.
    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.


    ## Examples

    ```shell
    > query is(volume_type) | successors | query is(volume)
    kind=gcp_disk, id=16, name=gke16, age=8mo29d, cloud=gcp, account=eng, region=us-west1, zone=us-west1-a
    kind=gcp_disk, id=26, name=gke26, age=8mo29d, cloud=gcp, account=eng, region=us-west1, zone=us-west1-a
    kind=aws_ec2_volume, id=vol1, name=vol1, age=2mo11d, cloud=aws, account=insights, region=us-west-2
    ```
    """

    @property
    def name(self) -> str:
        return "successors"

    def info(self) -> str:
        return "Select all successor of this node in the graph."


class AncestorPart(QueryPart):
    """
    ```shell
    ancestors [--with-origin] [edge_type]
    ```

    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.
    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Examples

    ```shell
    > query is(volume_type) limit 1 | ancestors
    kind=gcp_service_sku, id=D2, name=Storage PD Capacity, age=5d8h, cloud=gcp, account=sre
    kind=gcp_zone, id=2, name=us-central1-a, age=52yr1mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    kind=gcp_region, id=1000, name=us-central1, age=52yr1mo, cloud=gcp, account=sre, region=us-central1
    kind=gcp_service, id=6F81-5844-456A, name=Compute Engine, age=5d8h, cloud=gcp, account=sre
    kind=gcp_project, id=sre-tests, name=sre-tests, age=5d8h, cloud=gcp, account=sre
    kind=cloud, id=gcp, name=gcp, age=5d8h, cloud=gcp
    kind=graph_root, id=root, name=root
    ```
    """

    @property
    def name(self) -> str:
        return "ancestors"

    def info(self) -> str:
        return "Select all ancestors of this node in the graph."


class DescendantPart(QueryPart):
    """
    ```shell
    descendants [--with-origin] [edge_type]
    ```

    This command extends an already existing query.
    It will select all descendants of the currently selected nodes of the query.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `query id(A) | descendants`
    will select B and A, while `query id(A) | descendants --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    ## Examples

    ```shell
    > query is(volume_type) limit 1 | descendants --with-origin
    kind=gcp_disk_type, name=pd-standard, age=52yr1mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    kind=gcp_disk, id=881, name=disk-1, age=1yr2mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    ```
    """

    @property
    def name(self) -> str:
        return "descendants"

    def info(self) -> str:
        return "Select all descendants of this node in the graph."


class AggregatePart(QueryPart):
    """
    ```shell
    aggregate [group_prop, .., group_prop]: [function(), .. , function()]
    ```

    This command extends an already existing query.
    Using the results of a query by aggregating over given properties and applying given aggregation functions.

    Aggregate data by using on of the following functions: `sum`, `avg`, `min`, `max` and `count`.
    Multiple aggregation functions can be applied to the result set by separating them by comma.
    Each aggregation function can be named via an optional `as <name>` clause.

    Aggregation functions can be grouped using aggregation values.
    Multiple grouping values can be defined by separating them via comma.
    Each grouping variable can be renamed via an optional `as <name>` clause.

    ## Parameters

    - `group_prop`: the name of the property to use for grouping.
       Multiple grouping variables are possible, separated by comma.
       Every grouping variable can be renamed via an as name directive (`prop as prop_name`).
    - `function`: grouping function to be applied on every resulting node.
       Following functions are possible: `sum`, `count`, `min`, `max`, `avg`.
       The function contains the variable name (e.g.: min(path.to.prop))
       It is possible to use static values (e.g.: sum(1))
       It is possible to use simple math expressions in the function (e.g. min(path.to.prop * 3 + 2))
       It is possible to name the result of this function (e.g. count(foo) as number_of_foos)

    ## Examples

    ```shell
    # Count all volumes in the system based on the kind
    > query is(volume) | aggregate kind as kind: sum(1) as count
    group:
      kind: aws_ec2_volume
    count: 1799
    ---
    group:
      kind: gcp_disk
    count: 1100

    # Count all volumes in the system together with the complete volume size based on the kind
    > query is(volume) | aggregate kind: sum(volume_size) as summed, sum(1) as count
    group:
      reported.kind: aws_ec2_volume
    summed: 130903
    count: 1799
    ---
    group:
      reported.kind: gcp_disk
    summed: 23930
    count: 1100

    # Sum the available volume size without any group
    > query is(volume) | aggregate sum(volume_size) as summed, sum(1) as count
    summed: 154833
    count: 2899
    ```
    """

    @property
    def name(self) -> str:
        return "aggregate"

    def info(self) -> str:
        return "Aggregate this query by the provided specification"


class HeadCommand(QueryPart):
    """
    ```shell
    head [-num]
    ```

    Take [num] number of elements from the input stream and send them downstream.
    The rest of the stream is discarded.

    Note: using a query, the same result can be achieved using `sort` and `limit`.

    ## Options
    - `-num` [optional, defaults to 100]: the number of elements to take from the head.

    ## Examples

    ```shell
    # Json array with 5 elements is defined. We only take the first 2 elements.
    > json [1,2,3,4,5] | head -2
    1
    2

    # A query is performed to select all volumes. Only the first 2 results are taken.
    > query is(volume) | head -2
    kind=gcp_disk, id=12, name=gke-1, age=5mo26d, cloud=gcp, account=eng, region=us-central1, zone=us-central1-c
    kind=gcp_disk, id=34, name=pvc-2, age=4mo16d, cloud=gcp, account=dev, region=us-west1, zone=us-west1-a
    ```

    ## Related
    - `tail` - take the last number of elements.
    """

    @property
    def name(self) -> str:
        return "head"

    def info(self) -> str:
        return "Return n first elements of the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        size = self.parse_size(arg)
        return CLIFlow(lambda in_stream: stream.take(in_stream, size))

    @staticmethod
    def parse_size(arg: Optional[str]) -> int:
        return abs(int(arg)) if arg else 100


class TailCommand(QueryPart):
    """
    ```shell
    tail [-num]
    ```

    Take the last [num] number of elements from the input stream and send them downstream.
    The beginning of the stream is consumed and discarded.

    Note: using a query, the same result can be achieved using `sort` and `limit`.

    ## Options
    - `-num` [optional, defaults to 100]: the number of elements to take from the head.

    ## Examples

    ```shell
    # Json array with 5 elements is defined. We only take the last 2 elements.
    > json [1,2,3,4,5] | tail -2
    4
    5

    # A query is performed to select all volumes. Only the last 2 results are taken.
    > query is(volume) | tail -2
    kind=aws_ec2_volume, id=vol-0, name=vol-0, age=2mo1d, cloud=aws, account=dev, region=us-west-2
    kind=gcp_disk, id=123, name=gke-1, age=7mo22d, cloud=gcp, account=eng, region=us-west1, zone=us-west1-a
    ```

    ## Related
    - `head` - take a defined number of elements.
    """

    @property
    def name(self) -> str:
        return "tail"

    def info(self) -> str:
        return "Return n last elements of the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        size = HeadCommand.parse_size(arg)
        return CLIFlow(lambda in_stream: stream.takelast(in_stream, size))


class CountCommand(QueryPart):
    """
    ```shell
    count [arg]
    ```

    In case no arg is given, it counts the number of instances provided to count.
    In case of arg: it pulls the property with the name of arg and counts the occurrences of this property.

    This command is part of a query.
    `count` uses an aggregation query under the hood.
    In case you need more advances aggregations, please see `help aggregation`.

    ## Parameters

    - `arg` [optional]: Instead of counting the instances, count the occurrences of given instance.


    ## Examples

    ```shell
    # Json array with 3 objects is defined and then counted.
    > json [{"a": 1}, {"a": 2}, {"a": 1}] | count
    total matched: 3
    total unmatched: 0

    # Json array with 3 objects is defined. This time the occurrences of the value of a is counted.
    > json [{"a": 1}, {"a": 2}, {"a": 1}] | count a
    2: 1
    1: 2
    total matched: 3
    total unmatched: 0

    > json [{"a": 1}, {"a": 2}, {"a": 3}] | count b
    total matched: 0
    total unmatched: 3

    > query all | count
    total matched: 142670
    total unmatched: 0

    > query all | count /ancestors.cloud.reported.name
    gcp: 42403
    aws: 93168
    total matched: 135571
    total unmatched: 0
    ```
    """

    @property
    def name(self) -> str:
        return "count"

    def info(self) -> str:
        return "Count incoming elements or sum defined property."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        get_path = ctx.variable_in_section(arg).split(".") if arg else None
        counter: Dict[str, int] = defaultdict(int)
        matched = 0
        unmatched = 0

        def inc_prop(o: JsonElement) -> None:
            nonlocal matched
            nonlocal unmatched
            value = value_in_path(o, get_path)  # type:ignore
            if value is not None:
                if isinstance(value, str):
                    pass
                elif isinstance(value, (dict, list)):
                    value = json.dumps(value)
                else:
                    value = str(value)
                matched += 1
                counter[value] += 1
            else:
                unmatched += 1

        def inc_identity(_: Any) -> None:
            nonlocal matched
            matched += 1

        fn = inc_prop if arg else inc_identity

        async def count_in_stream(content: Stream) -> AsyncIterator[JsonElement]:
            async with content.stream() as in_stream:
                async for element in in_stream:
                    fn(element)

            for key, value in sorted(counter.items(), key=lambda x: x[1]):
                yield f"{key}: {value}"

            yield f"total matched: {matched}"
            yield f"total unmatched: {unmatched}"

        # noinspection PyTypeChecker
        return CLIFlow(count_in_stream)


class EchoCommand(CLICommand):
    """
    ```shell
    echo <message>
    ```

    Send the provided message to downstream.

    ## Parameters
    - `message` is the message to send downstream.

    ## Examples
    ```shell
    # Hello World in resoto
    > echo Hello World
    Hello World

    # Echo the current time. The placeholder @TIME@ is replaced during execution time.
    > echo The current time is @TIME@
    The current time is 09:16:18
    ```
    """

    @property
    def name(self) -> str:
        return "echo"

    def info(self) -> str:
        return "Send the provided message to downstream"

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        return CLISource.single(lambda: stream.just(strip_quotes(arg if arg else "")))


class JsonCommand(CLICommand):
    """
    ```shell
    json <json-string>
    ```

    The defined json-string will be parsed into a json structure.
    If the defined element is a json array, each element of the array will be sent downstream.
    Any other json type will be sent as is.

    ## Parameters

    - `json-string` the json string that is parsed as json.

    ## Examples

    ```shell
    # A simple json string is parsed.
    > json "test"
    test

    # A json object is parsed.
    > json {"a": 1, "b": 2}
    a: 1
    b: 2

    # An array of json objects is parsed. Each element is sent downstream.
    > json [{"a":1, "b": 2}, {"c": 3, "d": 4}]
    a: 1
    b: 2
    ---
    c: 3
    d: 4
    ```
    """

    @property
    def name(self) -> str:
        return "json"

    def info(self) -> str:
        return "Parse json and pass parsed objects to the output stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        if arg:
            js = json.loads(arg)
        else:
            raise AttributeError("json expects one argument!")
        if isinstance(js, list):
            elements = js
        elif isinstance(js, (str, int, float, bool, dict)):
            elements = [js]
        else:
            raise AttributeError(f"json does not understand {arg}.")
        return CLISource.with_count(lambda: stream.iterate(elements), len(elements))


class SleepCommand(CLICommand):
    """
    ```shell
    sleep <seconds>
    ```
    Sleep the amount of seconds. An empty string is emitted.

    ## Parameters
    - `seconds` the number of seconds to sleep.

    ### Examples
    ```shell
    # Print the string "6 seconds later..." after 6 seconds.
    > sleep 6; echo 6 seconds later...

    ---
    6 seconds later...
    """

    @property
    def name(self) -> str:
        return "sleep"

    def info(self) -> str:
        return "Suspend execution for an interval of time"

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:

        if not arg:
            raise AttributeError("Sleep needs an argument!")
        try:
            sleep_time = float(arg)

            async def sleep() -> AsyncIterator[JsonElement]:
                for _ in range(0, 1):
                    await asyncio.sleep(sleep_time)
                    yield ""

            return CLISource.single(sleep)
        except Exception as ex:
            raise AttributeError("Sleep needs the time in seconds as arg.") from ex


class AggregateToCountCommand(CLICommand, InternalPart):
    """
    ```shell
    aggregate_to_count
    ```

    This command transforms the output of an aggregation query to the output of the count command.
    ```
    { "group": { "name": "group_name" }, "count": 123 }  --> group_name: 123
    ```

    Expected group key: `name`
    Expected function key: `count`

    It is usually not invoked directly but automatically invoked when there is a query | count cli command.
    """

    @property
    def name(self) -> str:
        return "aggregate_to_count"

    def info(self) -> str:
        return "Convert the output of an aggregate query to the result of count."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        name_path = ["group", "name"]
        count_path = ["count"]

        async def to_count(in_stream: AsyncIterator[JsonElement]) -> AsyncIterator[JsonElement]:
            null_value = 0
            total = 0
            in_streamer = in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)
            async with in_streamer.stream() as streamer:
                async for elem in streamer:
                    name = value_in_path(elem, name_path)
                    count = value_in_path_get(elem, count_path, 0)
                    if name is None:
                        null_value = count
                    else:
                        total += count
                        yield f"{name}: {count}"
                tm, tu = (total, null_value) if arg else (null_value + total, 0)
                yield f"total matched: {tm}"
                yield f"total unmatched: {tu}"

        return CLIFlow(to_count)


class ExecuteQueryCommand(CLICommand, InternalPart):
    """
    ```shell
    execute_query [--include-edges] [--explain] <query>
    ```

    This command is usually not invoked directly - use `query` instead.

    ## Options

    - `--include-edges`: Return edges in addition to nodes.
    - `--explain`: Instead of executing the query, analyze its cost.

    ## Parameters

    - `query` [mandatory]: The query to execute.

    ## Related
    - `query` - query the graph.
    """

    @property
    def name(self) -> str:
        return "execute_query"

    def info(self) -> str:
        return "Query the database and pass the results to the output stream."

    @staticmethod
    def parse_known(arg: str) -> Tuple[Dict[str, Any], str]:
        parser = NoExitArgumentParser()
        parser.add_argument("--include-edges", dest="include-edges", default=None, action="store_true")
        parser.add_argument("--explain", dest="explain", default=None, action="store_true")
        parsed, rest = parser.parse_known_args(arg.split(maxsplit=2))
        return {k: v for k, v in vars(parsed).items() if v is not None}, " ".join(rest)

    @staticmethod
    def argument_string(args: Dict[str, Any]) -> str:
        result = []
        for key, value in args.items():
            if value is True:
                result.append(f"--{key}")
        return " ".join(result) + " " if result else ""

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        # db name is coming from the env
        graph_name = ctx.env["graph"]
        if not arg:
            raise CLIParseError("query command needs a query to execute, but nothing was given!")

        # Read all argument flags / options
        parsed, rest = self.parse_known(arg)
        with_edges: bool = parsed.get("include-edges", False)
        explain: bool = parsed.get("explain", False)

        # all templates are expanded at this point, so we can call the parser directly.
        query = parse_query(rest, **ctx.env)
        db = self.dependencies.db_access.get_graph_db(graph_name)

        async def load_query_model() -> QueryModel:
            model = await self.dependencies.model_handler.load_model()
            query_model = QueryModel(query, model)
            await db.to_query(query_model)  # only here to validate the query itself (can throw)
            return query_model

        async def explain_query() -> AsyncIterator[Json]:
            query_model = await load_query_model()
            explanation = await db.explain(query_model, with_edges)
            yield to_js(explanation)

        async def prepare() -> Tuple[Optional[int], AsyncIterator[Json]]:
            query_model = await load_query_model()
            count = ctx.env.get("count", "true").lower() != "false"
            timeout = if_set(ctx.env.get("query_timeout"), duration)
            context = (
                await db.query_aggregation(query_model)
                if query.aggregate
                else (
                    await db.query_graph_gen(query_model, with_count=count, timeout=timeout)
                    if with_edges
                    else await db.query_list(query_model, with_count=count, timeout=timeout)
                )
            )
            cursor = context.cursor

            # since we can not use context boundaries here,
            # an explicit iterator is used, which makes sure to close the connection.
            async def iterate_and_close() -> AsyncIterator[Json]:
                try:
                    async for e in cursor:
                        yield e
                finally:
                    cursor.close()

            return cursor.count(), iterate_and_close()

        return CLISource.single(explain_query) if explain else CLISource(prepare)


class EnvCommand(CLICommand):
    """
    ```shell
    env
    ```

    Emits the provided environment.
    This is useful to inspect the environment given to the CLI interpreter.

    ## Examples
    ```shell
    # The resotoshell will set the graph, section and a session id.
    > env
    graph: resoto
    section: reported
    resoto_session_id: SHQF9MBUEJ

    # Environment variables can be defined directly on the command line
    > section=desired foo=bla env
    graph: resoto
    section: desired
    resoto_session_id: SHQF9MBUEJ
    foo: bla
    ```
    """

    @property
    def name(self) -> str:
        return "env"

    def info(self) -> str:
        return "Retrieve the environment and pass it to the output stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        return CLISource.with_count(lambda: stream.just(ctx.env), len(ctx.env))


class ChunkCommand(CLICommand):
    """
    ```shell
    chunk [num]
    ```

    Take <num> number of elements from the input stream, put them in a list and send a stream of list downstream.
    The last chunk might have a lower size than the defined chunk size.

    ## Parameters
    - `num` [optional, defaults to 100] - the number of elements to put into one chunk.

    ## Examples

    ```shell
    # Chunk an array by putting up to 2 elements into one chunk and sent it downstream.
    > json [1,2,3,4,5] | chunk 2
    [1, 2]
    [3, 4]
    [5]

    # Chunk an array by putting up to 3 elements into one chunk and sent it downstream.
    > json [1,2,3,4,5] | chunk 3
    [1, 2, 3]
    [4, 5]

    # The output of query can be chunked as well. The result is omitted here for brevity.
    > query is(volume) limit 5 | chunk 3
    ```

    ## Related
    - `flatten` - for flattening a chunked input stream.
    """

    @property
    def name(self) -> str:
        return "chunk"

    def info(self) -> str:
        return "Chunk incoming elements in batches."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        size = int(arg) if arg else 100
        return CLIFlow(lambda in_stream: stream.chunks(in_stream, size))


class FlattenCommand(CLICommand):
    """
    ```shell
    flatten
    ```

    Take array elements from the input stream and put them to the output stream one after the other,
    while preserving the original order.

    ## Examples:

    ```shell
    # In case elements of the stream are arrays, they will be flattened.
    > json [[1, 2], 3, [4, 5]] | flatten
    1
    2
    3
    4
    5

    # An already flat stream of elements is not changed.
    > json [1, 2, 3, 4, 5] | flatten
    1
    2
    3
    4
    5
    ```

    ## Related
    - `chunk` to put incoming elements into chunks
    """

    @property
    def name(self) -> str:
        return "flatten"

    def info(self) -> str:
        return "Take incoming batches of elements and flattens them to a stream of single elements."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        def iterate(it: Any) -> Stream:
            return stream.iterate(it) if is_async_iterable(it) or isinstance(it, Iterable) else stream.just(it)

        return CLIFlow(lambda in_stream: stream.flatmap(in_stream, iterate))


class UniqCommand(CLICommand):
    """
    ```shell
    uniq
    ```

    All elements flowing through the uniq command are analyzed and all duplicates get removed.
    Note: a hash value is computed from json objects, which is ignorant of the order of properties,
    so that `{"a": 1, "b": 2}` is declared equal to `{"b": 2, "a": 1}`

    ## Examples

    ```shell
    # Multiple occurrences of the same element are sorted out.
    > json [1, 2, 3, 1, 2, 3] | uniq
    1
    2
    3

    # The same logic applies to json objects
    > json [{"a": 1, "b": 2}, {"b": 2, "a": 1}] | uniq
    a: 1
    b: 2
    ```
    """

    @property
    def name(self) -> str:
        return "uniq"

    def info(self) -> str:
        return "Remove all duplicated objects from the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        visited = set()

        def hashed(item: Any) -> Hashable:
            if isinstance(item, dict):
                return json.dumps(item, sort_keys=True)
            else:
                raise CLIParseError(f"{self.name} can not make {item}:{type(item)} uniq")

        def has_not_seen(item: Any) -> bool:
            item = item if isinstance(item, Hashable) else hashed(item)

            if item in visited:
                return False
            else:
                visited.add(item)
                return True

        return CLIFlow(lambda in_stream: stream.filter(in_stream, has_not_seen))


class JqCommand(CLICommand, OutputTransformer):
    """
    ```
    jq <filter>
    ```

    Use the well known jq JSON processor to manipulate incoming json.
    Every element from the incoming stream is passed to jq.
    See: https://stedolan.github.io/jq/ for a list of possible jq filter definitions.

    ## Parameter

    - `filter` the filter definition to create a jq program.

    ## Examples

    ```shell
    # Query ec2 instances and extract only the name property
    > query is(aws_ec2_instance) limit 2| jq .name
    build-node-1
    prod-23

    # Query ec2 instances and create a new json object for each entry with name and owner.
    > query is(aws_ec2_instance) limit 2 | jq {name: .name, owner: .tags.owner}
    name: build-node-1
    owner: frosty
    ---
    name: prod-23
    owner: bog-team
    ```

    ## Related
    - `format` - to format incoming objects to a defined string.
    - `list` - create list output for every element.
    """

    @property
    def name(self) -> str:
        return "jq"

    def info(self) -> str:
        return "Filter and process json."

    path_re = re.compile("[.](?:([A-Za-z])+|(\\[]))[A-Za-z0-9\\[\\].]*")

    @staticmethod
    def rewrite_props(arg: str, ctx: CLIContext) -> str:
        """
        Rewrite property path according to their section.
        .foo -> .reported.foo
        {a: .a, b:.path.to.b} -> {a: .reported.a, b:.reported.path.to.b }
        """
        split = arg.split("|", maxsplit=1)  # ignore everything after the pipe
        selector, rest = (split[0], "|" + split[1]) if len(split) == 2 else (split[0], "")
        last_pos = 0
        result = ""
        for match in JqCommand.path_re.finditer(selector):
            result += selector[last_pos : match.start()]  # noqa: E203
            result += "."
            result += ctx.variable_in_section(match[0][1:])
            last_pos = match.end()
        result += selector[last_pos : len(selector)]  # noqa: E203
        return result + rest

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        if not arg:
            raise AttributeError("jq requires an argument to be parsed")

        compiled = jq.compile(self.rewrite_props(strip_quotes(arg), ctx))

        def process(in_json: Json) -> Json:
            out = compiled.input(in_json).all()
            result = out[0] if len(out) == 1 else out
            return cast(Json, result)

        return CLIFlow(lambda in_stream: stream.map(in_stream, process))


class KindCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    kind [-p property_path] [name]
    ```

    kind gives information about the available graph data kinds.

    ## Options

    - `-p` [Optional] property_path: lookup the kind for the defined property path.
       This will do a reverse lookup and search all kinds for the specified property path.

    ## Parameters

    - `name` [Optional]: show available information about the kind with provided name.

    ## Examples

    ```shell

    # Show all available kinds.
    > kind
    access_key
    .
    .
    zone

    # Show details about a specific kind.
    > kind graph_root
    name: graph_root
    bases:
    - graph_root
    properties:
    - description: The name of this node.
      kind: string
      name: name
      required: false
    - description: All attached tags of this node.
      kind: dictionary[string, string]
      name: tags
      required: false

    # Lookup the type of the given property path in the model.
    > kind -p reported.tags.owner
    name: string
    runtime_kind: string
    ```
    """

    @property
    def name(self) -> str:
        return "kind"

    def info(self) -> str:
        return "Retrieves information about the graph data kinds."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        show_path: Optional[str] = None
        show_kind: Optional[str] = None

        if arg:
            args = strip_quotes(arg).split(" ")
            if len(args) == 1:
                show_kind = arg
            elif len(args) == 2 and args[0] == "-p":
                show_path = args[1]
            else:
                raise AttributeError(f"Don't know what to do with: {arg}")

        def kind_to_js(kind: Kind) -> Json:
            if isinstance(kind, SimpleKind):
                return {"name": kind.fqn, "runtime_kind": kind.runtime_kind}
            elif isinstance(kind, DictionaryKind):
                return {"name": kind.fqn, "key": kind.key_kind.fqn, "value": kind.value_kind.fqn}
            elif isinstance(kind, ComplexKind):
                props = sorted(kind.all_props(), key=lambda k: k.name)
                return {"name": kind.fqn, "bases": list(kind.kind_hierarchy()), "properties": to_json(props)}
            else:
                return {"name": kind.fqn}

        async def source() -> Tuple[int, Stream]:
            model = await self.dependencies.model_handler.load_model()
            if show_kind:
                result = kind_to_js(model[show_kind]) if show_kind in model else f"No kind with this name: {show_kind}"
                return 1, stream.just(result)
            elif show_path:
                result = kind_to_js(model.kind_by_path(Section.without_section(show_path)))
                return 1, stream.just(result)
            else:
                result = sorted(list(model.kinds.keys()))
                return len(model.kinds), stream.iterate(result)

        return CLISource(source)


class SetDesiredStateBase(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_desired, arg, ctx.env["graph"], self.patch(arg, ctx))
        return CLIFlow(lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func))

    async def set_desired(
        self, arg: Optional[str], graph_name: str, patch: Json, items: List[Json]
    ) -> AsyncIterator[JsonElement]:
        model = await self.dependencies.model_handler.load_model()
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = []
        for item in items:
            if "id" in item:
                node_ids.append(item["id"])
            elif isinstance(item, str):
                node_ids.append(item)
        async for update in db.update_nodes_desired(model, patch, node_ids):
            yield update


class SetDesiredCommand(SetDesiredStateBase):
    """
    ```shell
    set_desired <property>=<value> [<property>=<value> ..]
    ```

    Set one or more desired properties for every database node that is received on the input channel.
    The desired state of each node in the database is merged with this new desired state, so that
    existing desired state not defined in this command is not touched.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.
    The result of this command will emit the updated state.

    ## Parameters

    - `property` - the name of the property to set in the desired section.
    - `value` - the value of the property to set in the desired section. This needs to be a json element.

    Multiple properties can be changed by defining multiple property=value definitions separated by space.

    ## Examples

    ```shell
    > query is(instance) limit 1 | set_desired a=b b="c" num=2 | list /id, /desired
    id=123, a=b, b=c, num=2

    > json ["id1", "id2"] | set_desired a=b | list /id /desired
    id=id1, a=b
    id=id2, a=b
    ```
    """

    @property
    def name(self) -> str:
        return "set_desired"

    def info(self) -> str:
        return "Allows to set arbitrary properties as desired for all incoming database objects."

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class CleanCommand(SetDesiredStateBase):
    """
    ```shell
    clean [reason]
    ```

    Mark incoming objects for cleanup.
    All objects marked as such will eventually be cleaned up in the next delete run.

    An optional reason can be provided.
    This reason is used to log each marked element, which can be useful to understand the reason
    a resource is cleaned later on.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    The result of this command will emit the updated object.

    ## Parameters
    - `reason` [Optional] - a log message is issued with this reason, once a resource is marked for cleanup.

    ## Examples
    ```shell
    # Query for volumes that have not been accessed in the last month
    # Mark them for cleanup and show the id as well as the complete desired section.
    > query is(volume) and last_access>1month | clean "Volume not accessed for longer than 1 month" | list id, /desired
    id=vol-123, clean=true

    # Manually mark a list of resources for cleanup.
    > json ["vol-123"] | clean | list id, /desired
    id=vol-123, clean=true
    ```
    """

    @property
    def name(self) -> str:
        return "clean"

    def info(self) -> str:
        return "Mark all incoming database objects for cleaning."

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        return {"clean": True}

    async def set_desired(
        self, arg: Optional[str], graph_name: str, patch: Json, items: List[Json]
    ) -> AsyncIterator[JsonElement]:
        reason = f"Reason: {strip_quotes(arg)}" if arg else "No reason provided."
        async for elem in super().set_desired(arg, graph_name, patch, items):
            uid = value_in_path(elem, NodePath.node_id)
            r_id = value_in_path_get(elem, NodePath.reported_id, "<no id>")
            r_name = value_in_path_get(elem, NodePath.reported_name, "<no name>")
            r_kind = value_in_path_get(elem, NodePath.reported_kind, "<no kind>")
            log.info(f"Node id={r_id}, name={r_name}, kind={r_kind} marked for cleanup. {reason}. ({uid})")
            yield elem


class SetMetadataStateBase(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_metadata, ctx.env["graph"], self.patch(arg, ctx))
        return CLIFlow(lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func))

    async def set_metadata(self, graph_name: str, patch: Json, items: List[Json]) -> AsyncIterator[JsonElement]:
        model = await self.dependencies.model_handler.load_model()
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = []
        for item in items:
            if "id" in item:
                node_ids.append(item["id"])
            elif isinstance(item, str):
                node_ids.append(item)
        async for update in db.update_nodes_metadata(model, patch, node_ids):
            yield update


class SetMetadataCommand(SetMetadataStateBase):
    """
    ```shell
    set_metadata <property>=<value> [<property>=<value> ..]
    ```

    Set one or more metadata properties for every database node that is received on the input channel.
    The metadata state of each node in the database is merged with this new metadata state, so that
    existing metadata state not defined in this command is not touched.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.
    The result of this command will emit the updated state.

    ## Parameters

    - `property` - the name of the property to set in the desired section.
    - `value` - the value of the property to set in the desired section. This needs to be a json element.

    Multiple properties can be changed by defining multiple property=value definitions separated by space.


    ## Examples

    ```shell
    > query is(instance) limit 1 | set_metadata a=b b="c" num=2 | list /id, /metadata
    id=123, a=b, b=c, num=2

    > json ["id1", "id2"] | set_metadata a=b | list /id /metadata
    id=id1, a=b
    id=id2, a=b
    ```
    """

    @property
    def name(self) -> str:
        return "set_metadata"

    def info(self) -> str:
        return "Allows to set arbitrary properties as metadata for all incoming database objects."

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class ProtectCommand(SetMetadataStateBase):
    """
    ```shell
    protect
    ```

    Mark incoming objects as protected.
    All objects marked as such will not be cleaned up, even if they are marked for cleanup.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.
    The result of this command will emit the updated object.

    ## Examples

    ```shell
    # Query for instances that are tagged with "build node" - such nodes should never be clean up.
    > query is(instance) and tags.job=="build node" | protect | list id, /metadata
    id=ins123, protected=true

    # Manually protect a list of resources.
    > json ["ins123"] | protect | list id, /metadata
    id=vol-123, protected=true
    ```
    """

    @property
    def name(self) -> str:
        return "protect"

    def info(self) -> str:
        return "Mark all incoming database objects as protected."

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        return {"protected": True}


class FormatCommand(CLICommand, OutputTransformer):
    """
    ```
    format [--json][--ndjson][--text][--cytoscape][--graphml][--dot] [format string]
    ```

    This command creates a string from the json input based on the format string.
    The format string might contain placeholders in curly braces that access properties of the json object.
    If a property is not available, it will result in the string `null`.
    You can either use a format string or you can use a predefined format.

    ## Options
    - `--json` [Optional] - will create a json string from the incoming json. The result will be a json array.
    - `--ndjson` [Optional] - will create a json object for every element, where one element fits on one line.
    - `--text` [Optional] - will create a text representation of every element.
    - `--cytoscape` [Optional] - will create a string representation in the well known cytoscape format.
      See: [https://js.cytoscape.org/#notation/elements-json](https://js.cytoscape.org/#notation/elements-json)
    - `--graphml` [Optional] - will create string representaion of the result in graphml format.
      See: [http://graphml.graphdrawing.org](http://graphml.graphdrawing.org)
    - `--dot` [Optional] - will create a string representation in graphviz dot format.
      See: [https://graphviz.org/doc/info/lang.html](https://graphviz.org/doc/info/lang.html)

    ## Parameters
    - `format_string` [optional]: a string with any content with placeholders to be filled by the object.
      Placeholders are defined in curly braces.


    ## Examples

    ```shell
    # Example json to extract a formatted string using placeholder format
    > json {"a":"b", "b": {"c":"d"}} | format >{a}< and not >{b.c}<
    >b< and not >d<

    # Accessing any nested or list property is possible
    > json {"b": {"c":[0,1,2,3]}} | format only select >{b.c[2]}<
    only select >2<

    > query all | format --json | write out.json
    Received a file out.json, which is stored to ./out.json.
    ```
    """

    @property
    def name(self) -> str:
        return "format"

    def info(self) -> str:
        return "Transform incoming objects as string with a defined format."

    formats = {
        "ndjson": respond_ndjson,
        "json": respond_json,
        "text": respond_text,
        "yaml": respond_yaml,
        "cytoscape": respond_cytoscape,
        "graphml": respond_graphml,
        "dot": respond_dot,
    }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        parser = NoExitArgumentParser()
        parser.add_argument("--json", dest="json", action="store_true")
        parser.add_argument("--ndjson", dest="ndjson", action="store_true")
        parser.add_argument("--graphml", dest="graphml", action="store_true")
        parser.add_argument("--text", dest="text", action="store_true")
        parser.add_argument("--yaml", dest="yaml", action="store_true")
        parser.add_argument("--cytoscape", dest="cytoscape", action="store_true")
        parser.add_argument("--dot", dest="dot", action="store_true")
        parsed, formatting_string = parser.parse_known_args(arg.split() if arg else [])
        format_to_use = {k for k, v in vars(parsed).items() if v is True}

        async def render_format(format_name: str, iss: Stream) -> JsGen:
            async with iss.stream() as streamer:
                async for elem in self.formats[format_name](streamer):
                    yield elem

        async def format_stream(in_stream: Stream) -> Stream:
            if format_to_use:
                if len(format_to_use) > 1:
                    raise AttributeError(f'You can define only one format. Defined: {", ".join(format_to_use)}')
                if len(formatting_string) > 0:
                    raise AttributeError("A format renderer can not be combined together with a format string!")
                return render_format(next(iter(format_to_use)), in_stream)
            elif formatting_string:
                return stream.map(in_stream, ctx.formatter(arg)) if arg else in_stream
            else:
                return in_stream

        return CLIFlow(format_stream)


@make_parser
def list_single_arg_parse() -> Parser:
    name = yield variable_dp
    as_name = yield (space_dp >> string("as") >> space_dp >> literal_dp).optional()
    return name, as_name


list_arg_parse = list_single_arg_parse.sep_by(comma_p, min=1)


class DumpCommand(CLICommand, OutputTransformer):
    """
    ```
    dump
    ```

    Dump all properties of an incoming element.

    ## Example

    ```shell
    > query is(volume) limit 1 | dump
    id: 0QcwZ5DHsS58A1tHEk5JRQ
    reported:
      kind: gcp_disk
      id: '7027640035137'
      tags:
        owner: 'dev-rel'
      name: gke-cluster-1
      ctime: '2021-08-04T08:31:42Z'
      volume_size: 50
      volume_type: pd-standard
      volume_status: available
      snapshot_before_delete: false
      link: https://www.googleapis.com/compute/v1/projects/eng-ksphere-platform/zones/us-central1-c/disks/gke-cluster-1
      label_fingerprint: nT7_dAxskBs=
      last_attach_timestamp: '2021-08-04T08:31:42Z'
      last_detach_timestamp: '2021-08-04T08:31:42Z'
      age: 5mo25d
    metadata:
      protected: false
    ancestors:
      cloud:
        reported:
          name: gcp
          id: gcp
      account:
        reported:
          name: eng-ksphere-platform
          id: eng-ksphere-platform
      region:
        reported:
          name: us-central1
          id: '1000'
      zone:
        reported:
          name: us-central1-c
          id: '2002'
    ```

    ## Related

    - `format` - Create a string from object based on a defined format.
    - `list` - Define a list of properties to show.
    - `jq` - Define a transformation via the well known `jq` command.
    """

    @property
    def name(self) -> str:
        return "dump"

    def info(self) -> str:
        return "Dump all properties of incoming objects."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        # Dump returns the same stream as provided without changing anything.
        # Since it is an OutputTransformer, the resulting transformer will be dump (not list).
        return CLIFlow(identity)


class ListCommand(CLICommand, OutputTransformer):
    """
    ```
    list [property [as <name>]] [,property ...]
    ```

    This command creates a string from the json input based on the defined properties to show.

    If no prop is defined a predefined list of properties will be shown:

    - /reported.kind as kind
    - /reported.id as id
    - /reported.name as name
    - /reported.age as age
    - /reported.last_update as last_update
    - /ancestors.cloud.reported.name as cloud
    - /ancestors.account.reported.name as account
    - /ancestors.region.reported.name as region
    - /ancestors.zone.reported.name as zone

    If property is defined, it will override the default and will show the defined properties.
    The syntax for property is a comma delimited list of property paths.
    The property path can be absolute, meaning it includes the section name (reported, desired, metadata).
    In case the section name is not defined, the reported section is assumed automatically.

    The defined property path will be looked for every element in the incoming json.
    If the value is defined, it will be part of the list line.
    Undefined values are filtered out and will not be printed.

    The property name can be defined via an `as` clause.
    `reported.kind as kind` would look up the path reported.kind and if the value is defined write kind={value}
    If no as clause is defined, the name of the last element of property path is taken.
    In the example above we could write `reported.kind` or `reported.kind as kind` - both would end in the same result.
    The `as` clause is important, in case the last part of the property path is not sufficient as property name.


    ## Parameters

    - property [optional]: a comma separated list of properties to show. Each property defines the path
      to the property with an optional name.

      *Example*: `path.to.property as prop1`.

    ## Examples

    ```shell
    # If all parameters are omitted, the predefined default list is taken.
    > query is(aws_ec2_instance) limit 3 | list
    kind=aws_ec2_instance, id=1, name=sun, ctime=2020-09-10T13:24:45Z, cloud=aws, account=prod, region=us-west-2
    kind=aws_ec2_instance, id=2, name=moon, ctime=2021-09-21T01:08:11Z, cloud=aws, account=dev, region=us-west-2
    kind=aws_ec2_instance, id=3, name=star, ctime=2021-09-25T23:28:40Z, cloud=aws, account=int, region=us-east-1

    # Explicitly define the properties to show without renaming them.
    > query is(aws_ec2_instance) limit 3 | list kind, name
    kind=aws_ec2_instance, name=sun
    kind=aws_ec2_instance, name=moon
    kind=aws_ec2_instance, name=star

    # Same query and same result as before, with an explicit rename clause.
    > query is(aws_ec2_instance) limit 3 | list kind as a, name as b
    a=aws_ec2_instance, b=sun
    a=aws_ec2_instance, b=moon
    a=aws_ec2_instance, b=star

    # Properties that do not exist, are not printed.
    > query is(aws_ec2_instance) limit 3 | list kind as a, name as b, does_not_exist
    a=aws_ec2_instance, b=sun
    a=aws_ec2_instance, b=moon
    a=aws_ec2_instance, b=star
    ```

    ## Related

    - `format` - Create a string from object based on a defined format.
    - `dump` - will show the complete content tree of an incoming object.
    - `jq` - Define a transformation via the well known `jq` command.

    """

    # This is the list of properties to show in the list command by default
    default_properties_to_show = [
        (["reported", "kind"], "kind"),
        (["reported", "id"], "id"),
        (["reported", "name"], "name"),
    ]
    default_context_properties_to_show = [
        (["reported", "age"], "age"),
        (["reported", "last_update"], "last_update"),
        (["ancestors", "cloud", "reported", "name"], "cloud"),
        (["ancestors", "account", "reported", "name"], "account"),
        (["ancestors", "region", "reported", "name"], "region"),
        (["ancestors", "zone", "reported", "name"], "zone"),
    ]
    all_default_props = {".".join(path) for path, _ in default_properties_to_show + default_context_properties_to_show}
    dot_re = re.compile("[.]")

    @property
    def name(self) -> str:
        return "list"

    def info(self) -> str:
        return "Transform incoming objects as string with defined properties."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        def default_props_to_show() -> List[Tuple[List[str], str]]:
            result = []
            # include the object id, if edges are requested
            if ctx.query_options.get("include-edges") is True:
                result.append((["id"], "node_id"))
            # add all default props
            result.extend(self.default_properties_to_show)
            # add all predicates the user has queried
            if ctx.query:
                for predicate in ctx.query.predicates:
                    if predicate.name not in self.all_default_props:
                        result.append((self.dot_re.split(predicate.name), predicate.name.rsplit(".", 1)[-1]))
            # add all context properties
            result.extend(self.default_context_properties_to_show)
            return result

        def adjust_path(prop_path: str) -> List[str]:
            return self.dot_re.split(ctx.variable_in_section(prop_path))

        def to_str(name: str, elem: JsonElement) -> str:
            if isinstance(elem, dict):
                return ", ".join(f"{to_str(k, v)}" for k, v in sorted(elem.items()))
            elif isinstance(elem, list):
                return f"{name}=[" + ", ".join(str(e) for e in elem) + "]"
            elif elem is None:
                return f"{name}=null"
            elif elem is True:
                return f"{name}=true"
            elif elem is False:
                return f"{name}=false"
            else:
                return f"{name}={elem}"

        def parse_props_to_show(props_arg: str) -> List[Tuple[List[str], str]]:
            props: List[Tuple[List[str], str]] = []
            for prop, as_name in list_arg_parse.parse(props_arg):
                path = adjust_path(prop)
                as_name = path[-1] if prop == as_name or as_name is None else as_name
                props.append((path, as_name))
            return props

        props_to_show = parse_props_to_show(arg) if arg is not None else default_props_to_show()

        def fmt_json(elem: Json) -> JsonElement:
            if is_node(elem):
                result = ""
                first = True
                for prop_path, name in props_to_show:
                    value = value_in_path(elem, prop_path)
                    if value is not None:
                        delim = "" if first else ", "
                        result += f"{delim}{to_str(name, value)}"
                        first = False
                return result
            elif is_edge(elem):
                return f'{elem.get("from")} -> {elem.get("to")}'
            else:
                return elem

        def fmt(elem: JsonElement) -> JsonElement:
            return fmt_json(elem) if isinstance(elem, dict) else str(elem)

        return CLIFlow(lambda in_stream: stream.map(in_stream, fmt))


class JobsCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    jobs list
    jobs show <id>
    jobs add [--id <id>] [--schedule <cron_expression>] [--wait-for-event <event_name>] <command_line>
    jobs update <id> [--schedule <cron_expression>] [--wait-for-event <event_name> :] <command_line>
    jobs delete <id>
    jobs activate <id>
    jobs deactivate <id>
    jobs run <id>
    jobs running
    ```

    - `jobs list`: get the list of all jobs in the system
    - `jobs show <id>`: show the current definition of the job defined by given job identifier.
    - `jobs add ...`: add a job to the task handler with provided identifier, trigger and command line to execute.
    - `jobs update <id> ...` : update trigger and or command line of an existing job with provided identifier.
    - `jobs delete <id>`: delete the job with the provided identifier.
    - `jobs activate <id>`: activate the triggers of a job.
    - `jobs deactivate <id>`: deactivate the triggers of a job. The job will not get started in case the trigger fires.
    - `jobs run <id>`: run the job as if the trigger would be triggered.
    - `jobs running`: show all currently running jobs.


    A job can be scheduled, react on events or both:
    - scheduled via a defined cron expression
    - event triggered via defined identifier of event to trigger this job
    - combined scheduled + event trigger once the schedule triggers this job,
      it is possible to wait for an incoming event, before the command line is executed.

    *Note:*

    If a job is triggered, while it is already running, the invocation will wait for the current run to finish.
    This means that there will be no parallel execution of jobs with the same identifier at any moment in time.
    A command line is not allowed to run longer than the specified timeout.
    It is killed in case this timeout is exceeded.

    ## Options
    - `--id` <id> [optional]: The identifier of this job. If no id is defined a random identifier is generated.
    - `--schedule` <cron_expression>  [optional]: defines the recurrent schedule in crontab format.
    - `--wait-for-event` <event_name> [optional]: if defined, the job waits for the specified event to occur.
         If this parameter is defined in combination with a schedule, the schedule has
         to trigger first, before the event will trigger the execution.
    - `--timeout` [optional, default=3600] Number of seconds, the job is allowed to run. In case this timeout is
         exceeded, the job run will be killed.


    ## Parameters
    - `command_line` [mandatory]: the CLI command line that will be executed, when the job is triggered.
       Note: It is recommended to wrap the command line into single quotes or escape all
       CLI terms like pipe or semicolon (| -> \\|).
       Multiple command lines can be defined by separating them via semicolon.


    ## Examples

    ```shell
    # print hello world every minute to the console
    > jobs add --id say-hello --schedule "* * * * *" echo hello world
    Job say-hello added.

    # print all available jobs in the system
    > jobs list
    id: say-hello
    trigger:
      cron_expression: '* * * * *'
    command: echo hello world

    # show a specific job by identifier
    > jobs show say-hello
    id: say-hello
    trigger:
      cron_expression: '* * * * *'
    command: echo hello world

    # every morning at 4: wait for message of type collect_done and print a message
    > jobs add --id early_hi --schedule "0 4 * * *" --wait-for-event collect_done 'match is("volume") | format id'
    Job early_hi added.

    # wait for message of type collect_done and print a message
    > jobs add --id wait_for_collect_done collect_done: echo hello world
    Job wait_for_collect_done added.

    # run the job directly without waiting for a trigger
    > jobs run say-hello
    Job say-hello started with id a4bb64cc-7385-11ec-b2cb-dad780437c53.

    # show all currently running jobs
    > jobs running
    job: say-hello
    started_at: '2022-01-12T09:01:34Z'
    task-id: a4bb64cc-7385-11ec-b2cb-dad780437c53

    # triggers can be activated and deactivated.
    # Deactivated triggers will not trigger the job.
    # The active flag shows the state of activation.
    > jobs deactivate say-hello
    id: say-hello
    command: echo hello world
    active: false
    trigger:
      cron_expression: '* * * * *'

    # activate the triggers of the job.
    > jobs activate say-hello
    id: say-hello
    command: echo hello world
    active: true
    trigger:
      cron_expression: '* * * * *'

    # delete a job
    > jobs delete say-hello
    Job say-hello deleted.
    ```
    """

    @property
    def name(self) -> str:
        return "jobs"

    def info(self) -> str:
        return "Manage all jobs."

    @staticmethod
    def is_jobs_update(command: ParsedCommand) -> bool:
        if command.cmd == "jobs":
            args = re.split("\\s+", command.args, maxsplit=1) if command.args else []
            return len(args) == 2 and args[0] in ("add", "update")
        else:
            return False

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        def job_to_json(job: Job) -> Json:
            wait = {"wait": {"message_type": job.wait[0].message_type}} if job.wait else {}
            trigger = {"trigger": to_js(job.trigger, strip_nulls=True)} if job.trigger else {}
            return {"id": job.id, "command": job.command.command, "active": job.active, **trigger, **wait}

        async def list_jobs() -> Tuple[int, AsyncIterator[JsonElement]]:
            listed = await self.dependencies.job_handler.list_jobs()

            async def iterate() -> AsyncIterator[JsonElement]:
                for job in listed:
                    yield job_to_json(job)

            return len(listed), iterate()

        async def show_job(job_id: str) -> AsyncIterator[JsonElement]:
            matching = [job for job in await self.dependencies.job_handler.list_jobs() if job.name == job_id]
            if matching:
                yield job_to_json(matching[0])
            else:
                yield f"No job with this id: {job_id}"

        async def put_job(arg_str: str) -> AsyncIterator[str]:
            arg_parser = NoExitArgumentParser()
            arg_parser.add_argument("--id", dest="id", default=rnd_str())
            arg_parser.add_argument("--schedule", dest="schedule", type=lambda r: TimeTrigger(strip_quotes(r)))
            arg_parser.add_argument("--wait-for-event", dest="event", type=lambda e: EventTrigger(strip_quotes(e)))
            arg_parser.add_argument(
                "--timeout", dest="timeout", default=timedelta(hours=1), type=lambda t: timedelta(seconds=int(t))
            )
            parsed, rest = arg_parser.parse_known_args(list(args_parts_parser.parse(arg_str)))
            uid = parsed.id
            command = " ".join(rest)
            # only here to make sure the command can be executed
            await self.dependencies.cli.evaluate_cli_command(command, ctx)

            timeout: timedelta = parsed.timeout
            if parsed.schedule and parsed.event:
                wait = (parsed.event, timeout)
                job = Job(uid, ExecuteCommand(command), timeout, parsed.schedule, wait, ctx.env)
            elif parsed.schedule or parsed.event:
                trigger = parsed.schedule or parsed.event
                job = Job(uid, ExecuteCommand(command), timeout, trigger, environment=ctx.env)
            else:
                job = Job(uid, ExecuteCommand(command), timeout, environment=ctx.env)
            await self.dependencies.job_handler.add_job(job)
            yield f"Job {job.id} added."

        async def delete_job(job_id: str) -> AsyncIterator[str]:
            job = await self.dependencies.job_handler.delete_job(job_id)
            yield f"Job {job_id} deleted." if job else f"No job with this id: {job_id}"

        async def run_job(job_id: str) -> AsyncIterator[str]:
            task = await self.dependencies.job_handler.start_task_by_descriptor_id(job_id)
            yield f"Job {task.descriptor.id} started with id {task.id}." if task else f"No job with this id: {job_id}"

        async def activate_deactivate_job(job_id: str, active: bool) -> AsyncIterator[JsonElement]:
            matching = [job for job in await self.dependencies.job_handler.list_jobs() if job.name == job_id]
            if matching:
                m = matching[0]
                if m.trigger is not None:
                    job = Job(m.id, m.command, m.timeout, m.trigger, m.wait, m.environment, m.mutable, active)
                    await self.dependencies.job_handler.add_job(job)
                    yield job_to_json(job)
                else:
                    yield f"Job {job_id} does not have any trigger that could be activated/deactivated."
            else:
                yield f"No job with this id: {job_id}"

        async def running_jobs() -> Tuple[int, Stream]:
            tasks = await self.dependencies.job_handler.running_tasks()
            return len(tasks), stream.iterate(
                {
                    "job": t.descriptor.id,
                    "started_at": to_json(t.task_started_at),
                    "task-id": t.id,
                }
                for t in tasks
                if isinstance(t.descriptor, Job)
            )

        async def show_help() -> AsyncIterator[str]:
            yield self.rendered_help(ctx)

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] in ("add", "update"):
            return CLISource.single(partial(put_job, args[1].strip()))
        elif arg and len(args) == 2 and args[0] == "delete":
            return CLISource.single(partial(delete_job, args[1].strip()))
        elif arg and len(args) == 2 and args[0] == "show":
            return CLISource.single(partial(show_job, args[1].strip()))
        elif arg and len(args) == 2 and args[0] == "run":
            return CLISource.single(partial(run_job, args[1].strip()))
        elif arg and len(args) == 2 and args[0] == "activate":
            return CLISource.single(partial(activate_deactivate_job, args[1].strip(), True))
        elif arg and len(args) == 2 and args[0] == "deactivate":
            return CLISource.single((partial(activate_deactivate_job, args[1].strip(), False)))
        elif arg and len(args) == 2:
            raise CLIParseError(f"Does not understand action {args[0]}. Allowed: add, update, delete.")
        elif arg and len(args) == 1 and args[0] == "running":
            return CLISource(running_jobs)
        elif arg and len(args) == 1 and args[0] == "list":
            return CLISource(list_jobs)
        else:
            return CLISource.single(show_help)


class SendWorkerTaskCommand(CLICommand, ABC):
    # Abstract base for all commands that send task to the work queue

    # this method expects a stream of Tuple[str, Dict[str, str], Json]
    def send_to_queue_stream(
        self,
        in_stream: Stream,
        result_handler: Callable[[WorkerTask, Future[Json]], Awaitable[Json]],
        wait_for_result: bool,
    ) -> Stream:
        async def send_to_queue(task_name: str, task_args: Dict[str, str], data: Json) -> Union[JsonElement]:
            future = asyncio.get_event_loop().create_future()
            task = WorkerTask(uuid_str(), task_name, task_args, data, future, self.timeout())
            # enqueue this task
            await self.dependencies.worker_task_queue.add_task(task)
            # wait for the task result
            result_future = result_handler(task, future)
            if wait_for_result:
                return await result_future
            else:
                result_task: Task[JsonElement] = asyncio.create_task(result_future)
                await self.dependencies.forked_tasks.put((result_task, f"WorkerTask {task_name}:{task.id}"))
                return f"Spawned WorkerTask {task_name}:{task.id}"

        return stream.starmap(in_stream, send_to_queue, ordered=False, task_limit=self.task_limit())

    # noinspection PyMethodMayBeStatic
    def task_limit(self) -> int:
        # override if this limit is not sufficient
        return 100

    cloud_account_region_zone = {
        "cloud": ["ancestors", "cloud", "reported", "id"],
        "account": ["ancestors", "account", "reported", "id"],
        "region": ["ancestors", "region", "reported", "id"],
        "zone": ["ancestors", "zone", "reported", "id"],
    }

    @classmethod
    def carz_from_node(cls, node: Json) -> Json:
        result = {}
        for name, path in cls.cloud_account_region_zone.items():
            value = value_in_path(node, path)
            if value:
                result[name] = value
        return result

    @abstractmethod
    def timeout(self) -> timedelta:
        pass


class TagCommand(SendWorkerTaskCommand):
    """
    ```
    tag update [--nowait] [tag_name new_value]
    tag delete [--nowait] [tag_name]
    ```

    This command can be used to update or delete a specific tag.
    Tags have a name and value - both name and value are strings.

    When this command is issued, the change is done on the cloud resource via the cloud specific provider.
    The change in the graph data itself is reflected with this operation.
    In rare case it might take up to the next collect run.

    When a tag is updated, the new value can be defined as static string or as format string using curly braces.
    All placeholders in a format string are replaced with values from the related resource (see `format` for details).

    After the tag of a resource is updated or deleted the resulting data is provided as output of this command
    and can be used for further chained operations.

    The command would wait for the worker to report the result back synchronously.
    Once the cli command returns, also the tag update/delete is finished.
    If the command should not wait for the result, the action can be performed in background via the `--nowait` flag.

    The input of this command is either a query result or the identifier of the resource as string.

    ## Options
    - `--nowait` if this flag is defined, the cli will send the tag command to the worker
       and will not wait for the task to finish.


    ## Parameters
    - `tag_name` [mandatory]: the name of the tag to change
    - `tag_value` [mandatory]: in case of update: the new value of the tag_name.
       The tag_value can use format templates (`help format`) to define the value with backreferences from the object.
       Example: test_{name}_{kind} -> test_pvc-123_disk

    ## Examples
    ```shell
    # Make sure there is no resource that is tagged with 'foo'
    > query is(resource) and tags.foo!=null | tag delete foo
    kind=aws_ec2_keypair, id=key-0, name=default, age=1yr8mo, cloud=aws, account=eng-sre, region=us-west-2

    # Manually select the resources to tag by using the id.
    > json["key-0"] | tag delete foo
    kind=aws_ec2_keypair, id=key-0, name=default, age=1yr8mo, cloud=aws, account=eng-sre, region=us-west-2

    # Updating a tag by using a format template.
    > query is(volume) and tags.owner == null limit 1 | tag update owner "gen_{/ancestors.account.reported.name}_{name}"
    kind=gcp_disk, id=123, name=gke-1, age=5mo27d, cloud=gcp, account=eng, region=us-central1, zone=us-central1-c
    ```
    """

    @property
    def name(self) -> str:
        return "tag"

    def info(self) -> str:
        return "Update a tag with provided value or delete a tag"

    def timeout(self) -> timedelta:
        return timedelta(seconds=30)

    def load_by_id_merged(self, model: Model, in_stream: Stream, variables: Optional[Set[str]], **env: str) -> Stream:
        async def load_element(items: List[JsonElement]) -> AsyncIterator[JsonElement]:
            # collect ids either from json dict or string
            ids: List[str] = [i["id"] if is_node(i) else i for i in items]  # type: ignore
            # one query to load all items that match given ids (max 1000 as defined in chunk size)
            query = (
                Query.by(P("_key").is_in(ids))
                .merge_with("ancestors.cloud", NavigateUntilRoot, IsTerm(["cloud"]))
                .merge_with("ancestors.account", NavigateUntilRoot, IsTerm(["account"]))
                .merge_with("ancestors.region", NavigateUntilRoot, IsTerm(["region"]))
                .merge_with("ancestors.zone", NavigateUntilRoot, IsTerm(["zone"]))
            ).rewrite_for_ancestors_descendants(variables)
            query_model = QueryModel(query, model)
            async with await self.dependencies.db_access.get_graph_db(env["graph"]).query_list(query_model) as crs:
                async for a in crs:
                    yield a

        return stream.flatmap(stream.chunks(in_stream, 1000), load_element)

    def handle_result(self, model: Model, **env: str) -> Callable[[WorkerTask, Future[Json]], Awaitable[Json]]:
        async def to_result(task: WorkerTask, future_result: Future[Json]) -> Json:
            nid = value_in_path(task.data, ["node", "id"])
            try:
                result = await future_result
                if is_node(result):
                    db = self.dependencies.db_access.get_graph_db(env["graph"])
                    try:
                        updated: Json = await db.update_node(model, result["id"], result, None)
                        return updated
                    except ClientError as ex:
                        # if the change could not be reflected in database, show success
                        log.warning(
                            f"Tag update not reflected in db. Wait until next collector run. Reason: {str(ex)}",
                            exc_info=ex,
                        )
                        return result
                else:
                    log.warning(
                        f"Result from tag worker is not a node. "
                        f"Will not update the internal state. {json.dumps(result)}"
                    )
                    return result
            except Exception as ex:
                return {"error": str(ex), "id": nid}

        return to_result

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        arg_tokens = args_parts_unquoted_parser.parse(arg if arg else "")
        p = NoExitArgumentParser()
        p.add_argument("--nowait", dest="nowait", default=False, action="store_true")
        ns, rest = p.parse_known_args(arg_tokens)
        variables: Optional[Set[str]] = None

        if arg_tokens[0] == "delete" and len(rest) == 2:
            fn: Callable[[Json], Tuple[str, Dict[str, str], Json]] = lambda item: (
                "tag",
                self.carz_from_node(item),
                {"delete": [rest[1]], "node": item},
            )  # noqa: E731
        elif arg_tokens[0] == "update" and len(rest) == 3:
            _, tag, vin = rest
            formatter, variables = ctx.formatter_with_variables(double_quoted_or_simple_string_dp.parse(vin))
            fn = lambda item: (  # noqa: E731
                "tag",
                self.carz_from_node(item),
                {"update": {tag: formatter(item)}, "node": item},
            )
        else:
            raise AttributeError("Expect update tag_key tag_value or delete tag_key")

        def setup_stream(in_stream: Stream) -> Stream:
            def with_dependencies(model: Model) -> Stream:
                load = self.load_by_id_merged(model, in_stream, variables, **ctx.env)
                result_handler = self.handle_result(model, **ctx.env)
                return self.send_to_queue_stream(stream.map(load, fn), result_handler, not ns.nowait)

            # dependencies are not resolved directly (no async function is allowed here)
            dependencies = stream.call(self.dependencies.model_handler.load_model)
            return stream.flatmap(dependencies, with_dependencies)

        return CLIFlow(setup_stream)


class StartTaskCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    start_task <name of task>
    ```

    Start a task with given task descriptor id.

    The configured surpass behaviour of a task definition defines, if multiple tasks of the same task definition
    are allowed to run in parallel.
    In case parallel tasks are forbidden a new task can not be started.
    If a task could be started or not is returned as result message of this command.

    ## Parameters
    - `task_name` [mandatory]:  The name of the related task definition.

    ## Examples
    ```shell
    > start_task example_task
    ```

    See: add_job, delete_job, jobs
    """

    @property
    def name(self) -> str:
        return "start_task"

    def info(self) -> str:
        return "Start a task with the given name."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        async def start_task() -> AsyncIterator[str]:
            if not arg:
                raise CLIParseError("Name of task is not provided")

            task = await self.dependencies.job_handler.start_task_by_descriptor_id(arg)
            yield f"Task {task.id} has been started" if task else "Task can not be started."

        return CLISource.single(start_task)


class FileCommand(CLICommand, InternalPart):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        def file_command() -> Stream:
            if not arg:
                raise AttributeError("file command needs a parameter!")
            elif not os.path.exists(arg):
                raise AttributeError(f"file does not exist: {arg}!")
            else:
                return stream.just(arg if arg else "")

        return CLISource.single(file_command, MediaType.FilePath)

    @property
    def name(self) -> str:
        return "file"

    def info(self) -> str:
        return "only for debugging purposes..."


class UploadCommand(CLICommand, InternalPart):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        if not arg:
            raise AttributeError("upload command needs a parameter!")
        file_id = "file"

        def upload_command() -> Stream:
            if file_id in ctx.uploaded_files:
                file = ctx.uploaded_files[file_id]
                return stream.just(f"Received file {file} of size {os.path.getsize(file)}")
            else:
                raise AttributeError(f"file was not uploaded: {arg}!")

        return CLISource.single(upload_command, MediaType.Json, [CLIFileRequirement(file_id, arg)])

    @property
    def name(self) -> str:
        return "upload"

    def info(self) -> str:
        return "only for debugging purposes..."


class SystemCommand(CLICommand, PreserveOutputFormat):
    """
    ```
    system backup create [name]
    system backup restore <path>
    system info
    ```

    ## Parameters
    - `name` [optional] - the file name of the backup that is created. If no name is provided,
      a new name is created by using the current time and this format: `backup_yyyyMMdd_hmm`.
      Example: backup_20211022_1028
    - `path` [mandatory] - path to the local backup file.


    ## Backup creation

    Create a system backup for the complete database, which contains:
    - backup of all graph data
    - backup of all model data
    - backup of all persisted jobs/tasks data
    - backup of all subscribers data
    - backup of all configuration data

    This backup can be restored via `system backup restore <path>`.
    Since this command creates a complete backup, it can be restored to an empty database.

    *Note*: a backup acquires a global write lock. This basically means, that *no write* can be
    performed, while the backup is created! The backup is not encrypted.


    ## Restore a backup

    The complete database state from a previously generated backup can be restored.
    All existing data in the database will be overwritten.
    This command will not wipe any existing data: if there are collections in the database, that are not included
    in the backup, it will not be deleted by this process.
    In order to restore exactly the same state as in the backup, you should start from an empty database.

    *Note*: a backup acquires a global write lock. This basically means, that *no write* can be
    performed, while the backup is restored! After the restore process is done,
    the resotocore process will stop. It should be restarted by the process supervisor automatically.
    The restart is necessary to take effect from the changed underlying data source.


    ## System information

    Prints information about the currently running system.


    ## Examples
    ```shell
    # Create a backup. The name of the backup will have the current time.
    > system backup create
    Received a file backup_20220202_1121, which is stored to ./backup_20220202_1121.

    # Create a backup and provide a name for it
    > system backup create bck_1234
    Received a file bck_1234, which is stored to ./bck_1234.

    # Restore a backup. This will stop the running resotocore instance.
    > system backup restore bck_1234
    Database has been restored successfully!
    Since all data has changed in the database eventually, this service needs to be restarted!

    # Show system information.
    > system info
    name: resotocore
    version: 2.0.0a14
    cpus: 8
    mem_available: 2.85 GiB
    mem_total: 16.00 GiB
    inside_docker: false
    started_at: '2022-02-02T11:23:19Z'
    ```
    """

    @property
    def name(self) -> str:
        return "system"

    def info(self) -> str:
        return "Access and manage system wide properties."

    async def create_backup(self, arg: Optional[str]) -> AsyncIterator[str]:
        temp_dir: str = tempfile.mkdtemp()
        maybe_proc: Optional[Process] = None
        try:
            args = self.dependencies.args
            if not shutil.which("arangodump"):
                raise CLIParseError("db_backup expects the executable `arangodump` to be in path!")
            # fmt: off
            process = await asyncio.create_subprocess_exec(
                "arangodump",
                "--progress", "false",  # do not show progress
                "--threads", "8",  # default is 2
                "--log.level", "error",  # only print error messages
                "--output-directory", temp_dir,  # directory to write to
                "--overwrite", "true",  # required for existing directories
                "--server.endpoint", args.graphdb_server.replace("http", "http+tcp"),
                "--server.authentication", "false" if args.graphdb_no_ssl_verify else "true",
                "--server.database", args.graphdb_database,
                "--server.username", args.graphdb_username,
                "--server.password", args.graphdb_password,
                "--configuration", "none",
                stderr=asyncio.subprocess.PIPE,
            )
            # fmt: on
            _, stderr = await process.communicate()
            maybe_proc = process
            code = await process.wait()
            if code == 0:
                files = os.listdir(temp_dir)
                name = re.sub("[^a-zA-Z0-9_\\-.]", "_", arg) if arg else f'backup_{utc().strftime("%Y%m%d_%H%M")}'
                backup = os.path.join(temp_dir, name)
                # create an unzipped tarfile (all of the entries are already gzipped)
                with tarfile.open(backup, "w") as tar:
                    for file in files:
                        await run_async(tar.add, os.path.join(temp_dir, file), file)
                yield backup
            else:
                raise CLIExecutionError(f"Creation of backup failed! Response from process:\n{stderr.decode()}")
        finally:
            if maybe_proc and maybe_proc.returncode is None:
                with suppress(Exception):
                    maybe_proc.kill()
                    await asyncio.sleep(5)
            shutil.rmtree(temp_dir)

    async def restore_backup(self, backup_file: Optional[str], ctx: CLIContext) -> AsyncIterator[str]:
        if not backup_file:
            raise CLIExecutionError(f"No backup file defined: {backup_file}")
        if not os.path.exists(backup_file):
            raise CLIExecutionError(f"Provided backup file does not exist: {backup_file}")
        if not shutil.which("arangorestore"):
            raise CLIParseError("db_restore expects the executable `arangorestore` to be in path!")

        temp_dir: str = tempfile.mkdtemp()
        maybe_proc: Optional[Process] = None
        try:
            # extract tar file
            with tarfile.open(backup_file, "r") as tar:
                tar.extractall(temp_dir)

            # fmt: off
            args = self.dependencies.args
            process = await asyncio.create_subprocess_exec(
                "arangorestore",
                "--progress", "false",  # do not show progress
                "--threads", "8",  # default is 2
                "--log.level", "error",  # only print error messages
                "--input-directory", temp_dir,  # directory to write to
                "--overwrite", "true",  # required for existing db collections
                "--server.endpoint", args.graphdb_server.replace("http", "http+tcp"),
                "--server.authentication", "false" if args.graphdb_no_ssl_verify else "true",
                "--server.database", args.graphdb_database,
                "--server.username", args.graphdb_username,
                "--server.password", args.graphdb_password,
                "--configuration", "none",
                stderr=asyncio.subprocess.PIPE,
            )
            # fmt: on
            _, stderr = await process.communicate()
            maybe_proc = process
            code = await process.wait()
            if code == 0:
                yield "Database has been restored successfully!"
            else:
                raise CLIExecutionError(f"Restore of backup failed! Response from process:\n{stderr.decode()}")
        finally:
            if maybe_proc and maybe_proc.returncode is None:
                with suppress(Exception):
                    maybe_proc.kill()
                    await asyncio.sleep(5)
            shutil.rmtree(temp_dir)
            log.info("Restore process complete. Restart the service.")
            yield "Since all data has changed in the database eventually, this service needs to be restarted!"
            # for testing purposes, we can avoid sys exit
            if str(ctx.env.get("BACKUP_NO_SYS_EXIT", "false")).lower() != "true":

                async def wait_and_exit() -> None:
                    log.info("Database was restored successfully - going to STOP the service!")
                    await asyncio.sleep(1)
                    shutdown_process(0)

                # create a background task, so that the current request can be executed completely
                asyncio.create_task(wait_and_exit())

    @staticmethod
    async def show_system_info() -> AsyncIterator[Json]:
        info = to_js(system_info())
        yield {**{"name": "resotocore"}, **info}

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        parts = re.split(r"\s+", arg if arg else "")
        if len(parts) >= 2 and parts[0] == "backup" and parts[1] == "create":
            rest = parts[2:]

            def backup() -> AsyncIterator[str]:
                return self.create_backup(" ".join(rest) if rest else None)

            return CLISource.single(backup, MediaType.FilePath)

        elif len(parts) == 3 and parts[0] == "backup" and parts[1] == "restore":
            backup_file = parts[2]

            def restore() -> AsyncIterator[str]:
                return self.restore_backup(ctx.uploaded_files.get("backup"), ctx)

            return CLISource.single(restore, MediaType.Json, [CLIFileRequirement("backup", backup_file)])
        elif len(parts) == 1 and parts[0] == "info":
            return CLISource.single(self.show_system_info)
        else:
            raise CLIParseError(f"system: Can not parse {arg}")


class WriteCommand(CLICommand):
    """
    ```shell
    write <file-name>
    ```

    Writes the result of this command to a file with given name.

    ## Parameters
    - `file-name` [mandatory]:  The name of the file to write to.

    ## Examples
    ```shell
    # Select 3 resources, format them as json and write it to the file out.json.
    > query all limit 3 | format --json | write out.json
    Received a file out.json, which is stored to ./out.json.

    # Select the root node and traverse 2 levels deep. Format the result as dot graph and write it to out.dot.
    > query --include-edges id(root) -[0:2]-> | format --dot | write out.dot
    Received a file out.dot, which is stored to ./out.dot.
    ```
    """

    @property
    def name(self) -> str:
        return "write"

    def info(self) -> str:
        return "Writes the incoming stream of data to a file in the defined format."

    @staticmethod
    async def write_result_to_file(in_stream: Stream, file_name: str) -> AsyncIterator[str]:
        temp_dir: str = tempfile.mkdtemp()
        path = os.path.join(temp_dir, file_name)
        try:
            async with aiofiles.open(path, "w") as f:
                async with in_stream.stream() as streamer:
                    async for out in streamer:
                        if isinstance(out, str):
                            await f.write(out)
                        else:
                            raise AttributeError("No output format is defined! Consider to use the format command.")
            yield path
        finally:
            shutil.rmtree(temp_dir)

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        if arg is None:
            raise AttributeError("write requires a filename to write to")
        defined_arg: str = arg
        return CLIFlow(lambda in_stream: self.write_result_to_file(in_stream, defined_arg), MediaType.FilePath)


class TemplatesCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    templates
    templates <name_of_template>
    templates add <name_of_template> <query_template>
    templates update <name_of_template> <query_template>
    templates delete <name_of_template>
    templates test key1=value1, key2=value2, ..., keyN=valueN <template_to_expand>
    ```

    - `templates: get the list of all templates
    - `templates <name>`: get the current definition of the template defined by given template name
    - `templates add <name> <template>`: add a query template to the query template library under given name.
    - `templates update <name> <template>`: update a query template in the query template library.
    - `templates delete <name>`: delete the query template with given name.
    - `templates test k=v <template_to_expand>`: test the defined template.

    Placeholders are defined in 2 double curly braces {{placeholder}}
    and get replaced by the provided placeholder value during render_console time.
    The name of the placeholder can be any valid alphanumeric string.
    The template 'is({{kind}})' with expand parameters kind=volume becomes
    'is(volume)' during expand time.

    ## Parameters

    - `name_of_template`:  The name of the query template.
    - `query_template`:  The query with template placeholders.
    - `key=value`: any number of key/value pairs separated by comma

    ## Examples
    ```shell
    # Test a template by populating it with provided key/value pairs
    > templates test kind=volume is({{kind}})
    is(volume)

    # Add a very simple template with name filter_kind to the query library
    > templates add filter_kind is({{kind}})
    Template filter_kind added to the query library.
    is({{kind}})

    # List all templates in the query library
    > templates
    filter_kind: is({{kind}})

    # Show one specific template by provided name
    > templates filter_kind
    is({{kind}})

    # Use this template in a query
    > query expand(filter_kind, kind=volume) and name=~dkl
    kind=aws_ec2_volume, id=vol-1, name=dkl-3, age=2mo2d, cloud=aws, account=eng, region=us-west-2

    > templates delete filter_kind
    Template filter_kind deleted from the query library.
    ```
    """

    @property
    def name(self) -> str:
        return "templates"

    def info(self) -> str:
        return "Access the query template library."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        def template_str(template: Template) -> str:
            tpl_str = f"{template.template[0:70]}..." if len(template.template) > 70 else template.template
            return f"{template.name}: {tpl_str}"

        async def get_template(name: str) -> AsyncIterator[JsonElement]:
            maybe_template = await self.dependencies.template_expander.get_template(name)
            yield maybe_template.template if maybe_template else f"No template with this name: {name}"

        async def list_templates() -> Tuple[Optional[int], AsyncIterator[Json]]:
            templates = await self.dependencies.template_expander.list_templates()
            return len(templates), stream.iterate(template_str(t) for t in templates)

        async def put_template(name: str, template_query: str) -> AsyncIterator[str]:
            # try to render_console the template with dummy values and see if the query can be parsed
            try:
                rendered_query = self.dependencies.template_expander.render(template_query, defaultdict(lambda: True))
                parse_query(rendered_query, **ctx.env)
            except Exception as ex:
                raise CLIParseError(f"Given template does not define a valid query: {template_query}") from ex
            await self.dependencies.template_expander.put_template(Template(name, template_query))
            yield f"Template {name} added to the query library.\n{template_query}"

        async def delete_template(name: str) -> AsyncIterator[str]:
            await self.dependencies.template_expander.delete_template(name)
            yield f"Template {name} deleted from the query library."

        async def expand_template(spec: str) -> AsyncIterator[str]:
            maybe_dict, template = tpl_props_p.parse_partial(spec)
            yield self.dependencies.template_expander.render(template, maybe_dict if maybe_dict else {})

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] in ("add", "update"):
            nm, tpl = re.split("\\s+", args[1], maxsplit=1)
            return CLISource.single(partial(put_template, nm.strip(), tpl.strip()))
        elif arg and len(args) == 2 and args[0] == "delete":
            return CLISource.single(partial(delete_template, args[1].strip()))
        elif arg and len(args) == 2 and args[0] == "test":
            return CLISource.single(partial(expand_template, args[1].strip()))
        elif arg and len(args) == 2:
            raise CLIParseError(f"Does not understand action {args[0]}. Allowed: add, update, delete, test.")
        elif arg and len(args) == 1:
            return CLISource.single(partial(get_template, arg.strip()))
        elif not arg:
            return CLISource(list_templates)
        else:
            raise CLIParseError(f"Can not parse arguments: {arg}")


@dataclass
class HttpRequestTemplate:
    method: str
    url: str
    headers: Dict[str, str]
    params: Dict[str, str]
    retries: int
    backoff_base: float
    timeout: ClientTimeout
    compress: bool
    no_ssl_verify: bool
    no_body: bool


class HttpCommand(CLICommand):
    """
    ```shell
    http[s] [--compress] [--timeout <seconds>] [--no-ssl-verify] [--no-body] [--nr-of-retries <num>]
            [http_method] <url> [headers] [query_params]
    ```

    This command takes every object from the incoming stream and sends this object to the defined http(s) endpoint.
    The payload of the request contains the object.
    The shape and format of the object can be adjusted with other commands like: list, format, jq, etc.
    Note: you can use the chunk command to send chunks of objects.
          E.g.: query is(volume) limit 30 | chunk 10 | http test.foo.org
                will perform up to 3 requests, where every request will contain up to 10 elements.

    ## Options
    - `--compress` [optional]: enable compression of the request body
    - `--timeout` <seconds> [optional, default: 30]: if the request takes longer than the specified seconds
      it will be aborted
    - `--no-ssl-verify` [optional]: the ssl certificate will not be verified.
    - `--no-body` [optional]: if this flag is enabled, no content is sent in the request body
    - `--nr-of-retries` [optional, default=3]: in case the request is not successful (no 2xx), the request
      is retried this often. There will be an exponential backoff between the retries.

    ## Parameters
    - `http_method` [optional, default: POST]: one of GET, PUT, POST, DELETE or PATCH
    - `url`: the full url of the endpoint to call. Example: https://localhost:8080/call/me
      If the scheme is not defined, it is taken from the command (http or https).
      If the host is localhost, it can be omitted (e.g. :8080/call/me)
    - `headers`: a list of http headers can be defined via <header_name>:<header_value>
      Example: HeaderA:test HeaderB:rest
      Note: You can use quotes to use whitespace chars: "HeaderC:this is the value"
    - `query_params`: a list of query parameters can be defined via <param>==<param_value>.
      Example: param1==test param2==rest
      Note: You can use quotes to use whitespace chars: "param3==this is the value"


    ## Examples
    ```shell
    # Look for unencrypted volumes and report them to the specified endpoint
    > query is(volume) and reported.volume_encrypted==false | https my.node.org/handle_unencrypted
    3 requests with status 200 sent.

    # Query all volumes and send chunks of 50 volumes per request to the specified handler
    > query is(volume) | chunk 50 | https --compress my.node.org/handle
    2 requests with status 200 sent.

    # Same query as before, but define special header values and query parameter
    > query is(volume) | chunk 50 | https my.node.org/handle "greeting:hello from resotocore" type==volume
    2 requests with status 200 sent.
    ```
    """

    @property
    def name(self) -> str:
        return "http"

    def info(self) -> str:
        return "Perform http request with incoming data"

    default_timeout = ClientTimeout(total=30)
    colon_port = re.compile("^:(\\d+)(.*)$")
    allowed_methods = {"GET", "PUT", "POST", "DELETE", "PATCH"}

    @classmethod
    def parse_args(cls, scheme: str, arg: Optional[str]) -> HttpRequestTemplate:
        def parse_timeout(time_str: str) -> ClientTimeout:
            return ClientTimeout(int(time_str))

        def parse_method(remaining_args: List[str]) -> Tuple[str, List[str]]:
            if remaining_args[0].upper() in cls.allowed_methods:
                return remaining_args[0].upper(), remaining_args[1:]
            else:
                return "POST", remaining_args

        def parse_url(remaining_args: List[str]) -> Tuple[str, List[str]]:
            url = urlparse(remaining_args[0])
            # fix shorthand notation
            if url.scheme and not url.scheme.startswith("http") and not url.netloc:
                url = urlparse(f"{scheme}://{remaining_args[0]}")
            elif not url.scheme and not url.netloc and url.path.startswith("://"):
                url = urlparse(scheme + remaining_args[0])
            elif not url.scheme and not url.netloc and cls.colon_port.match(url.path):
                url = urlparse(f"{scheme}://localhost{remaining_args[0]}")
            elif not url.scheme and not url.netloc:
                url = urlparse(f"{scheme}://{remaining_args[0]}")

            assert url.scheme in ["http", "https"], f"Only http and https is allowed as scheme. Got: {url}"
            return urlunparse(url), remaining_args[1:]

        def parse_header_query_params(remaining_args: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
            headers = {}
            params = {}
            for prop in remaining_args:
                prop = strip_quotes(prop)
                if ":" in prop:
                    k, v = re.split("\\s*:\\s*", prop, 1)
                    headers[k] = v
                elif "==" in prop:
                    k, v = re.split("\\s*==\\s*", prop, 1)
                    params[k] = v
                else:
                    raise AttributeError(f"Can not parse: >{prop}<")
            return headers, params

        arg_parser = NoExitArgumentParser(allow_abbrev=True)
        arg_parser.add_argument("--compress", dest="compress", default=False, action="store_true")
        arg_parser.add_argument("--backoff-base", dest="backoff_base", default=0.5, type=float)
        arg_parser.add_argument("--nr-of-retries", dest="retries", default=3, type=int)
        arg_parser.add_argument("--timeout", dest="timeout", default=cls.default_timeout, type=parse_timeout)
        arg_parser.add_argument("--no-ssl-verify", dest="no_ssl_verify", default=False, action="store_true")
        arg_parser.add_argument("--no-body", dest="no_body", default=False, action="store_true")
        args, remaining = arg_parser.parse_known_args(args_parts_unquoted_parser.parse(arg.strip()) if arg else [])
        if remaining:
            method, remaining = parse_method(remaining)
            parsed_url, remaining = parse_url(remaining)
            hdr, prm = parse_header_query_params(remaining)
            return HttpRequestTemplate(
                method,
                parsed_url,
                hdr,
                prm,
                args.retries,
                args.backoff_base,
                args.timeout,
                args.compress,
                args.no_ssl_verify,
                args.no_body,
            )
        else:
            raise AttributeError("No URL provided to connect to.")

    def perform_requests(self, template: HttpRequestTemplate) -> Callable[[Stream], AsyncIterator[JsonElement]]:
        retries_left = template.retries

        async def perform_request(e: JsonElement) -> int:
            nonlocal retries_left
            data = None if template.no_body else (JsonPayload(e) if isinstance(e, dict) else e)
            log.debug(f"Perform request with this template={template} and data={data}")
            try:
                async with self.dependencies.http_session.request(
                    template.method,
                    template.url,
                    headers=template.headers,
                    params=template.params,
                    data=data,
                    compress=template.compress,
                    timeout=template.timeout,
                    ssl=not template.no_ssl_verify,
                ) as response:
                    log.debug(f"Request performed: {response}")
                    if (200 <= response.status < 400) or retries_left == 0:
                        return response.status
                    else:
                        err_context = f"status={response.status} and message {await response.text()}"
            except Exception as ex:
                err_context = f"exception={ex}"

            retries_left -= 1
            sleep_time = template.backoff_base * pow(2, (template.retries - retries_left))
            log.warning(
                f"Request to {template.method} {template.url} failed. "
                f"Reason: {err_context} Retry in {sleep_time} seconds."
            )
            if retries_left >= 0:
                await asyncio.sleep(sleep_time)
                return await perform_request(e)
            else:
                # define exceptions as server error
                return 500

        async def iterate_stream(in_stream: Stream) -> AsyncIterator[JsonElement]:
            results: Dict[int, int] = defaultdict(lambda: 0)
            async with in_stream.stream() as streamer:
                async for elem in streamer:
                    status_code = await perform_request(elem)
                    results[status_code] += 1
            summary = ", ".join(f"{count} requests with status {status}" for status, count in results.items())
            yield f"{summary} sent."

        return iterate_stream

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        # command name is the default scheme: http, https etc.
        default_scheme = kwargs.get("cmd_name", "http")
        template = self.parse_args(default_scheme, arg)
        return CLIFlow(self.perform_requests(template))


def all_commands(d: CLIDependencies) -> List[CLICommand]:
    commands = [
        AggregatePart(d),
        AggregateToCountCommand(d),
        AncestorPart(d),
        ChunkCommand(d),
        CleanCommand(d),
        CountCommand(d),
        DescendantPart(d),
        DumpCommand(d),
        EchoCommand(d),
        EnvCommand(d),
        ExecuteQueryCommand(d),
        FlattenCommand(d),
        FormatCommand(d),
        HeadCommand(d),
        HttpCommand(d),
        JobsCommand(d),
        JqCommand(d),
        JsonCommand(d),
        KindCommand(d),
        ListCommand(d),
        TemplatesCommand(d),
        PredecessorPart(d),
        ProtectCommand(d),
        QueryAllPart(d),
        SetDesiredCommand(d),
        SetMetadataCommand(d),
        SleepCommand(d),
        StartTaskCommand(d),
        SuccessorPart(d),
        SystemCommand(d),
        TagCommand(d),
        TailCommand(d),
        UniqCommand(d),
        WriteCommand(d),
    ]
    # commands that are only available when the system is started in debug mode
    if d.args.debug:
        commands.extend([FileCommand(d), UploadCommand(d)])

    return commands


def aliases() -> Dict[str, str]:
    # command alias -> command name
    return {"match": "query", "start_workflow": "start_task", "https": "http"}
