from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os.path
import re
import shutil
import tarfile
from abc import abstractmethod, ABC
from argparse import Namespace
from asyncio import Future, Task

# noinspection PyProtectedMember
from asyncio.subprocess import Process
from collections import defaultdict
from contextlib import suppress
from datetime import timedelta, datetime
from functools import partial, lru_cache
from itertools import dropwhile, chain
from pathlib import Path
from typing import (
    Dict,
    List,
    Tuple,
    Optional,
    Any,
    AsyncIterator,
    Hashable,
    Iterable,
    Callable,
    Awaitable,
    cast,
    Set,
    FrozenSet,
    Union,
    TYPE_CHECKING,
    Iterator,
)
from urllib.parse import urlparse, urlunparse

import aiofiles
import jq
import yaml
from aiofiles.tempfile import TemporaryDirectory
from aiohttp import ClientTimeout, JsonPayload, BasicAuth
from aiostream import stream, pipe
from aiostream.aiter_utils import is_async_iterable
from aiostream.core import Stream
from attr import evolve, frozen
from attrs import define, field
from dateutil import parser as date_parser
from detect_secrets.core import scan, plugins
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.settings import configure_settings_from_baseline, default_settings
from parsy import Parser, string, ParseError
from fixclient.models import Model as RCModel, Kind as RCKind
from fixcore import version
from fixcore.async_extensions import run_async
from fixcore.cli import (
    JsGen,
    NoExitArgumentParser,
    args_parts_parser,
    args_parts_unquoted_parser,
    is_edge,
    is_node,
    get_node,
    js_value_at,
    key_values_parser,
    parse_time_or_delta,
    strip_quotes,
    key_value_parser,
    JsStream,
    js_value_get,
)
from fixcore.cli.model import (
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
    ParsedCommand,
    NoTerminalOutput,
    ArgsInfo,
    ArgInfo,
    EntityProvider,
    FilePath,
    CLISourceContext,
)
from fixcore.cli.tip_of_the_day import SuggestionPolicy, SuggestionStrategy, get_suggestion_strategy
from fixcore.config import ConfigEntity
from fixcore.db.async_arangodb import AsyncCursor
from fixcore.db.graphdb import HistoryChange, GraphDB
from fixcore.db.model import QueryModel
from fixcore.db.runningtaskdb import RunningTaskData
from fixcore.error import CLIParseError, ClientError, CLIExecutionError, NotEnoughPermissions
from fixcore.ids import ConfigId, TaskId, InfraAppName, TaskDescriptorId, GraphName, Email, Password
from fixcore.infra_apps.manifest import AppManifest
from fixcore.infra_apps.package_manager import Failure
from fixcore.model.graph_access import Section, EdgeTypes
from fixcore.model.model import (
    Model,
    Kind,
    ComplexKind,
    DictionaryKind,
    SimpleKind,
    Property,
    ArrayKind,
    PropertyPath,
    TransformKind,
    EmptyPath,
    any_kind,
    string_kind,
    double_kind,
)
from fixcore.model.resolve_in_graph import NodePath
from fixcore.model.typed_model import to_json, to_js, from_js
from fixcore.query.model import (
    Query,
    P,
    Template,
    NavigateUntilRoot,
    Term,
    AggregateFunction,
    AggregateVariableName,
    AggregateVariableCombined,
    Aggregate,
    AggregateVariable,
    Part,
    NavigateUntilLeaf,
    IsTerm,
)
from fixcore.query.query_parser import parse_query, aggregate_parameter_parser, predicate_term
from fixcore.query.template_expander import tpl_props_p
from fixcore.report import ReportSeverity
from fixcore.report.benchmark_renderer import respond_benchmark_result
from fixcore.report.report_config import BenchmarkConfig
from fixcore.system_start import system_info
from fixcore.task.task_description import Job, TimeTrigger, EventTrigger, ExecuteCommand, Workflow, RunningTask
from fixcore.types import Json, JsonElement, EdgeType
from fixcore.user import FixInventoryUser
from fixcore.user.model import Permission, AllowedRoleNames
from fixcore.util import (
    uuid_str,
    utc,
    if_set,
    duration,
    identity,
    rnd_str,
    set_value_in_path,
    restart_service,
    combine_optional,
    value_in_path,
)
from fixcore.web.content_renderer import (
    respond_ndjson,
    respond_json,
    respond_text,
    respond_graphml,
    respond_dot,
    respond_yaml,
    respond_cytoscape,
)
from fixcore.worker_task_queue import WorkerTask, WorkerTaskName
from fixdatalink import EngineConfig
from fixdatalink.batch_stream import BatchStream
from fixdatalink.collect_plugins import update_sql
from fixlib.core import CLIEnvelope
from fixlib.durations import parse_duration
from fixlib.parse_util import (
    double_quoted_or_simple_string_dp,
    space_dp,
    make_parser,
    variable_dp,
    literal_dp,
    comma_p,
    variable_p,
    equals_p,
    json_value_p,
)
from fixlib.utils import safe_members_in_tarfile, get_local_tzinfo
from fixlib.x509 import write_cert_to_file, write_key_to_file
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from fixcore.dependencies import TenantDependencies

log = logging.getLogger(__name__)


# A SearchCLIPart is a command that can be used on the command line.
# Such a part is not executed, but builds a search, which is executed.
# Therefore, the parse method is implemented in a dummy fashion here.
# The real interpretation happens in CLI.create_query.
class SearchCLIPart(CLICommand, EntityProvider, ABC):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        return CLISource.empty()


class SearchPart(SearchCLIPart):
    """

    ```shell
    search [--with-edges] [--explain] <search-statement>
    ```

    This command allows to search the graph using filters, traversals, functions and aggregates.

    ## Options

    - `--with-edges`: Return edges in addition to nodes.
    - `--explain`: Instead of executing the search, analyze its cost.
    - `--at <time|delta>`: Perform search on the snapshot of a graph just before the given time.

    ## Parameters

    - `search-statement` [mandatory]: The search to execute.


    ### Filters

    Filters have the form `path op value`.
    - `path` is the complete path of names in the json structure combined with a dot (e.g. reported.cpu_count).

      In case the path contains elements, that are not json conform,
      they can be put into backticks (e.g. foo.bla.\\`:-)\\`.baz).
    - `operator` is one of: `<=`, `>=`, `>`, `<`, `==`, `!=`, `=~`, `!~`, `in`, `not in`.

      Note:  `=` is the same as `==` and `~` is the same as `=~`.
    - value is a json literal (e.g. `"test"`, `23`, `[1, 2, 3]`, `true`, `{"a": 12}`).

      Note: the search statement allows to omit the parentheses for strings most of the time.
      In case it contains whitespace or a special characters, you should put the string into parentheses.

    Example:
    ```shell
    > search reported.cpu_count >= 4
    > search name!="test"
    > search title in ["first", "second"]
    > search some_array[3].test.number > 6
    > search some_array[*].test.number < 4
    ```

    Filters can be combined with `and` and `or` and use parentheses.
    Example:
    ```shell
    > search (cpu_count>=4 and name!="test") or (title in ["first", "second"] and name=="test")
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
    > search aggregate(kind: sum(1)): is(volume)
    > search aggregate(kind as kind: sum(1) as count): is(volume)
    > search aggregate(kind, volume_type: sum(1) as count): is(volume)
    > search aggregate(kind: sum(volume_size) as summed, sum(1) as count): is(volume)
    > search aggregate(sum(volume_size) as summed, sum(1) as count): is(volume)
    ```

    ### Sort and Limit

    The number of search results can be limited to a defined number by using limit <limit>
    and sorted by using sort <sort_column> [asc, desc].
    Limit and sort is allowed before a traversal and as last statement to the search result.
    Example:
    ```
    > search is(volume) sort volume_size desc limit 3 <-[2]- sort name limit 1
    ```

    Use --explain to understand the cost of a search. A search explanation has this form (example):

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
    - `estimated_cost shows` the absolute cost of this search. See rating for an interpreted number.
    - `estimated_nr_items` estimated number of items returned for this search.
       It is computed based on search statistics and heuristics and does not reflect the real number.
    - `full_collection_scan` indicates, if a full collection scan is required.
       In case this is true, the search does not take advantage of any indexes.
    - `rating` The more general rating of this search.
       Simple: The estimated cost is fine - the search will most probably run smoothly.
       Complex: The estimated cost is quite high. Check other properties. Maybe an index can be used?
       Bad: The estimated cost is very high. It will most probably run long and/or will take a lot of resources.


    ## Examples

    ```shell
    # Search all volumes with state available
    > search is(volume) and volume_status=available
    kind=gcp_disk, id=71, name=gke-1, volume_status=available, age=5mo26d, cloud=gcp, account=dev, region=us-central1
    kind=gcp_disk, id=12, name=pvc-2, volume_status=available, age=4mo15d, cloud=gcp, account=eng, region=us-west1
    kind=gcp_disk, id=17, name=pvc-2, volume_status=available, age=9mo29d, cloud=gcp, account=eng, region=us-west1

    # Other sections than reported, need to be defined from the root /
    > search is(volume) and /desired.cleanup=true

    # Sort and limit the number of results
    > search is(volume) sort name asc limit 3
    kind=aws_ec2_volume, id=vol-1, name=adf-image-1, age=2mo1d, cloud=aws, account=general-support, region=us-west-2
    kind=aws_ec2_volume, id=vol-2, name=adf-image-2, age=2mo1d, cloud=aws, account=general-support, region=us-west-2

    # Emit nodes together with the edges
    > search --with-edges id(root) -[0:1]->
    node_id=root, kind=graph_root, id=root, name=root
    node_id=L_tRxI2tn6iLZdK3e8EQ3w, kind=cloud, id=gcp, name=gcp, age=5d5h, cloud=gcp
    root -> L_tRxI2tn6iLZdK3e8EQ3w
    node_id=WYcfqyMIkPAPoAHiEIIKOw, kind=cloud, id=aws, name=aws, age=5d5h, cloud=aws
    root -> WYcfqyMIkPAPoAHiEIIKOw

    # Aggregate resulting nodes
    > search aggregate(kind as kind: sum(1) as count): is(volume)
    group:
      kind: aws_ec2_volume
    count: 1799
    ---
    group:
      kind: gcp_disk
    count: 1100

    # Do not execute the search, but show an explanation of the search cost.
    > search --explain is(graph_root) -[0:1]->
    available_nr_items: 142670
    estimated_cost: 58569
    estimated_nr_items: 8
    full_collection_scan: false
    rating: simple

    # Search all volumes on a snapshot from the past
    > search --at 2023-05-07T12:34:56Z is(volume)
    > search --at 1w is(volume)
    ```

    ## Environment Variables

    - `graph` [default=fix]: the name of the graph to operate on.
    - `section` [default=reported]: interpret all property paths with respect to this section.
       With section `reported` set, the search `name=~"test"` would be interpreted as `reported.name=~"test"`.
       Note: the fixshell sets the section to reported by default.
       If you want to quickly override the section on one command line, you can define env vars in from of the
       command line (e.g.: `section=desired search clean==true`). It is possible to use absolute path using `/`,
       so all paths have to be defined from root (e.g.: `search desired.clean==true`)

    See [https://inventory.fix.security/docs](https://inventory.fix.security/docs) for detailed explanation of search.
    """

    @property
    def name(self) -> str:
        return "search"

    def info(self) -> str:
        return "Search the graph."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo(expects_value=True, value_hint="search"),
            ArgInfo("--with-edges", help_text="include edges in result"),
            ArgInfo("--at", help_text="timestamp | timedelta"),
        ]


class HistoryPart(SearchCLIPart):
    """
    ```shell
    history [--before <time|delta>] [--after <time|delta>] [--change <change>] [search-statement]
    ```

    Return all changes of the graph based on the given criteria.

    Whenever changes are given to Fix, a dedicated change event is written as separate entity.
    Following changes are supported:
    - node_created: a node is added to the graph that has not been seen before.
    - node_updated: a node is delivered and is different to the one in the graph.
    - node_deleted: a node is no longer reported and gets deleted from the graph.

    ## Options
    - `--before` <time|delta>: only show changes before this timestamp or timedelta.
    - `--after` <time|delta>: only show changes after this timestamp or timedelta.
    - `--change` <change>: one of `node_created`, `node_deleted`, `node_updated`

    ## Parameters
    - `search-statement`: a search statement to filter the history

    ## Examples
    ```shell
    # Show all nodes changed in the last hour
    > history --after 1h
    change=node_updated, changed_at=2022-01-01T03:00:59Z, kind=kubernetes_config_map, id=73616434 name=leader, cloud=k8s
    change=node_deleted, changed_at=2022-01-01T04:40:59Z, kind=aws_vpc, id=vpc-1, name=fix-eks, cloud=aws

    # Show all nodes created on 1.1.2022 between 03:00 and 06:00 (UTC)
    > history --change node_created --after 2022-01-01T03:00:00Z --before 2022-01-02T06:00:00Z
    change=node_created, changed_at=2022-01-01T05:40:59Z, kind=aws_iam_role, id=AROA, name=some-role, cloud=aws

    # Show all changes to kubernetes resources in the kube-system namespace
    > history is(kubernetes_resource) and namespace=kube-system
    change=node_created, changed_at=2022-11-18T12:00:49Z, kind=kubernetes_role, name=eks, namespace=kube-system
    change=node_updated, changed_at=2022-11-18T12:00:50Z, kind=kubernetes_config_map, name=cert, namespace=kube-system
    ```
    """

    @property
    def name(self) -> str:
        return "history"

    def info(self) -> str:
        return "Search the history of nodes."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--after", help_text="timestamp | timedelta", expects_value=True, value_hint="timestamp"),
            ArgInfo("--before", help_text="timestamp | timedelta", expects_value=True, value_hint="timestamp"),
            ArgInfo(
                "--change",
                help_text="type of change",
                expects_value=True,
                possible_values=[e.value for e in list(HistoryChange)],
                can_occur_multiple_times=True,
            ),
            ArgInfo(expects_value=True, value_hint="search"),
        ]


class SortPart(SearchCLIPart):
    """
    ```shell
    sort <sort_property> [asc|desc], <sort_property> [asc|desc], ...
    ```
    Sort the search results based on the given properties in the given order.

    ## Parameters
    - <sort_property> [mandatory]: the property to sort by.
    - [asc|desc] [optional, default to asc]: the sort order as ascending or descending.

    ## Examples

    ```shell
    # Search all volumes and sort by volume size ascending, showing the smallest volume first.
    > search is(volume) | sort volume_size desc | head -1
    kind=aws_ec2_volume, id=vol-1, name=vol-2, age=1yr5mo, cloud=aws, account=eng, region=us-west-2

    # Add a second search criteria
    > search is(volume) | sort volume_size asc, name desc | head -2
    kind=example_volume, id=Vol2, name=Vol2, age=1mo8d, cloud=example, account=Example Account, region=US East
    kind=example_volume, id=Vol1, name=Vol1, age=1mo8d, cloud=example, account=Example Account, region=US West

    # Same search as before, now sort by name ascending
    > search is(volume) | sort volume_size asc, name asc | head -2
    kind=example_volume, id=Vol1, name=Vol1, age=1mo8d, cloud=example, account=Example Account, region=US West
    kind=example_volume, id=Vol2, name=Vol2, age=1mo8d, cloud=example, account=Example Account, region=US East
    ```
    """

    @property
    def name(self) -> str:
        return "sort"

    def info(self) -> str:
        return "Sort the search results."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="<property> [asc|desc]")]


class LimitPart(SearchCLIPart):
    """
    ```shell
    limit [offset] <nr_items>
    ```
    Limit allows to define an optional offset as well as the number if item to return.

    ## Parameters
    - offset [optional, default to 0]: drop the first number of items and start at defined position.
    - nr_items [mandatory]: the number of items to return.

    ## Examples

    ```shell
    # Return the first 3 results from the search
    > search is(volume) | limit 3
    kind=aws_ec2_volume, id=vol-0, name=fs-0, age=2mo23d, cloud=aws, account=eng, region=us-west-2
    kind=aws_ec2_volume, id=vol-1, name=fs-1, age=2mo23d, cloud=aws, account=eng, region=us-west-2
    kind=aws_ec2_volume, id=vol-2, name=fs-2, age=2mo23d, cloud=aws, account=eng, region=us-west-1

    # Return one result from the search dropping the first 2 items
    > search is(volume) | limit 2, 1
    kind=aws_ec2_volume, id=vol-2, name=fs-2, age=2mo23d, cloud=aws, account=eng, region=us-west-1
    ```
    """

    @property
    def name(self) -> str:
        return "limit"

    def info(self) -> str:
        return "Limit the number of returned search results."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="[offset], <nr_items> to return")]


class PredecessorsPart(SearchCLIPart):
    """
    ```shell
    predecessors [--with-origin] [edge_type]
    ```

    This command extends an already existing search.
    It will select all predecessors of the currently selected nodes of the search.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `search id(C) | predecessors`
    will select B, while `search id(A) | predecessors --with-origin` will select C and B.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    ## Environment Variables
    - `edge_type` [Optional]: Defines the type of the edge to navigate.
      The parameter takes precedence over the env var.

    ## Examples

    ```shell
    > search is(volume) and volume_status=available | predecessors | search is(volume_type)
    kind=gcp_disk_type, name=pd-standard, age=2yr1mo, cloud=gcp, account=eng, region=us-central1, zone=us-central1-a
    kind=gcp_disk_type, name=pd-standard, age=2yr1mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    kind=aws_ec2_volume_type, name=gp2, age=5d8h, cloud=aws, account=sales, region=us-west-2
    ```
    """

    @property
    def name(self) -> str:
        return "predecessors"

    def info(self) -> str:
        return "Select predecessors of incoming nodes in the graph."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--with-origin"),
            ArgInfo(expects_value=True, possible_values=["default", "delete"], help_text="edge type"),
        ]

    @staticmethod
    def parse_args(arg: Optional[str], ctx: CLIContext) -> Tuple[int, EdgeType]:
        def valid_edge_type(name: str) -> str:
            if name in EdgeTypes.all:
                return name
            else:
                raise AttributeError(f'Given name is not a valid edge type: {name}. {", ".join(EdgeTypes.all)}')

        parser = NoExitArgumentParser()
        parser.add_argument("--with-origin", dest="origin", default=1, action="store_const", const=0)
        parser.add_argument(
            "edge", default=ctx.env.get("edge_type", EdgeTypes.default), type=valid_edge_type, nargs="?"
        )
        parsed = parser.parse_args(arg.split() if arg else [])
        return parsed.origin, parsed.edge


class SuccessorsPart(SearchCLIPart):
    """
    ```shell
    successors [--with-origin] [edge_type]
    ```

    This command extends an already existing search.
    It will select all successors of the currently selected nodes of the search.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `search id(A) | successors`
    will select B, while `search id(A) | successors --with-origin` will select C and B.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    ## Environment Variables
    - `edge_type` [Optional]: Defines the type of the edge to navigate.
      The parameter takes precedence over the env var.


    ## Examples

    ```shell
    > search is(volume_type) | successors | search is(volume)
    kind=gcp_disk, id=16, name=gke16, age=8mo29d, cloud=gcp, account=eng, region=us-west1, zone=us-west1-a
    kind=gcp_disk, id=26, name=gke26, age=8mo29d, cloud=gcp, account=eng, region=us-west1, zone=us-west1-a
    kind=aws_ec2_volume, id=vol1, name=vol1, age=2mo11d, cloud=aws, account=insights, region=us-west-2
    ```
    """

    @property
    def name(self) -> str:
        return "successors"

    def info(self) -> str:
        return "Select successors of incoming nodes in the graph."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--with-origin"),
            ArgInfo(expects_value=True, possible_values=["default", "delete"], help_text="edge type"),
        ]


class AncestorsPart(SearchCLIPart):
    """
    ```shell
    ancestors [--with-origin] [edge_type]
    ```

    This command extends an already existing search.
    It will select all ancestors of the currently selected nodes of the search.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `search id(C) | ancestors`
    will select B and A, while `search id(C) | ancestors --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    ## Environment Variables
    - `edge_type` [Optional]: Defines the type of the edge to navigate.
      The parameter takes precedence over the env var.

    ## Examples

    ```shell
    > search is(volume_type) limit 1 | ancestors
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
        return "Select ancestors of incoming nodes in the graph."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--with-origin"),
            ArgInfo(expects_value=True, possible_values=["default", "delete"], help_text="edge type"),
        ]


class DescendantsPart(SearchCLIPart):
    """
    ```shell
    descendants [--with-origin] [edge_type]
    ```

    This command extends an already existing search.
    It will select all descendants of the currently selected nodes of the search.
    The graph may contain different types of edges (e.g. the `default` graph or the `delete` graph).
    In order to define which graph to walk, the edge_type can be specified.

    If --with-origin is specified, the current element is included in the result set as well.
    Assume node A with descendant B with descendant C: A --> B --> C `search id(A) | descendants`
    will select B and A, while `search id(A) | descendants --with-origin` will select C and B and A.

    ## Options
    - `--with-origin` [Optional, default to false]: includes the current element into the result set.

    ## Parameters
    - `edge_type` [Optional, default to `default`]: Defines the type of edge to navigate.

    ## Environment Variables
    - `edge_type` [Optional]: Defines the type of the edge to navigate.
      The parameter takes precedence over the env var.

    ## Examples

    ```shell
    > search is(volume_type) limit 1 | descendants --with-origin
    kind=gcp_disk_type, name=pd-standard, age=52yr1mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    kind=gcp_disk, id=881, name=disk-1, age=1yr2mo, cloud=gcp, account=sre, region=us-central1, zone=us-central1-a
    ```
    """

    @property
    def name(self) -> str:
        return "descendants"

    def info(self) -> str:
        return "Select descendants of incoming nodes in the graph."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--with-origin"),
            ArgInfo(expects_value=True, possible_values=["default", "delete"], help_text="edge type"),
        ]


@define(slots=True)
class _AggregateIntermediateResult:
    group_count: int = 0
    # function_result_name -> (value, count)
    fn_values: Dict[str, tuple[Optional[int], int]] = field(factory=lambda: defaultdict(lambda: (None, 0)))


class AggregateCommand(SearchCLIPart):
    """
    ```shell
    aggregate [group_prop, .., group_prop]: [function(), .. , function()]
    ```

    This command extends an already existing search.
    Using the results of a search by aggregating over given properties and applying given aggregation functions.

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
    > search is(volume) | aggregate kind as kind: sum(1) as count
    group:
      kind: aws_ec2_volume
    count: 1799
    ---
    group:
      kind: gcp_disk
    count: 1100

    # Count all volumes in the system together with the complete volume size based on the kind
    > search is(volume) | aggregate kind: sum(volume_size) as summed, sum(1) as count
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
    > search is(volume) | aggregate sum(volume_size) as summed, sum(1) as count
    summed: 154833
    count: 2899
    ```
    """

    @property
    def name(self) -> str:
        return "aggregate"

    def info(self) -> str:
        return "Aggregate the result of a search by the provided specification."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, value_hint="aggregate", help_text="aggregation specification")]

    @staticmethod
    async def aggregate_in(
        content: JsGen,
        group_props: Optional[List[str]] = None,
        fn_props: Optional[List[AggregateFunction]] = None,
    ) -> Dict[tuple[Any, ...], _AggregateIntermediateResult]:
        """
        Aggregate the number of elements in the stream, grouped by the provided group properties and
        aggregated by the given aggregate functions.

        :param content: the stream to aggregate
        :param group_props: the properties to group by
        :param fn_props: the aggregate functions to apply
        :return: A dictionary with the group properties as key and the aggregate result as value
        """
        counter: Dict[tuple[Any, ...], _AggregateIntermediateResult] = defaultdict(_AggregateIntermediateResult)
        empty_tuple = ()

        def key_at(o: JsonElement, n: str) -> Any:
            prop_val = js_value_at(o, n)
            if isinstance(prop_val, (dict, list)):
                return json.dumps(prop_val)
            else:
                return prop_val

        def value_at(o: JsonElement, n: str) -> int:
            prop_val = js_value_at(o, n)
            return prop_val if isinstance(prop_val, int) else 0

        def from_prop(o: JsonElement) -> Any:
            return tuple(key_at(o, n) for n in group_props)  # type: ignore

        def from_none(_: JsonElement) -> Any:
            return empty_tuple

        key_getter = from_prop if group_props else from_none

        def exec_fn(fn: AggregateFunction, o: JsonElement, r: _AggregateIntermediateResult) -> Any:
            value = fn.name if isinstance(fn.name, int) else value_at(o, fn.name)
            name = fn.as_name or str(fn.name)
            ex_fn_val, ex_fn_count = r.fn_values[name]
            if fn.function in ("sum", "avg", "count"):
                r.fn_values[name] = (combine_optional(ex_fn_val, value, lambda a, b: a + b), ex_fn_count + 1)
            elif fn.function == "min":
                if ex_fn_val is None or ex_fn_val > value:
                    r.fn_values[name] = (value, ex_fn_count + 1)
            elif fn.function == "max":
                if ex_fn_val is None or ex_fn_val < value:
                    r.fn_values[name] = (value, ex_fn_count + 1)
            else:
                raise ValueError(f"Unknown function {fn.function}")

        async for element in content:
            key = key_getter(element)
            current = counter[key]
            current.group_count += 1
            if fn_props:
                for fn in fn_props:
                    exec_fn(fn, element, current)

        return counter

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        # read aggregate and interpret all variables in the same section as the rest of the command
        aggregate = Aggregate(*aggregate_parameter_parser.parse(arg)).change_variable(ctx.variable_in_section)
        var_names: List[str] = [n for gv in aggregate.group_by for n in gv.all_names()]
        # lookup the function by result name
        fn_by_name = {fn.as_name or str(fn.name): fn.function for fn in aggregate.group_func}

        def group(keys: tuple[Any, ...]) -> Json:
            lookup = dict(zip(var_names or [], keys))

            result = {}
            for av in aggregate.group_by:
                if isinstance(av.name, AggregateVariableCombined):
                    value = ""
                    for p in av.name.parts:
                        if isinstance(p, AggregateVariableName):
                            v = lookup[p.name]
                            value += str(v) if v is not None else "null"
                        else:
                            value += p
                else:
                    value = lookup[av.name.name]
                result[av.as_name or ".".join(av.all_names())] = value
            return result

        async def aggregate_data(content: JsStream) -> AsyncIterator[JsonElement]:
            async with content.stream() as in_stream:
                for key, value in (await self.aggregate_in(in_stream, var_names, aggregate.group_func)).items():
                    entry: Json = {"group": group(key)}
                    for fn_name, (fn_val, fn_count) in value.fn_values.items():
                        if fn_by_name.get(fn_name) == "avg" and fn_val is not None and fn_count > 0:
                            fn_val = fn_val / fn_count  # type: ignore
                        entry[fn_name] = fn_val
                    yield entry

        # noinspection PyTypeChecker
        return CLIFlow(aggregate_data)


class HeadCommand(SearchCLIPart):
    """
    ```shell
    head [-num]
    ```

    Take [num] number of elements from the input stream and send them downstream.
    The rest of the stream is discarded.

    Note: using a search, the same result can be achieved using `sort` and `limit`.

    ## Options
    - `-num` [optional, defaults to 100]: the number of elements to take from the head.

    ## Examples

    ```shell
    # Json array with 5 elements is defined. We only take the first 2 elements.
    > json [1,2,3,4,5] | head -2
    1
    2

    # A search is performed to select all volumes. Only the first 2 results are taken.
    > search is(volume) | head -2
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
        return CLIFlow(lambda in_stream: in_stream | pipe.take(size))

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="number of elements to take")]

    @staticmethod
    def parse_size(arg: Optional[str]) -> int:
        return abs(int(arg)) if arg else 100


class TailCommand(SearchCLIPart):
    """
    ```shell
    tail [-num]
    ```

    Take the last [num] number of elements from the input stream and send them downstream.
    The beginning of the stream is consumed and discarded.

    Note: using a search, the same result can be achieved using `sort` and `limit`.

    ## Options
    - `-num` [optional, defaults to 100]: the number of elements to take from the head.

    ## Examples

    ```shell
    # Json array with 5 elements is defined. We only take the last 2 elements.
    > json [1,2,3,4,5] | tail -2
    4
    5

    # A search is performed to select all volumes. Only the last 2 results are taken.
    > search is(volume) | tail -2
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

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="number of elements to take")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        size = HeadCommand.parse_size(arg)
        return CLIFlow(lambda in_stream: in_stream | pipe.takelast(size))


class CountCommand(SearchCLIPart):
    """
    ```shell
    count [arg]
    ```

    In case no arg is given, it counts the number of instances provided to count.
    In case of arg: it pulls the property with the name of arg and counts the occurrences of this property.

    This command is part of a search.
    `count` uses an aggregation search under the hood.
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

    > search all | count
    total matched: 142670
    total unmatched: 0

    > search all | count /ancestors.cloud.reported.name
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

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="optional property to count", value_hint="property")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        get_path = ctx.variable_in_section(arg).split(".") if arg else None
        counter: Dict[str, int] = defaultdict(int)
        matched = 0
        unmatched = 0

        def inc_prop(o: JsonElement) -> None:
            nonlocal matched
            nonlocal unmatched
            value = js_value_at(o, get_path)  # type:ignore
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

        async def count_in_stream(content: JsStream) -> AsyncIterator[JsonElement]:
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
    # Hello World in fix
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
        return "Send the provided message to downstream."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="message to send downstream")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        return CLISource.single(
            lambda: stream.just(strip_quotes(arg if arg else "")), required_permissions={Permission.read}
        )


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

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="json string to emit")]

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
        return CLISource.with_count(
            lambda: stream.iterate(elements), len(elements), required_permissions={Permission.read}
        )


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
        return "Suspend execution for an interval of time."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="number of seconds to sleep")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        if not arg:
            raise AttributeError("Sleep needs an argument!")
        try:
            sleep_time = float(arg)

            async def sleep() -> AsyncIterator[JsonElement]:
                for _ in range(0, 1):
                    await asyncio.sleep(sleep_time)
                    yield ""

            return CLISource.single(sleep, required_permissions={Permission.read})
        except Exception as ex:
            raise AttributeError("Sleep needs the time in seconds as arg.") from ex


class AggregateToCountCommand(CLICommand, InternalPart):
    """
    ```shell
    aggregate_to_count
    ```

    This command transforms the output of an aggregation search to the output of the count command.
    ```
    { "group": { "name": "group_name" }, "count": 123 }  --> group_name: 123
    ```

    Expected group key: `name`
    Expected function key: `count`

    It is usually not invoked directly but automatically invoked when there is a search | count cli command.
    """

    @property
    def name(self) -> str:
        return "aggregate_to_count"

    def info(self) -> str:
        return "Convert the output of an aggregate search to the result of count."

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        name_path = ["group", "name"]
        count_path = ["count"]

        async def to_count(in_stream: JsStream) -> AsyncIterator[JsonElement]:
            null_value = 0
            total = 0
            in_streamer = in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)
            async with in_streamer.stream() as streamer:
                async for elem in streamer:
                    name = js_value_at(elem, name_path)
                    count = js_value_get(elem, count_path, 0)
                    if name is None:
                        null_value = count
                    else:
                        total += count
                        yield f"{name}: {count}"
                tm, tu = (total, null_value) if arg else (null_value + total, 0)
                yield f"total matched: {tm}"
                yield f"total unmatched: {tu}"

        return CLIFlow(to_count)


class ExecuteSearchCommand(CLICommand, InternalPart, EntityProvider):
    """
    ```shell
    execute_search [--with-edges] [--explain] <search-statement>
    ```

    This command is usually not invoked directly - use `search` instead.

    ## Options

    - `--with-edges`: Return edges in addition to nodes.
    - `--explain`: Instead of executing the search, analyze its cost.

    ## Parameters

    - `search-statement` [mandatory]: The search to execute.

    ## Related
    - `search` - search the graph.
    """

    @property
    def name(self) -> str:
        return "execute_search"

    def info(self) -> str:
        return "Search the database and pass the results to the output stream."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, value_hint="search", help_text="search to perform")]

    @staticmethod
    def parse_known(arg: str) -> Tuple[Dict[str, Any], str]:
        parser = NoExitArgumentParser()
        parser.add_argument("--with-edges", dest="with-edges", default=None, action="store_true")
        parser.add_argument("--explain", dest="explain", default=None, action="store_true")
        parser.add_argument("--history", dest="history", default=None, action="store_true")
        parser.add_argument("--after", dest="after", default=None)
        parser.add_argument("--before", dest="before", default=None)
        parser.add_argument("--change", dest="change", action="append", default=[])
        parser.add_argument("--at", dest="at", default=None)
        try:
            # try to parse as many arguments as possible
            args, remaining = args_parts_parser.parse_partial(arg)
            # try to parse the parsed arguments
            parsed, rest = parser.parse_known_args(list(args))
            parsed_args = {k: v for k, v in vars(parsed).items() if v is not None}
            # join the unparsed arguments and the remaining arg string
            return parsed_args, " ".join(rest) + remaining
        except Exception:
            # coming here is totally fine - no args could be parsed
            return {}, arg

    @staticmethod
    def argument_string(args: Dict[str, Any]) -> str:
        result = []

        def render_flag(name: str, value: Any) -> None:
            result.append(f"--{name}")
            if value is not True:
                result.append(f"'{value}'")  # put the value into single quotes to maintain the spaces

        for key, value in args.items():
            if value is None or value is False:
                continue
            if isinstance(value, list):
                for v in value:
                    render_flag(key, v)
            else:
                render_flag(key, value)
        return " ".join(result) + " " if result else ""

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        # db name is coming from the env
        current_graph_name = ctx.graph_name
        if not arg:
            raise CLIParseError("search command needs a search-statement to execute, but nothing was given!")

        def parse_at(x: Optional[str]) -> Optional[datetime]:
            if x is None:
                return None
            try:
                return parse_time_or_delta(strip_quotes(x))
            except Exception as ex:
                raise CLIParseError(f"Could not parse {x} as timestamp or timedelta.") from ex

        # Read all argument flags / options
        parsed, rest = self.parse_known(arg)
        with_edges: bool = parsed.get("with-edges", False)
        explain: bool = parsed.get("explain", False)
        history: bool = parsed.get("history", False)
        at: Optional[datetime] = parse_at(parsed.get("at", None))

        # all templates are expanded at this point, so we can call the parser directly.
        query = parse_query(rest, ctx.env)

        async def get_db(at: Optional[datetime], graph_name: GraphName) -> Tuple[GraphDB, GraphName]:
            db_access = self.dependencies.db_access
            if at:
                # if we search at some specific time: find a snapshot at that time
                snapshot_name = await self.dependencies.graph_manager.snapshot_at(time=at, graph_name=graph_name)
                if not snapshot_name:
                    raise CLIParseError(f"No graph snapshot at {at} found for graph {graph_name}.")

                return db_access.get_graph_db(snapshot_name), snapshot_name

            return db_access.get_graph_db(graph_name), graph_name

        async def load_query_model(db: GraphDB, graph_name: GraphName) -> QueryModel:
            model = await self.dependencies.model_handler.load_model(graph_name)
            query_model = QueryModel(query, model, ctx.env)
            await db.to_query(query_model)  # only here to validate the query itself (can throw)
            return query_model

        async def explain_search() -> AsyncIterator[Json]:
            db, graph_name = await get_db(at, current_graph_name)
            query_model = await load_query_model(db, graph_name)
            explanation = await db.explain(query_model, with_edges)
            yield to_js(explanation)

        async def prepare() -> Tuple[CLISourceContext, AsyncIterator[Json]]:
            db, graph_name = await get_db(at, current_graph_name)

            query_model = await load_query_model(db, graph_name)
            count = ctx.env.get("count", "true").lower() != "false"
            timeout = if_set(ctx.env.get("search_timeout"), duration)
            if history:
                before = if_set(parsed.get("before"), lambda x: parse_time_or_delta(strip_quotes(x)))
                after = if_set(parsed.get("after"), lambda x: parse_time_or_delta(strip_quotes(x)))
                changes = [HistoryChange[strip_quotes(x)] for x in parsed.get("change", [])]
                context = await db.search_history(
                    query_model, changes, before, after, with_count=count, timeout=timeout
                )
            elif query.aggregate:
                context = await db.search_aggregation(query_model, with_count=count, timeout=timeout)
            elif with_edges:
                context = await db.search_graph_gen(query_model, with_count=count, timeout=timeout)
            else:
                context = await db.search_list(query_model, with_count=count, timeout=timeout)
            cursor = context.cursor

            # since we can not use context boundaries here,
            # an explicit iterator is used, which makes sure to close the connection.
            async def iterate_and_close() -> AsyncIterator[Json]:
                try:
                    async for e in cursor:
                        yield e
                finally:
                    cursor.close()

            return CLISourceContext(cursor.count(), cursor.full_count()), iterate_and_close()

        return (
            CLISource.single(explain_search, required_permissions={Permission.read})
            if explain
            else CLISource(prepare, required_permissions={Permission.read})
        )


class EnvCommand(CLICommand):
    """
    ```shell
    env
    ```

    Emits the provided environment.
    This is useful to inspect the environment given to the CLI interpreter.

    ## Examples
    ```shell
    # The fixshell will set the graph, section and a session id.
    > env
    graph: fix
    section: reported
    fix_session_id: SHQF9MBUEJ

    # Environment variables can be defined directly on the command line
    > section=desired foo=bla env
    graph: fix
    section: desired
    fix_session_id: SHQF9MBUEJ
    foo: bla
    ```
    """

    @property
    def name(self) -> str:
        return "env"

    def info(self) -> str:
        return "Retrieve the environment and pass it to the output stream."

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        return CLISource.with_count(lambda: stream.just(ctx.env), len(ctx.env), required_permissions={Permission.read})


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

    # The output of search can be chunked as well. The result is omitted here for brevity.
    > search is(volume) limit 5 | chunk 3
    ```

    ## Related
    - `flatten` - for flattening a chunked input stream.
    """

    @property
    def name(self) -> str:
        return "chunk"

    def info(self) -> str:
        return "Chunk incoming elements in batches."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="The number of elements to put into one chunk.")]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        size = int(arg) if arg else 100
        return CLIFlow(lambda in_stream: in_stream | pipe.chunks(size), required_permissions={Permission.read})


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

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        def iterable(it: Any) -> bool:
            return False if isinstance(it, str) else isinstance(it, Iterable)

        def iterate(it: Any) -> JsGen:
            return stream.iterate(it) if is_async_iterable(it) or iterable(it) else stream.just(it)

        return CLIFlow(lambda i: i | pipe.flatmap(iterate), required_permissions={Permission.read})  # type: ignore


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

    def args_info(self) -> ArgsInfo:
        return []

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

        return CLIFlow(lambda in_stream: stream.filter(in_stream, has_not_seen), required_permissions={Permission.read})


class JqCommand(CLICommand, OutputTransformer):
    """
    ```
    jq [--no-rewrite] <filter>
    ```

    Use the well known jq JSON processor to manipulate incoming json.
    Every element from the incoming stream is passed to jq.
    See: https://stedolan.github.io/jq/ for a list of possible jq filter definitions.

    Fix Inventory will rewrite attribute paths to match the defined section.
    Example:
    ```bash
    # the accessed path is rewritten to jq .reported.name
    > search ... | jq .name
    # the accessed path is rewritten to jq .reported.name
    > search is(volume) | jq ./reported.name
    ```

    If you find yourself fighting with this rewrite mechanism, you can turn it off with the `--no-rewrite` option.

    ## Options
    - `--no-rewrite` When this option is enabled, the jq filter is not preprocessed by Fix and given as is to Jq.

    ## Parameters
    - `filter` the filter definition to create a jq program.

    ## Examples

    ```shell
    # Search ec2 instances and extract only the name property
    > search is(aws_ec2_instance) limit 2| jq .name
    build-node-1
    prod-23

    # Search ec2 instances and create a new json object for each entry with name and owner.
    > search is(aws_ec2_instance) limit 2 | jq {name: .name, owner: .tags.owner}
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

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--no-rewrite"),
            ArgInfo(expects_value=True, help_text="The filter definition to create a jq program."),
        ]

    path_re = re.compile("[.](/?[A-Za-z]+)[A-Za-z0-9_\\[\\].]*")

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

        arg = strip_quotes(arg)
        args = arg.split(maxsplit=1)
        in_arg = args[1] if len(args) == 2 and args[0] == "--no-rewrite" else self.rewrite_props(strip_quotes(arg), ctx)
        compiled = jq.compile(strip_quotes(in_arg))

        def process(in_json: JsonElement) -> JsonElement:
            out = compiled.input(in_json).all()
            result = out[0] if len(out) == 1 else out
            return cast(Json, result)

        return CLIFlow(lambda i: i | pipe.map(process), required_permissions={Permission.read})  # type: ignore


class KindsCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    kinds [-a ] [-p property_path] [name]
    ```

    kinds gives information about the available graph data kinds.

    ## Options

    - `-a` | `--all` [Optional]:  Show all kinds. By default only the top level service kinds are shown.
    - `-p` [Optional] property_path: lookup the kind for the defined property path.
       This will do a reverse lookup and search all kinds for the specified property path.

    ## Parameters

    - `name` [Optional]: show available information about the kind with provided name.

    ## Examples

    ```shell
    # Show all available kinds.
    > kinds
    access_key
    .
    .
    zone

    # Show details about a specific kind.
    > kinds volume
    name: volume
    bases:
    - resource
    properties:
      age: duration
      atime: datetime
      ctime: datetime
      id: string
      kind: string
      last_access: duration
      last_update: duration
      mtime: datetime
      name: string
      snapshot_before_delete: boolean
      tags: dictionary[string, string]
      volume_encrypted: boolean
      volume_iops: int64
      volume_size: int64
      volume_status: string
      volume_throughput: int64
      volume_type: string

    # Lookup the type of the given property path in the model.
    > kinds -p reported.tags.owner
    name: string
    runtime_kind: string
    ```
    """

    @property
    def name(self) -> str:
        return "kinds"

    def info(self) -> str:
        return "Retrieves information about the graph data kinds."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo(
                "-a",
                expects_value=False,
                help_text="Show all available kinds.",
            ),
            ArgInfo(
                "-p",
                expects_value=True,
                value_hint="property",
                help_text="lookup the kind of a property path.",
                option_group="lookup",
            ),
            ArgInfo(expects_value=True, value_hint="kind", help_text="kind to lookup", option_group="lookup"),
        ]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        parser = NoExitArgumentParser()
        parser.add_argument("-a", "--all", dest="show_all", action="store_true", default=False)
        parser.add_argument("-p", "--property-path", dest="property_path", type=str)
        parser.add_argument("name", type=str, nargs="?")
        args = parser.parse_args(strip_quotes(arg or "").split())
        graph_name = ctx.graph_name

        def kind_to_js(model: Model, kind: Kind) -> Json:
            if isinstance(kind, SimpleKind):
                return {"name": kind.fqn, "runtime_kind": kind.runtime_kind}
            elif isinstance(kind, DictionaryKind):
                return {"name": kind.fqn, "key": kind.key_kind.fqn, "value": kind.value_kind.fqn}
            elif isinstance(kind, ArrayKind):
                return {"is_array": True, **kind_to_js(model, kind.inner)}
            elif isinstance(kind, ComplexKind):
                synth = {k.prop.name: k for k in kind.synthetic_props() if len(k.path.path) == 1}

                def kind_name(p: Property) -> str:
                    # in case of synthetic property
                    return (
                        (synth[p.name].simple_kind.runtime_kind if p.name in synth else p.kind)
                        if p.synthetic
                        else p.kind
                    )

                props = sorted(kind.all_props(), key=lambda k: k.name)
                predecessors = list(
                    {
                        cpl.fqn
                        for cpl in model.complex_kinds()
                        if kind.fqn in cpl.successor_kinds.get(EdgeTypes.default, [])
                    }
                )
                js = {"name": kind.fqn, "properties": {p.name: kind_name(p) for p in props}}
                if bases := list(kind.kind_hierarchy() - {kind.fqn}):
                    js["bases"] = bases
                if predecessors:
                    js["predecessors"] = predecessors
                if successors := kind.successor_kinds.get(EdgeTypes.default, []):
                    js["successors"] = successors
                return js
            else:
                return {"name": kind.fqn}

        def property_defined_in(model: Model, path_: str) -> List[str]:
            path = PropertyPath.from_string(path_)
            return [
                kind.fqn
                for kind in model.complex_kinds()
                if any(p for p in kind.resolved_property_paths() if p.path.same_as(path))
            ]

        async def source() -> Tuple[int, JsGen]:
            model = await self.dependencies.model_handler.load_model(graph_name)

            def show(k: ComplexKind) -> bool:
                return args.show_all or (
                    k.aggregate_root
                    and not any(isinstance(m, ComplexKind) and k.fqn in m.bases for m in model.kinds.values())
                )

            if args.name:
                kind = args.name
                result: JsonElement = (
                    kind_to_js(model, model[kind]) if kind in model else f"No kind with this name: {kind}"
                )
                return 1, stream.just(result)
            elif args.property_path:
                no_section = Section.without_section(args.property_path)
                result = kind_to_js(model, model.kind_by_path(no_section))
                if appears_in := property_defined_in(model, no_section):
                    result["appears_in"] = appears_in
                return 1, stream.just(result)
            else:
                result = sorted([k.fqn for k in model.kinds.values() if isinstance(k, ComplexKind) and show(k)])
                return len(model.kinds), stream.iterate(result)

        return CLISource.only_count(source, required_permissions={Permission.read})


class SetDesiredStateBase(CLICommand, EntityProvider, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_desired, arg, ctx.graph_name, self.patch(arg, ctx))
        return CLIFlow(
            lambda i: i | pipe.chunks(buffer_size) | pipe.flatmap(func), required_permissions={Permission.write}
        )

    async def set_desired(
        self, arg: Optional[str], graph_name: GraphName, patch: Json, items: List[Json]
    ) -> AsyncIterator[JsonElement]:
        model = await self.dependencies.model_handler.load_model(graph_name)
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

    This command assumes, that all incoming elements are either objects coming from a search or are object ids.
    All objects coming from a search will have a property `id`.
    The result of this command will emit the updated state.

    ## Parameters

    - `property` - the name of the property to set in the desired section.
    - `value` - the value of the property to set in the desired section. This needs to be a json element.

    Multiple properties can be changed by defining multiple property=value definitions separated by space.

    ## Examples

    ```shell
    > search is(instance) limit 1 | set_desired a=b b="c" num=2 | list /id, /desired
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

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="<prop>=<value>")]

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

    This command assumes, that all incoming elements are either objects coming from a search or are object ids.
    All objects coming from a search will have a property `id`.

    The result of this command will emit the updated object.

    ## Parameters
    - `reason` [Optional] - a log message is issued with this reason, once a resource is marked for cleanup.

    ## Examples
    ```shell
    # Search for volumes that have not been accessed in the last month
    # Mark them for cleanup and show the id as well as the complete desired section.
    > search is(volume) and last_access>1month | clean "Volume not accessed for longer than 1 month" | list id, /desired
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
        return "Mark all incoming resources for cleaning."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="optional reason for cleaning")]

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        return {"clean": True}

    async def set_desired(
        self, arg: Optional[str], graph_name: GraphName, patch: Json, items: List[Json]
    ) -> AsyncIterator[JsonElement]:
        reason = f"Reason: {strip_quotes(arg)}" if arg else "No reason provided."
        async for elem in super().set_desired(arg, graph_name, patch, items):
            uid = js_value_at(elem, NodePath.node_id)
            r_id = js_value_get(elem, NodePath.reported_id, "<no id>")
            r_name = js_value_get(elem, NodePath.reported_name, "<no name>")
            r_kind = js_value_get(elem, NodePath.reported_kind, "<no kind>")
            log.info(f"Node id={r_id}, name={r_name}, kind={r_kind} marked for cleanup. {reason}. ({uid})")
            yield elem


class SetMetadataStateBase(CLICommand, EntityProvider, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_metadata, ctx.graph_name, self.patch(arg, ctx))
        return CLIFlow(
            lambda i: i | pipe.chunks(buffer_size) | pipe.flatmap(func), required_permissions={Permission.write}
        )

    async def set_metadata(self, graph_name: GraphName, patch: Json, items: List[Json]) -> AsyncIterator[JsonElement]:
        model = await self.dependencies.model_handler.load_model(graph_name)
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

    This command assumes, that all incoming elements are either objects coming from a search or are object ids.
    All objects coming from a search will have a property `id`.
    The result of this command will emit the updated state.

    ## Parameters

    - `property` - the name of the property to set in the desired section.
    - `value` - the value of the property to set in the desired section. This needs to be a json element.

    Multiple properties can be changed by defining multiple property=value definitions separated by space.


    ## Examples

    ```shell
    > search is(instance) limit 1 | set_metadata a=b b="c" num=2 | list /id, /metadata
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

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, help_text="<key>=<value>")]

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

    This command assumes, that all incoming elements are either objects coming from a search or are object ids.
    All objects coming from a search will have a property `id`.
    The result of this command will emit the updated object.

    ## Examples

    ```shell
    # Search for instances that are tagged with "build node" - such nodes should never be clean up.
    > search is(instance) and tags.job=="build node" | protect | list id, /metadata
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

    def args_info(self) -> ArgsInfo:
        return []

    def patch(self, arg: Optional[str], ctx: CLIContext) -> Json:
        return {"protected": True}


ConvertFn = Callable[[AsyncIterator[JsonElement]], AsyncIterator[JsonElement]]


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
    - `--yaml` [Optional] - will create a yaml string from the incoming json.
       Subsequent object will be separated by `---`.
    - `--ndjson` [Optional] - will create a json object for every element, where one element fits on one line.
    - `--text` [Optional] - will create a text representation of every element.
    - `--cytoscape` [Optional] - will create a string representation in the well known Cytoscape .cyjs format.
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

    > search all | format --json | write out.json
    Received a file out.json, which is stored to ./out.json.
    ```
    """

    @property
    def name(self) -> str:
        return "format"

    def info(self) -> str:
        return "Transform incoming objects as string with a defined format."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--json", help_text="output format", option_group="output"),
            ArgInfo("--ndjson", help_text="output format", option_group="output"),
            ArgInfo("--text", help_text="output format", option_group="output"),
            ArgInfo("--cytoscape", help_text="output format", option_group="output"),
            ArgInfo("--graphml", help_text="output format", option_group="output"),
            ArgInfo("--dot", help_text="output format", option_group="output"),
            ArgInfo("--yaml", help_text="output format", option_group="output"),
            ArgInfo(expects_value=True, help_text="format definition with {} placeholders", option_group="output"),
        ]

    formats: Dict[str, ConvertFn] = {
        "ndjson": respond_ndjson,
        "json": partial(respond_json, indent=2),
        "text": respond_text,
        "yaml": respond_yaml,
        "cytoscape": respond_cytoscape,
        "graphml": respond_graphml,
        "dot": respond_dot,
    }

    render_all = {"benchmark_result": respond_benchmark_result}

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        parser = NoExitArgumentParser()
        parser.add_argument("--json", dest="json", action="store_true")
        parser.add_argument("--ndjson", dest="ndjson", action="store_true")
        parser.add_argument("--graphml", dest="graphml", action="store_true")
        parser.add_argument("--text", dest="text", action="store_true")
        parser.add_argument("--yaml", dest="yaml", action="store_true")
        parser.add_argument("--cytoscape", dest="cytoscape", action="store_true")
        parser.add_argument("--dot", dest="dot", action="store_true")
        parser.add_argument("--benchmark-result", dest="benchmark_result", action="store_true")
        parsed, formatting_string = parser.parse_known_args(arg.split() if arg else [])
        format_to_use = {k for k, v in vars(parsed).items() if v is True}
        use: Optional[str] = None
        if format_to_use:
            if len(format_to_use) > 1:
                raise AttributeError(f'You can define only one format. Defined: {", ".join(format_to_use)}')
            if len(formatting_string) > 0:
                raise AttributeError("A format renderer can not be combined together with a format string!")
            use = next(iter(format_to_use))

        async def render_single(converter: ConvertFn, iss: JsStream) -> JsGen:
            async with iss.stream() as streamer:
                async for elem in converter(streamer):
                    yield elem

        async def format_stream(in_stream: JsStream) -> JsGen:
            if use:
                if all_renderer := self.render_all.get(use):
                    return all_renderer(in_stream)
                elif single_renderer := self.formats.get(use):
                    return render_single(single_renderer, in_stream)
                else:
                    raise ValueError(f"Unknown format: {use}")
            elif formatting_string:
                return in_stream | pipe.map(ctx.formatter(arg)) if arg else in_stream  # type: ignore
            else:
                return in_stream

        produces = MediaType.Markdown if use == "benchmark_result" else MediaType.String
        return CLIFlow(format_stream, produces=produces, required_permissions={Permission.read})


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
    > search is(volume) limit 1 | dump
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

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        # Dump returns the same stream as provided without changing anything.
        # Since it is an OutputTransformer, the resulting transformer will be dump (not list).
        return CLIFlow(identity, required_permissions={Permission.read})


@frozen
class PropToShow:
    path: List[str]
    name: str
    display: str
    path_access: Optional[str] = None
    alternative_path: Optional[List[str]] = None
    override_kind: Optional[str] = None

    def full_path(self) -> str:
        return self.path_access or ".".join(self.path)

    def value(self, node: JsonElement) -> Optional[JsonElement]:
        result = js_value_at(node, self.path)
        return (
            result if result is not None or self.alternative_path is None else js_value_at(node, self.alternative_path)
        )


class ListCommand(CLICommand, OutputTransformer):
    """
    ```
    list [property [as <name>]] [,property ...]
    ```

    This command creates a string from the json input based on the defined properties to show.

    If no prop is defined a predefined list of properties will be shown:

    - /info as info
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
    The property path can be absolute, meaning it with the section name (reported, desired, metadata).
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


    ## Options

    - `--csv` [optional]: format the output as CSV. Can't be used together with `--markdown`.

    - `--markdown` [optional]: format the output as Markdown table. Can't be used together with `--csv`.

    ## Examples

    ```shell
    # If all parameters are omitted, the predefined default list is taken.
    > search is(aws_ec2_instance) limit 3 | list
    kind=aws_ec2_instance, id=1, name=sun, ctime=2020-09-10T13:24:45Z, cloud=aws, account=prod, region=us-west-2
    kind=aws_ec2_instance, id=2, name=moon, ctime=2021-09-21T01:08:11Z, cloud=aws, account=dev, region=us-west-2
    kind=aws_ec2_instance, id=3, name=star, ctime=2021-09-25T23:28:40Z, cloud=aws, account=int, region=us-east-1

    # Explicitly define the properties to show without renaming them.
    > search is(aws_ec2_instance) limit 3 | list kind, name
    kind=aws_ec2_instance, name=sun
    kind=aws_ec2_instance, name=moon
    kind=aws_ec2_instance, name=star

    # Same search and same result as before, with an explicit rename clause.
    > search is(aws_ec2_instance) limit 3 | list kind as a, name as b
    a=aws_ec2_instance, b=sun
    a=aws_ec2_instance, b=moon
    a=aws_ec2_instance, b=star

    # Properties that do not exist, are not printed.
    > search is(aws_ec2_instance) limit 3 | list kind as a, name as b, does_not_exist
    a=aws_ec2_instance, b=sun
    a=aws_ec2_instance, b=moon
    a=aws_ec2_instance, b=star

    # Properties that do not exist will be printed as empty values when using csv or markdown output.
    > search is(instance) limit 3 | list --csv instance_cores as cores, name, does_not_exist
    cores,name,does_not_exist
    2,node-1,
    1,something_else,
    4,very-long-instance-name-123,

    > search is(instance) limit 3 | list --markdown instance_cores as cores, name, does_not_exist
    |cores|name                       |does_not_exist|
    |-----|---------------------------|--------------|
    |2    |node-1                     |null          |
    |1    |something_else             |null          |
    |4    |very-long-instance-name-123|null          |
    ```

    ## Related

    - `format` - Create a string from object based on a defined format.
    - `dump` - will show the complete content tree of an incoming object.
    - `jq` - Define a transformation via the well known `jq` command.

    """

    # This is the list of properties to show in the list command by default
    default_properties_to_show = [
        PropToShow(["reported", "kind"], "kind", "Kind"),
        PropToShow(["reported", "id"], "id", "Id"),
        PropToShow(["reported", "name"], "name", "Name"),
    ]
    default_live_properties_to_show = [
        PropToShow(["reported", "age"], "age", "Age"),
        PropToShow(["reported", "last_update"], "last_update", "Last Update"),
    ]
    default_context_properties_to_show = [
        PropToShow(["ancestors", "cloud", "reported", "name"], "cloud", "Cloud"),
        PropToShow(["ancestors", "account", "reported", "name"], "account", "Account"),
        PropToShow(["ancestors", "region", "reported", "name"], "region", "Region"),
        PropToShow(["ancestors", "zone", "reported", "name"], "zone", "Zone"),
    ]
    default_history_properties_to_show = [
        PropToShow(["change"], "change", "Change"),
        PropToShow(["changed_at"], "changed_at", "Changed At"),
    ]
    default_properties_to_ignore = {
        "ancestors.cloud.reported.id",
        "ancestors.account.reported.id",
        "ancestors.region.reported.id",
        "ancestors.zone.reported.id",
    }
    json_table_live_properties_to_show = [
        PropToShow(["reported", "age"], "age", "Age"),
    ]
    json_table_context_properties_to_show = [
        PropToShow(["ancestors", "cloud", "reported", "name"], "cloud", "Cloud"),
        PropToShow(["ancestors", "account", "reported", "name"], "account", "Account"),
        PropToShow(
            ["ancestors", "zone", "reported", "name"],
            "region_zone",
            "Region / Zone",
            alternative_path=["ancestors", "region", "reported", "name"],
        ),
    ]
    default_list = (
        default_properties_to_show,
        default_context_properties_to_show,
        default_history_properties_to_show,
        default_live_properties_to_show,
    )
    json_table_list = (
        default_properties_to_show,
        json_table_context_properties_to_show,
        default_history_properties_to_show,
        json_table_live_properties_to_show,
    )

    @property
    def name(self) -> str:
        return "list"

    def info(self) -> str:
        return "Format elements as property list, csv or markdown."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--csv", help_text="format", option_group="format"),
            ArgInfo("--markdown", help_text="format", option_group="format"),
            ArgInfo("--json-table", help_text="format", option_group="format"),
            ArgInfo(
                expects_value=True,
                help_text="comma separated list of properties to show",
                value_hint="property_list_with_as",
            ),
        ]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        parser = NoExitArgumentParser()
        output_type = parser.add_mutually_exclusive_group()
        output_type.add_argument("--csv", dest="csv", action="store_true")
        output_type.add_argument("--markdown", dest="markdown", action="store_true")
        output_type.add_argument("--json-table", dest="json_table", action="store_true")
        parsed, properties_list = parser.parse_known_args(arg.split() if arg else [])
        properties = " ".join(properties_list) if properties_list else None
        is_aggregate: bool = ctx.query is not None and ctx.query.aggregate is not None

        def display(name: str) -> str:
            return " ".join(word.capitalize() for word in name.split("_"))

        def default_props_to_show(
            props_setting: Tuple[List[PropToShow], List[PropToShow], List[PropToShow], List[PropToShow]]
        ) -> List[PropToShow]:
            if (query := ctx.query) and (aggregate := query.aggregate) is not None:
                return default_aggregate_props_to_show(aggregate)
            else:
                return default_list_props_to_show(props_setting)

        def default_aggregate_props_to_show(aggregate: Aggregate) -> List[PropToShow]:
            props = [
                PropToShow(["group", n], n, display(n), override_kind=string_kind.fqn)
                for group in aggregate.group_by
                if (n := group.get_as_name())
            ]
            for fn in aggregate.group_func:
                props.append(
                    PropToShow(
                        [fn.get_as_name()], fn.get_as_name(), display(fn.get_as_name()), override_kind=double_kind.fqn
                    )
                )
            return props

        def default_list_props_to_show(
            props_setting: Tuple[List[PropToShow], List[PropToShow], List[PropToShow], List[PropToShow]]
        ) -> List[PropToShow]:
            default_props, context_props, history_props, live_props = props_setting
            all_default_props = {".".join(prop.path) for props in props_setting for prop in props}

            result: List[PropToShow] = []
            local_paths = set()
            # with the object id, if edges are requested
            if ctx.query_options.get("with-edges") is True:
                result.append(PropToShow(["id"], "node_id", "Node Id"))
            if ctx.query_options.get("history") is True:
                result.extend(history_props)
            # add additional props from commands
            for exc in ctx.commands:
                for path, name in exc.command.additional_properties_to_show():
                    prop = ".".join(path)
                    if name not in all_default_props and prop not in local_paths:
                        local_paths.add(prop)
                        result.append(PropToShow(path, name, display(name)))
            # add all default props
            result.extend(default_props)
            # add all predicates the user has queried
            if ctx.query:
                # add all predicates the user has queried
                predicate_names = (
                    p.name for p in ctx.query.visible_predicates if p.name not in self.default_properties_to_ignore
                )
                # add sort keys of the last part the user has defined
                sort_names = (s.name for s in ctx.query.current_part.sort)
                for name in chain(predicate_names, sort_names):
                    if name not in all_default_props and name not in local_paths:
                        local_paths.add(name)
                        path = PropertyPath.from_string(name).unescaped_parts()
                        result.append(PropToShow(path, path[-1], display(name), name))
            if ctx.query_options.get("history") is not True:
                result.extend(live_props)
            # add all context properties
            result.extend(context_props)
            return result

        def adjust_path(prop_path: str) -> List[str]:
            return PropertyPath.from_string(ctx.variable_in_section(prop_path)).unescaped_parts()

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

        def parse_props_to_show(props_arg: str) -> List[PropToShow]:
            props: List[PropToShow] = []
            for prop, as_name in list_arg_parse.parse(props_arg):
                path = adjust_path(prop)
                as_name = path[-1] if prop == as_name or as_name is None else as_name
                props.append(PropToShow(path, as_name, display(as_name), prop))
            return props

        def create_unique_names(all_props: List[PropToShow]) -> List[PropToShow]:
            result: List[PropToShow] = []
            names: Set[str] = set()

            def unique_name(path: List[str], current: str) -> str:
                # compute the name by parameter path
                current = "_".join(path) if path else current
                if current not in names:
                    return current
                # compute the name by parameter path and current name
                count = 0
                attempt = current
                while attempt in names:
                    count += 1
                    attempt = f"{current}_{count}"
                return attempt

            for prop in all_props:
                name = prop.name
                if name in names:
                    if len(prop.path) <= 1:
                        name = unique_name(prop.path, name)
                    elif prop.path[0] in ("ancestors", "descendants"):
                        name = unique_name([prop.path[1]] + prop.path[3:], name)
                    elif prop.path[0] in Section.all:
                        name = unique_name(prop.path[1:], name)
                    else:
                        name = unique_name(prop.path, name)
                names.add(name)
                result.append(evolve(prop, name=name))
            return result

        def props_to_show(
            props_setting: Tuple[List[PropToShow], List[PropToShow], List[PropToShow], List[PropToShow]]
        ) -> List[PropToShow]:
            props = parse_props_to_show(properties) if properties is not None else default_props_to_show(props_setting)
            return create_unique_names(props)

        def fmt_json(elem: Json) -> JsonElement:
            if is_node(elem) or is_aggregate:
                result = ""
                first = True
                for prop in props_to_show(self.default_list):
                    value = prop.value(elem)
                    if value is not None:
                        delim = "" if first else ", "
                        result += f"{delim}{to_str(prop.name, value)}"
                        first = False
                return result
            elif is_edge(elem):
                return f'{elem.get("from")} -> {elem.get("to")}: {elem.get("edge_type")}'
            else:
                return elem

        async def csv_stream(in_stream: JsStream) -> JsGen:
            output = io.StringIO()
            dialect = csv.unix_dialect()
            writer = csv.writer(output, dialect=dialect, quoting=csv.QUOTE_NONNUMERIC)

            def to_csv_string(lst: List[Any]) -> str:
                writer.writerow(lst)
                csv_value = output.getvalue().rstrip()
                output.truncate(0)
                output.seek(0)
                return csv_value

            props = props_to_show(self.default_list)
            header_values = [prop.name for prop in props]
            yield to_csv_string(header_values)

            async with in_stream.stream() as s:
                async for elem in s:
                    if is_node(elem) or is_aggregate:
                        result = []
                        for prop in props:
                            value = prop.value(elem)
                            result.append(value)
                        yield to_csv_string(result)

        async def json_table_stream(in_stream: JsStream, model: QueryModel) -> JsGen:
            def kind_of(path: str) -> Kind:
                resolved, _ = model.prop_kind(path)
                if isinstance(resolved.kind, TransformKind):
                    return resolved.kind.source_kind if resolved.kind.source_kind else any_kind
                else:
                    return resolved.kind

            def render_prop(elem: JsonElement) -> JsonElement:
                # For table output, we want to show a single element: create a string from complex or list element.
                if isinstance(elem, dict):
                    return ", ".join(f"{k}={render_prop(v)}" for k, v in sorted(elem.items()))
                elif isinstance(elem, list):
                    return ", ".join(str(render_prop(e)) for e in elem)
                else:
                    return elem

            props = props_to_show(self.json_table_list)
            # header columns
            yield {
                "columns": [
                    {
                        "name": prop.name,
                        "path": "/" + prop.full_path(),
                        "kind": prop.override_kind or kind_of(prop.full_path()).fqn,
                        "display": prop.display,
                    }
                    for prop in props
                ],
            }
            # data columns
            async with in_stream.stream() as s:
                async for elem in s:
                    if isinstance(elem, dict) and (is_node(elem) or is_aggregate):
                        yield {
                            "id": None if is_aggregate else elem["id"],  # aggregates have no id
                            "row": {prop.name: render_prop(prop.value(elem)) for prop in props},
                        }

        def markdown_stream(in_stream: JsStream) -> JsGen:
            chunk_size = 500

            props = props_to_show(self.default_list)
            headers = [prop.name for prop in props]
            columns_padding = [len(name) for name in headers]

            def extract_values(elem: JsonElement) -> List[Any | None]:
                result = []
                prop_idx: int
                for prop_idx, prop in enumerate(props):
                    value = prop.value(elem)
                    columns_padding[prop_idx] = max(columns_padding[prop_idx], len(str(value)))
                    result.append(value)
                return result

            async def generate_markdown(chunk: Tuple[int, List[List[Any]]]) -> JsGen:
                idx, rows = chunk

                def to_str(elem: Any) -> str:
                    if isinstance(elem, dict):
                        return ", ".join(f"{str((k, v))}" for k, v in sorted(elem.items()))
                    elif isinstance(elem, list):
                        return "[" + ", ".join(to_str(e) for e in elem) + "]"
                    elif elem is None:
                        return "null"
                    elif elem is True:
                        return "true"
                    elif elem is False:
                        return "false"
                    else:
                        return str(elem)

                if idx == 0:
                    # render the header of the table
                    line = ""
                    for header, padding in zip(headers, columns_padding):
                        line += f"|{header.ljust(padding)}"
                    line += "|"
                    yield line

                    # render the separator of the table
                    line = ""
                    for header, padding in zip(headers, columns_padding):
                        line += f"|{'-' * padding}"
                    line += "|"
                    yield line

                for row in rows:
                    line = ""
                    for value, padding in zip(row, columns_padding):
                        line += f"|{to_str(value).ljust(padding)}"
                    line += "|"
                    yield line

            # noinspection PyUnresolvedReferences
            markdown_chunks = (
                in_stream
                | pipe.filter(lambda x: is_node(x) or is_aggregate)
                | pipe.map(extract_values)  # type: ignore
                | pipe.chunks(chunk_size)
                | pipe.enumerate()
                | pipe.flatmap(generate_markdown)  # type: ignore
            )

            return markdown_chunks

        def fmt(in_stream: JsStream) -> JsGen:
            if parsed.csv:
                return csv_stream(in_stream)
            elif parsed.markdown:
                return markdown_stream(in_stream)
            elif parsed.json_table:

                async def load_model() -> QueryModel:
                    model = await self.dependencies.model_handler.load_model(ctx.graph_name)
                    return QueryModel(ctx.query or Query.empty(), model, ctx.env)

                return stream.call(load_model) | pipe.flatmap(partial(json_table_stream, in_stream))  # type: ignore
            else:
                return stream.map(
                    in_stream,
                    lambda elem: fmt_json(elem) if isinstance(elem, dict) else str(elem),  # type: ignore
                )

        return CLIFlow(fmt, produces=MediaType.String, required_permissions={Permission.read})


class JobsCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    jobs list
    jobs show <id>
    jobs add [--id <id>] [--schedule <cron_expression>] [--wait-for-event <event_name>] <command_line>
    jobs update --id <id> [--schedule <cron_expression>] [--wait-for-event <event_name> :] <command_line>
    jobs delete <id>
    jobs activate <id>
    jobs deactivate <id>
    jobs run <id>
    jobs running
    ```

    - `jobs list`: get the list of all jobs in the system
    - `jobs show <id>`: show the current definition of the job defined by given job identifier.
    - `jobs add ...`: add a job to the task handler with provided identifier, trigger and command line to execute.
    - `jobs update --id <id> ...` : update trigger and or command line of an existing job with provided identifier.
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
    > jobs add --id wait_for_collect_done --wait-for-event collect_done echo hello world
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

    def help(self) -> str:
        extra_info = f"## Time Zone\nThe default time zone for new jobs is {get_local_tzinfo().key}."
        return super().help() + "\n" + extra_info

    def args_info(self) -> ArgsInfo:
        return {
            "add": [
                ArgInfo("--id", expects_value=True),
                ArgInfo("--schedule", expects_value=True),
                ArgInfo("--wait-for-event", expects_value=True),
                ArgInfo("--timeout", expects_value=True),
                ArgInfo(None, value_hint="command", help_text="<command> to run"),
            ],
            "show": [ArgInfo(None, help_text="<job-id>")],
            "list": [],
            "update": [
                ArgInfo("--id", expects_value=True),
                ArgInfo("--schedule", expects_value=True),
                ArgInfo("--wait-for-event", expects_value=True),
                ArgInfo("--timeout", expects_value=True),
                ArgInfo(None, value_hint="command", help_text="<command> to run"),
            ],
            "delete": [ArgInfo(None, help_text="<job-id>")],
            "activate": [ArgInfo(None, help_text="<job-id>")],
            "deactivate": [ArgInfo(None, help_text="<job-id>")],
            "run": [ArgInfo(None, help_text="<job-id>")],
            "running": [],
        }

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
            listed = await self.dependencies.task_handler.list_jobs()

            async def iterate() -> AsyncIterator[JsonElement]:
                for job in listed:
                    yield job_to_json(job)

            return len(listed), iterate()

        async def show_job(job_id: str) -> AsyncIterator[JsonElement]:
            matching = [job for job in await self.dependencies.task_handler.list_jobs() if job.name == job_id]
            if matching:
                yield job_to_json(matching[0])
            else:
                yield f"No job with this id: {job_id}"

        async def put_job(arg_str: str, is_update: bool = False) -> AsyncIterator[str]:
            arg_parser = NoExitArgumentParser()
            arg_parser.add_argument("--id", dest="id", default=rnd_str(), required=is_update)
            arg_parser.add_argument("--schedule", dest="schedule", type=lambda r: TimeTrigger(strip_quotes(r)))
            arg_parser.add_argument("--wait-for-event", dest="event", type=lambda e: EventTrigger(strip_quotes(e)))
            arg_parser.add_argument(
                "--timeout", dest="timeout", default=timedelta(hours=1), type=lambda t: timedelta(seconds=int(t))
            )
            parsed, rest = arg_parser.parse_known_args(list(args_parts_parser.parse(arg_str)))
            uid = parsed.id
            command = " ".join(rest)
            # make sure the command can be executed
            cmd_lines = await self.dependencies.cli.evaluate_cli_command(command, ctx)
            # check that the permission required for the job exist for the current user
            if self.dependencies.config.args.psk is not None and not all(
                cmd_line.is_allowed_to_execute() for cmd_line in cmd_lines
            ):
                required = {
                    p
                    for cmd_line in cmd_lines
                    for cmd in cmd_line.executable_commands
                    for p in cmd.action.required_permissions
                }
                raise NotEnoughPermissions(ctx.user_permissions, required)

            timeout: timedelta = parsed.timeout
            if parsed.schedule and parsed.event:
                wait = (parsed.event, timeout)
                job = Job(uid, ExecuteCommand(command), timeout, parsed.schedule, wait, ctx.env)
            elif parsed.schedule or parsed.event:
                trigger = parsed.schedule or parsed.event
                job = Job(uid, ExecuteCommand(command), timeout, trigger, environment=ctx.env)
            else:
                job = Job(uid, ExecuteCommand(command), timeout, environment=ctx.env)
            await self.dependencies.task_handler.add_job(job)
            update_str = "updated" if is_update else "added"
            yield f"Job {job.id} {update_str}."

        async def delete_job(job_id: str) -> AsyncIterator[str]:
            job = await self.dependencies.task_handler.delete_job(job_id)
            yield f"Job {job_id} deleted." if job else f"No job with this id: {job_id}"

        async def run_job(job_id: str) -> AsyncIterator[str]:
            info = await self.dependencies.task_handler.start_task_by_descriptor_id(TaskDescriptorId(job_id))
            if info and info.scheduled_next:
                task = info.running_task
                yield (
                    f"Job {task.descriptor.id} is currently running with id {task.id}."
                    "Scheduled next run after this one is completed"
                )
            elif info:
                task = info.running_task
                yield f"Job {task.descriptor.id} started with id {task.id}."
            else:
                yield f"No job with this id: {job_id}"

        async def activate_deactivate_job(job_id: str, active: bool) -> AsyncIterator[JsonElement]:
            matching = [job for job in await self.dependencies.task_handler.list_jobs() if job.name == job_id]
            if matching:
                m = matching[0]
                if m.trigger is not None:
                    job = Job(m.id, m.command, m.timeout, m.trigger, m.wait, m.environment, m.mutable, active)
                    await self.dependencies.task_handler.add_job(job)
                    yield job_to_json(job)
                else:
                    yield f"Job {job_id} does not have any trigger that could be activated/deactivated."
            else:
                yield f"No job with this id: {job_id}"

        async def running_jobs() -> Tuple[int, JsStream]:
            tasks = await self.dependencies.task_handler.running_tasks()
            return len(tasks), stream.iterate(
                {"job": t.descriptor.id, "started_at": to_json(t.task_started_at), "task-id": t.id}
                for t in tasks
                if isinstance(t.descriptor, Job)
            )

        async def show_help() -> AsyncIterator[str]:
            yield self.rendered_help(ctx)

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] in ("add", "update"):
            is_update = args[0] == "update"
            return CLISource.single(
                partial(put_job, args[1].strip(), is_update), required_permissions={Permission.write}
            )
        elif arg and len(args) == 2 and args[0] == "delete":
            return CLISource.single(partial(delete_job, args[1].strip()), required_permissions={Permission.write})
        elif arg and len(args) == 2 and args[0] == "show":
            return CLISource.single(partial(show_job, args[1].strip()), required_permissions={Permission.read})
        elif arg and len(args) == 2 and args[0] == "run":
            return CLISource.single(partial(run_job, args[1].strip()), required_permissions={Permission.write})
        elif arg and len(args) == 2 and args[0] == "activate":
            return CLISource.single(
                partial(activate_deactivate_job, args[1].strip(), True), required_permissions={Permission.write}
            )
        elif arg and len(args) == 2 and args[0] == "deactivate":
            return CLISource.single(
                (partial(activate_deactivate_job, args[1].strip(), False)), required_permissions={Permission.write}
            )
        elif arg and len(args) == 2:
            raise CLIParseError(f"Does not understand action {args[0]}. Allowed: add, update, delete.")
        elif arg and len(args) == 1 and args[0] == "running":
            return CLISource.only_count(running_jobs, required_permissions={Permission.read})
        elif arg and len(args) == 1 and args[0] == "list":
            return CLISource.only_count(list_jobs, required_permissions={Permission.read})
        else:
            return CLISource.single(show_help, required_permissions={Permission.read})


class SendWorkerTaskCommand(CLICommand, ABC):
    # Abstract base for all commands that send task to the work queue

    # this method expects a stream of Tuple[str, Dict[str, str], Json]
    def send_to_queue_stream(
        self,
        in_stream: JsStream,
        result_handler: Callable[[WorkerTask, Future[Json]], Awaitable[Json]],
        wait_for_result: bool,
    ) -> JsStream:
        async def send_to_queue(task_name: str, task_args: Dict[str, str], data: Json) -> JsonElement:
            future = asyncio.get_event_loop().create_future()
            task = WorkerTask(TaskId(uuid_str()), task_name, task_args, data, future, self.timeout())
            # enqueue this task
            await self.dependencies.worker_task_queue.add_task(task)
            # wait for the task result
            result_future = result_handler(task, future)
            if wait_for_result:
                return await result_future
            else:
                result_task: Task[JsonElement] = asyncio.create_task(result_future)  # type: ignore
                await self.dependencies.forked_tasks.put((result_task, f"WorkerTask {task_name}:{task.id}"))
                return f"Spawned WorkerTask {task_name}:{task.id}"

        return in_stream | pipe.starmap(send_to_queue, ordered=False, task_limit=self.task_limit())  # type: ignore

    def load_by_id_merged(
        self,
        model: Model,
        in_stream: JsStream,
        variables: Optional[Set[str]],
        expected_kind: Optional[str] = None,
        **env: str,
    ) -> JsStream:
        async def load_element(items: List[JsonElement]) -> AsyncIterator[JsonElement]:
            # collect ids either from json dict or string
            ids: List[str] = [i["id"] if is_node(i) else i for i in items]  # type: ignore
            # if there is an entry which is not a string, use the list as is (e.g. chunked)
            if any(a for a in ids if not isinstance(a, str)):
                for a in items:
                    yield a
            else:
                # one query to load all items that match given ids (max 1000 as defined in chunk size)
                term: Term = P("_key").is_in(ids)
                if expected_kind is not None:
                    term &= P.of_kind(expected_kind)
                query = (
                    Query.by(term)
                    .merge_with("ancestors.cloud", NavigateUntilRoot, P.of_kind("cloud"))
                    .merge_with("ancestors.account", NavigateUntilRoot, P.of_kind("account"))
                    .merge_with("ancestors.region", NavigateUntilRoot, P.of_kind("region"))
                    .merge_with("ancestors.zone", NavigateUntilRoot, P.of_kind("zone"))
                ).rewrite_for_ancestors_descendants(variables)
                query_model = QueryModel(query, model, env)
                async with await self.dependencies.db_access.get_graph_db(GraphName(env["graph"])).search_list(
                    query_model
                ) as crs:
                    async for a in crs:
                        yield a

        return stream.chunks(in_stream, 1000) | pipe.flatmap(load_element)  # type: ignore

    async def no_update(self, _: WorkerTask, future_result: Future[Json]) -> Json:
        return await future_result

    def update_node_in_graphdb(self, model: Model, **env: str) -> Callable[[WorkerTask, Future[Json]], Awaitable[Json]]:
        async def to_result(task: WorkerTask, future_result: Future[Json]) -> Json:
            nid = js_value_at(task.data, ["node", "id"])
            try:
                result = await future_result
                if node := get_node(result):
                    db = self.dependencies.db_access.get_graph_db(GraphName(env["graph"]))
                    try:
                        updated: Json = await db.update_node(model, node["id"], node, True, None)
                        return updated
                    except ClientError as ex:
                        # if the change could not be reflected in database, show success
                        log.warning(
                            f"Update not reflected in db. Wait until next collector run. Reason: {str(ex)}",
                            exc_info=ex,
                        )
                        return node
                else:
                    log.warning(
                        f"Result from worker is not a node. "
                        f"Will not update the internal state. {json.dumps(result)}"
                    )
                    return result
            except Exception as ex:
                return {"error": str(ex), "id": nid}

        return to_result

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
            value = js_value_at(node, path)
            if value:
                result[name] = value
        return result

    @abstractmethod
    def timeout(self) -> timedelta:
        pass


class ExecuteTaskCommand(SendWorkerTaskCommand, InternalPart):
    """
    ```
    execute-task --command <command> --arg <arg> [--no-node-result] [--allowed-on <kind>]
    ```

    This command sends a task to the worker queue. The task is executed by a worker and the result is returned.
    The kind of command is defined by the command name, the arguments are passed via the arg parameter.
    Please note: the arg parameter can hold the complete argument string, containing multiple arguments.

    The `execute-task` command can be used to run a command directly, or pass the result
    of a previous command to a worker.

    You will most likely never invoke this command directly, but use it as custom command with an alias name.

    ## Options
    - `--no-node-result`: By default the result of this command should return a node. This node will be updated in the
       database. If this option is set, the result is not a node and will not be updated in the database.

    ## Parameters
    - `--command`: The name of the command to execute.
    - `--arg`: The argument string to pass to the command.
    - `--allowed-on`: The kind of node this command is allowed to be executed on. If not provided: any value is allowed.

    ## Examples
    ```shell
    # Call the aws task and pass the arguments to the task
    > execute-task --command "aws" --arg "sts get-caller-identity"

    # Search for resources and execute the task for every incoming resource
    > search is(aws_ec2_volume) | execute-task --command "aws" --arg "ec2 describe-volume-attribute --volume-id {id}"
    AutoEnableIO:
      Value: false
    VolumeId: vol-009b0a28d2754927e
    ```
    """

    @property
    def name(self) -> str:
        return "execute-task"

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--command", True, help_text="The name of the command to execute"),
            ArgInfo("--arg", True, help_text="The argument string to pass to the command"),
            ArgInfo(
                "--allowed-on",
                True,
                help_text="The kind of node this command is allowed to be executed on",
                value_hint="kind",
            ),
            ArgInfo("--no-node-result", help_text="The task does not return a node, or the node should not be updated"),
        ]

    def info(self) -> str:
        return "Execute a registered task on the worker"

    def timeout(self) -> timedelta:
        return timedelta(seconds=10)

    def send_command(
        self,
        command_name: str,
        expect_node_result: bool,
        args: Optional[str] = None,
        allowed_on_kind: Optional[str] = None,
        ctx: CLIContext = EmptyContext,
        **kwargs: Any,
    ) -> CLIAction:
        def call_function(jfn: Callable[[Json], Json]) -> Callable[[Json], Tuple[str, Dict[str, str], Json]]:
            def update_single(item: Json) -> Tuple[str, Dict[str, str], Json]:
                return command_name, self.carz_from_node(item), jfn(item)

            return update_single

        formatter, variables = ctx.formatter_with_variables(args or "")
        fn = call_function(lambda item: {"args": args_parts_unquoted_parser.parse(formatter(item)), "node": item})

        def setup_stream(in_stream: JsStream) -> JsStream:
            def with_dependencies(model: Model) -> JsStream:
                load = self.load_by_id_merged(model, in_stream, variables, allowed_on_kind, **ctx.env)
                handler = self.update_node_in_graphdb(model, **ctx.env) if expect_node_result else self.no_update
                return self.send_to_queue_stream(load | pipe.map(fn), handler, True)  # type: ignore

            # dependencies are not resolved directly (no async function is allowed here)
            async def load_model() -> Model:
                return await self.dependencies.model_handler.load_model(ctx.graph_name)

            return stream.call(load_model) | pipe.flatmap(with_dependencies)  # type: ignore

        def setup_source() -> JsStream:
            arg = {"args": args_parts_unquoted_parser.parse(formatter({}))}
            return self.send_to_queue_stream(stream.just((command_name, {}, arg)), self.no_update, True)

        return (
            CLISource.single(setup_source, required_permissions={Permission.write})
            if ctx.query is None
            else CLIFlow(setup_stream, required_permissions={Permission.write})
        )

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        parser = NoExitArgumentParser()
        parser.add_argument("--command", required=True)
        parser.add_argument("--arg")
        parser.add_argument("--no-node-result", action="store_true", default=False)
        parser.add_argument("--allowed-on")
        ns = parser.parse_args(args_parts_unquoted_parser.parse(arg if arg else ""))
        return self.send_command(ns.command, not ns.no_node_result, ns.arg, ns.allowed_on, ctx, **kwargs)


class TagCommand(SendWorkerTaskCommand):
    """
    ```
    tag update [--nowait] <tag_name> [new_value]
    tag delete [--nowait] <tag_name>
    ```

    This command can be used to update or delete a specific tag.
    Tags have a name and value - both name and value are strings. In some cases cloud providers may
    not support values in tags, and only allow names. In that case the value can be omitted.

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

    The input of this command is either a search result or the identifier of the resource as string.

    ## Options
    - `--nowait` if this flag is defined, the cli will send the tag command to the worker
       and will not wait for the task to finish.


    ## Parameters
    - `tag_name` [mandatory]: the name of the tag to change
    - `tag_value` [optional, default: null]: in case of update: the new value of the tag_name.
       If the cloud provider does not support tag values, it can be omitted.
       The tag_value can use format templates (`help format`) to define the value with backreferences from the object.
       Example: test_{name}_{kind} -> test_pvc-123_disk

    ## Examples
    ```shell
    # Make sure there is no resource that is tagged with 'foo'
    > search is(resource) and tags.foo!=null | tag delete foo
    kind=aws_ec2_keypair, id=key-0, name=default, age=1yr8mo, cloud=aws, account=eng-sre, region=us-west-2

    # Manually select the resources to tag by using the id.
    > json["key-0"] | tag delete foo
    kind=aws_ec2_keypair, id=key-0, name=default, age=1yr8mo, cloud=aws, account=eng-sre, region=us-west-2

    # Updating a tag by using a format template.
    > search is(volume) and tags.owner==null limit 1 | tag update owner "gen_{/ancestors.account.reported.name}_{name}"
    kind=gcp_disk, id=123, name=gke-1, age=5mo27d, cloud=gcp, account=eng, region=us-central1, zone=us-central1-c
    ```
    """

    @property
    def name(self) -> str:
        return "tag"

    def info(self) -> str:
        return "Update a tag with provided value or delete a tag."

    def args_info(self) -> ArgsInfo:
        return {
            "update": [ArgInfo("--nowait"), ArgInfo(None, expects_value=True, help_text="<tag-name> [tag-value]")],
            "delete": [ArgInfo("--nowait"), ArgInfo(None, expects_value=True, help_text="<tag-name>")],
        }

    def timeout(self) -> timedelta:
        return timedelta(seconds=30)

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIFlow:
        arg_tokens = args_parts_unquoted_parser.parse(arg if arg else "")
        p = NoExitArgumentParser()
        p.add_argument("--nowait", dest="nowait", default=False, action="store_true")
        ns, rest = p.parse_known_args(arg_tokens)
        variables: Optional[Set[str]] = None

        def change_tag(jfn: Callable[[Json], Json]) -> Callable[[Json], Tuple[str, Dict[str, str], Json]]:
            def update_single(item: Json) -> Tuple[str, Dict[str, str], Json]:
                return WorkerTaskName.tag, self.carz_from_node(item), jfn(item)

            return update_single

        if arg_tokens[0] == "delete" and len(rest) == 2:
            fn = change_tag(lambda item: {"delete": [rest[1]], "node": item})
        elif arg_tokens[0] == "update" and len(rest) == 3:
            _, tag, vin = rest
            formatter, variables = ctx.formatter_with_variables(double_quoted_or_simple_string_dp.parse(vin))
            fn = change_tag(lambda item: {"update": {tag: formatter(item)}, "node": item})
        elif arg_tokens[0] == "update" and len(rest) == 2:
            fn = change_tag(lambda item: {"update": {rest[1]: None}, "node": item})
        else:
            raise AttributeError("Expect update tag_key tag_value or delete tag_key")

        def setup_stream(in_stream: JsStream) -> JsStream:
            def with_dependencies(model: Model) -> JsStream:
                load = self.load_by_id_merged(model, in_stream, variables, **ctx.env)
                result_handler = self.update_node_in_graphdb(model, **ctx.env)
                return self.send_to_queue_stream(load | pipe.map(fn), result_handler, not ns.nowait)  # type: ignore

            async def load_model() -> Model:
                return await self.dependencies.model_handler.load_model(ctx.graph_name)

            # dependencies are not resolved directly (no async function is allowed here)
            return stream.call(load_model) | pipe.flatmap(with_dependencies)  # type: ignore

        return CLIFlow(setup_stream, required_permissions={Permission.write})


class FileCommand(CLICommand, InternalPart):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        def file_command() -> JsStream:
            if not arg:
                raise AttributeError("file command needs a parameter!")
            elif not os.path.exists(arg):
                raise AttributeError(f"file does not exist: {arg}!")
            else:
                return stream.just(arg if arg else "")

        return CLISource.single(file_command, MediaType.FilePath, required_permissions={Permission.admin})

    @property
    def name(self) -> str:
        return "file"

    def info(self) -> str:
        return "only for debugging purposes..."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, value_hint="file", help_text="file to download")]


class UploadCommand(CLICommand, InternalPart):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        if not arg:
            raise AttributeError("upload command needs a parameter!")
        file_id = "file"

        def upload_command() -> JsStream:
            if file_id in ctx.uploaded_files:
                file = ctx.uploaded_files[file_id]
                return stream.just(f"Received file {file} of size {os.path.getsize(file)}")
            else:
                raise AttributeError(f"file was not uploaded: {arg}!")

        return CLISource.single(
            upload_command, MediaType.Json, [CLIFileRequirement(file_id, arg)], required_permissions={Permission.admin}
        )

    @property
    def name(self) -> str:
        return "upload"

    def info(self) -> str:
        return "only for debugging purposes..."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, value_hint="file", help_text="file to upload")]


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
    the fixcore process will stop. It should be restarted by the process supervisor automatically.
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

    # Restore a backup. This will stop the running fixcore instance.
    > system backup restore bck_1234
    Database has been restored successfully!
    Since all data has changed in the database eventually, this service needs to be restarted!

    # Show system information.
    > system info
    name: fixcore
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

    def args_info(self) -> ArgsInfo:
        return {
            "backup": {
                "create": [ArgInfo(None, expects_value=True, help_text="name of the backup file.", value_hint="file")],
                "restore": [
                    ArgInfo(None, expects_value=True, help_text="local backup file to upload.", value_hint="file")
                ],
            },
            "info": [],
        }

    async def create_backup(self, arg: Optional[str]) -> AsyncIterator[JsonElement]:
        maybe_proc: Optional[Process] = None
        async with TemporaryDirectory() as temp_dir:
            try:
                db_config = self.dependencies.config.db
                if not shutil.which("arangodump"):
                    raise CLIParseError("db_backup expects the executable `arangodump` to be in path!")
                # fmt: off
                process = await asyncio.create_subprocess_exec(
                    "arangodump",
                    "--progress", "false",  # do not show progress
                    "--include-system-collections", "true",  # graphs are considered a system collection
                    "--threads", "8",  # default is 2
                    "--log.level", "error",  # only print error messages
                    "--output-directory", temp_dir,  # directory to write to
                    "--overwrite", "true",  # required for existing directories
                    "--server.endpoint", db_config.server.replace("http", "http+tcp"),
                    "--server.authentication", "false" if db_config.no_ssl_verify else "true",
                    "--server.database", db_config.database,
                    "--server.username", db_config.username,
                    "--server.password", db_config.password,
                    "--configuration", "none",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                # fmt: on
                stdout_b, stderr_b = await process.communicate()
                maybe_proc = process
                stdout = stdout_b.decode() if stdout_b else ""
                stderr = stderr_b.decode() if stderr_b else ""
                code = await process.wait()

                if code == 0:
                    log.debug(f"arangodump: out={stdout}, err={stderr}.")
                    files = os.listdir(temp_dir)
                    name = re.sub("[^a-zA-Z0-9_\\-.]", "_", arg) if arg else f'backup_{utc().strftime("%Y%m%d_%H%M")}'
                    backup = os.path.join(temp_dir, name)
                    # create an unzipped tarfile (all of the entries are already gzipped)
                    with tarfile.open(backup, "w") as tar:
                        for file in files:
                            await run_async(tar.add, os.path.join(temp_dir, file), file)
                    yield FilePath.user_local(arg or name, backup).json()
                else:
                    log.error(f"Could not create backup: {code}. out={stdout}, err={stderr}")
                    raise CLIExecutionError(f"Creation of backup failed! Response from process:\n{stderr}")
            finally:
                if maybe_proc and maybe_proc.returncode is None:
                    with suppress(Exception):
                        maybe_proc.kill()
                        await asyncio.sleep(5)

    async def restore_backup(self, backup_file: Optional[str], ctx: CLIContext) -> AsyncIterator[str]:
        if not backup_file:
            raise CLIExecutionError(f"No backup file defined: {backup_file}")
        if not os.path.exists(backup_file):
            raise CLIExecutionError(f"Provided backup file does not exist: {backup_file}")
        if not shutil.which("arangorestore"):
            raise CLIParseError("db_restore expects the executable `arangorestore` to be in path!")

        async with TemporaryDirectory() as temp_dir:
            maybe_proc: Optional[Process] = None
            try:
                # extract tar file
                with tarfile.open(backup_file, "r") as tar:
                    tar.extractall(temp_dir, members=safe_members_in_tarfile(tar))

                # fmt: off
                db_conf = self.dependencies.config.db
                process = await asyncio.create_subprocess_exec(
                    "arangorestore",
                    "--progress", "false",  # do not show progress
                    "--include-system-collections", "true",  # graphs are considered a system collection
                    "--threads", "8",  # default is 2
                    "--log.level", "error",  # only print error messages
                    "--input-directory", temp_dir,  # directory to write to
                    "--overwrite", "true",  # required for existing db collections
                    "--server.endpoint", db_conf.server.replace("http", "http+tcp"),
                    "--server.authentication", "false" if db_conf.no_ssl_verify else "true",
                    "--server.database", db_conf.database,
                    "--server.username", db_conf.username,
                    "--server.password", db_conf.password,
                    "--configuration", "none",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                # fmt: on
                stdout_b, stderr_b = await process.communicate()
                maybe_proc = process
                stdout = stdout_b.decode() if stdout_b else ""
                stderr = stderr_b.decode() if stderr_b else ""
                code = await process.wait()

                if code == 0:
                    log.debug(f"arangorestore: out={stdout}, err={stderr}.")
                    yield "Database has been restored successfully!"
                else:
                    log.error(f"Could not restore backup: {code}. out={stdout}, err={stderr}")
                    raise CLIExecutionError(f"Restore of backup failed! Response from process:\n{stderr}")
            finally:
                if maybe_proc and maybe_proc.returncode is None:
                    with suppress(Exception):
                        maybe_proc.kill()
                        await asyncio.sleep(5)

        log.info("Restore process complete. Restart the service.")
        yield "Since all data has changed in the database eventually, this service needs to be restarted!"
        # for testing purposes, we can avoid sys exit
        if str(ctx.env.get("BACKUP_NO_SYS_EXIT", "false")).lower() != "true":

            async def wait_and_exit() -> None:
                log.info("Database was restored successfully - going to STOP the service!")
                await asyncio.sleep(1)
                restart_service("database backup restored.")

            # create a background task, so that the current request can be executed completely
            asyncio.create_task(wait_and_exit())

    @staticmethod
    async def show_system_info() -> AsyncIterator[Json]:
        info = to_js(system_info())
        yield {"name": "fixcore", **info}

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        parts = re.split(r"\s+", arg if arg else "")
        if len(parts) >= 2 and parts[0] == "backup" and parts[1] == "create":
            rest = parts[2:]

            def backup() -> AsyncIterator[JsonElement]:
                return self.create_backup(" ".join(rest) if rest else None)

            return CLISource.single(backup, MediaType.FilePath, required_permissions={Permission.admin})

        elif len(parts) == 3 and parts[0] == "backup" and parts[1] == "restore":
            backup_file = parts[2]

            def restore() -> AsyncIterator[JsonElement]:
                return self.restore_backup(ctx.uploaded_files.get("backup"), ctx)

            return CLISource.single(
                restore,
                MediaType.Json,
                [CLIFileRequirement("backup", backup_file)],
                required_permissions={Permission.admin},
            )
        elif len(parts) == 1 and parts[0] == "info":
            return CLISource.single(self.show_system_info, required_permissions={Permission.read})
        else:
            raise CLIParseError(f"system: Can not parse {arg}")


class WriteCommand(CLICommand, NoTerminalOutput):
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
    > search all limit 3 | format --json | write out.json
    Received a file out.json, which is stored to ./out.json.

    # Select the root node and traverse 2 levels deep. Format the result as dot graph and write it to out.dot.
    > search --with-edges id(root) -[0:2]-> | format --dot | write out.dot
    Received a file out.dot, which is stored to ./out.dot.
    ```
    """

    @property
    def name(self) -> str:
        return "write"

    def info(self) -> str:
        return "Writes the incoming stream of data to a file in the defined format."

    def args_info(self) -> ArgsInfo:
        return [ArgInfo(expects_value=True, value_hint="file", help_text="file to write to")]

    @staticmethod
    async def write_result_to_file(ctx: CLIContext, in_stream: JsStream, file_name: str) -> AsyncIterator[JsonElement]:
        async with TemporaryDirectory() as temp_dir:
            path = file_name if ctx.intern else os.path.join(temp_dir, uuid_str())
            async with aiofiles.open(path, "w") as f:
                async with in_stream.stream() as streamer:
                    async for out in streamer:
                        if isinstance(out, str):
                            await f.write(out + "\n")
                        else:
                            raise AttributeError("No output format is defined! Consider to use the format command.")
            yield FilePath.user_local(user=file_name, local=path).json()

    @staticmethod
    async def already_file_stream(in_stream: JsStream, file_name: str) -> AsyncIterator[JsonElement]:
        async with in_stream.stream() as streamer:
            async for out in streamer:
                yield evolve(FilePath.from_path(out), user=Path(file_name)).json()

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        if arg is None:
            raise AttributeError("write requires a filename to write to")
        if (ex := self.get_previous_command(kwargs)) and ex.action.produces == MediaType.FilePath:
            fn = self.already_file_stream
        else:
            fn = partial(self.write_result_to_file, ctx)
        return CLIFlow(lambda in_stream: fn(in_stream, arg), MediaType.FilePath, required_permissions={Permission.read})


class TemplatesCommand(CLICommand, PreserveOutputFormat):
    """
    ```shell
    templates
    templates <name_of_template>
    templates add <name_of_template> <search_template>
    templates update <name_of_template> <search_template>
    templates delete <name_of_template>
    templates test key1=value1, key2=value2, ..., keyN=valueN <template_to_expand>
    ```

    - `templates: get the list of all templates
    - `templates <name>`: get the current definition of the template defined by given template name
    - `templates add <name> <template>`: add a search template to the search template library under given name.
    - `templates update <name> <template>`: update a search template in the search template library.
    - `templates delete <name>`: delete the search template with given name.
    - `templates test k=v <template_to_expand>`: test the defined template.

    Placeholders are defined in 2 double curly braces {{placeholder}}
    and get replaced by the provided placeholder value during render_console time.
    The name of the placeholder can be any valid alphanumeric string.
    The template 'is({{kind}})' with expand parameters kind=volume becomes
    'is(volume)' during expand time.

    ## Parameters

    - `name_of_template`:  The name of the search template.
    - `search_template`:  The search with template placeholders.
    - `key=value`: any number of key/value pairs separated by comma

    ## Examples
    ```shell
    # Test a template by populating it with provided key/value pairs
    > templates test kind=volume is({{kind}})
    is(volume)

    # Add a very simple template with name filter_kind to the search library
    > templates add filter_kind is({{kind}})
    Template filter_kind added to the search library.
    is({{kind}})

    # List all templates in the search library
    > templates
    filter_kind: is({{kind}})

    # Show one specific template by provided name
    > templates filter_kind
    is({{kind}})

    # Use this template in a search
    > search expand(filter_kind, kind=volume) and name=~dkl
    kind=aws_ec2_volume, id=vol-1, name=dkl-3, age=2mo2d, cloud=aws, account=eng, region=us-west-2

    > templates delete filter_kind
    Template filter_kind deleted from the search library.
    ```
    """

    @property
    def name(self) -> str:
        return "templates"

    def info(self) -> str:
        return "Access the search template library."

    def args_info(self) -> ArgsInfo:
        return {
            "add": [ArgInfo(None, expects_value=True, help_text="<name> <template>")],
            "delete": [ArgInfo(None, expects_value=True, help_text="<name>")],
            "test": [ArgInfo(None, expects_value=True, help_text="<key1>=<value1>, ..., <keyN>=<valueN> <template>")],
            "update": [ArgInfo(None, expects_value=True, help_text="<name> <template>")],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        def template_str(template: Template) -> str:
            tpl_str = f"{template.template[0:70]}..." if len(template.template) > 70 else template.template
            return f"{template.name}: {tpl_str}"

        async def get_template(name: str) -> AsyncIterator[JsonElement]:
            maybe_template = await self.dependencies.template_expander.get_template(name)
            yield maybe_template.template if maybe_template else f"No template with this name: {name}"

        async def list_templates() -> Tuple[int, Stream[str]]:
            templates = await self.dependencies.template_expander.list_templates()
            return len(templates), stream.iterate(template_str(t) for t in templates)

        async def put_template(name: str, template_query: str) -> AsyncIterator[str]:
            # try to render_console the template with dummy values and see if the search can be parsed
            try:
                rendered_query = self.dependencies.template_expander.render(template_query, defaultdict(lambda: True))
                parse_query(rendered_query, ctx.env)
            except Exception as ex:
                raise CLIParseError(f"Given template does not define a valid search: {template_query}") from ex
            await self.dependencies.template_expander.put_template(Template(name, template_query))
            yield f"Template {name} added to the search library.\n{template_query}"

        async def delete_template(name: str) -> AsyncIterator[str]:
            await self.dependencies.template_expander.delete_template(name)
            yield f"Template {name} deleted from the search library."

        async def expand_template(spec: str) -> AsyncIterator[str]:
            maybe_dict, template = tpl_props_p.parse_partial(spec)
            yield self.dependencies.template_expander.render(template, maybe_dict if maybe_dict else {})

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] in ("add", "update"):
            nm, tpl = re.split("\\s+", args[1], maxsplit=1)
            return CLISource.single(
                partial(put_template, nm.strip(), tpl.strip()), required_permissions={Permission.admin}
            )
        elif arg and len(args) == 2 and args[0] == "delete":
            return CLISource.single(partial(delete_template, args[1].strip()), required_permissions={Permission.admin})
        elif arg and len(args) == 2 and args[0] == "test":
            return CLISource.single(partial(expand_template, args[1].strip()), required_permissions={Permission.read})
        elif arg and len(args) == 2:
            raise CLIParseError(f"Does not understand action {args[0]}. Allowed: add, update, delete, test.")
        elif arg and len(args) == 1:
            return CLISource.single(partial(get_template, arg.strip()), required_permissions={Permission.read})
        elif not arg:
            return CLISource.only_count(list_templates, required_permissions={Permission.read})
        else:
            raise CLIParseError(f"Can not parse arguments: {arg}")


@define
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
    auth: Optional[str]


class HttpCommand(CLICommand):
    """
    ```shell
    http[s] [--compress] [--timeout <seconds>] [--no-ssl-verify] [--no-body] [--nr-of-retries <num>]
            [--auth username:password] [http_method] <url> [headers] [query_params]
    ```

    This command takes every object from the incoming stream and sends this object to the defined http(s) endpoint.
    The payload of the request contains the object.
    The shape and format of the object can be adjusted with other commands like: list, format, jq, etc.
    Note: you can use the chunk command to send chunks of objects.
          E.g.: search is(volume) limit 30 | chunk 10 | http test.foo.org
                will perform up to 3 requests, where every request will contain up to 10 elements.

    ## Options
    - `--compress` [optional]: enable compression of the request body
    - `--timeout` <seconds> [optional, default: 30]: if the request takes longer than the specified seconds
      it will be aborted
    - `--no-ssl-verify` [optional]: the ssl certificate will not be verified.
    - `--no-body` [optional]: if this flag is enabled, no content is sent in the request body
    - `--nr-of-retries` [optional, default=3]: in case the request is not successful (no 2xx), the request
      is retried this often. There will be an exponential backoff between the retries.
    - `--auth` [optional]: if this option is set, the given username and password will be used for basic auth.

    ## Parameters
    - `http_method` [optional, default: POST]: one of GET, PUT, POST, DELETE or PATCH
    - `url`: the full url of the endpoint to call. Example: https://localhost:8080/call/me
      If the scheme is not defined, it is taken from the command (http or https).
      If the host is localhost, it can be omitted (e.g. :8080/call/me)
    - `headers`: a list of http headers can be defined via <header_name>:<header_value>
      Example: HeaderA:test HeaderB:rest
      Note: You can use quotes to use whitespace chars: "HeaderC:this is the value"
    - `query_params`: a list of search parameters can be defined via <param>==<param_value>.
      Example: param1==test param2==rest
      Note: You can use quotes to use whitespace chars: "param3==this is the value"


    ## Examples
    ```shell
    # Look for unencrypted volumes and report them to the specified endpoint
    > search is(volume) and reported.volume_encrypted==false | https my.node.org/handle_unencrypted
    3 requests with status 200 sent.

    # search all volumes and send chunks of 50 volumes per request to the specified handler
    > search is(volume) | chunk 50 | https --compress my.node.org/handle
    2 requests with status 200 sent.

    # Same search as before, but define special header values and search parameter
    > search is(volume) | chunk 50 | https my.node.org/handle "greeting:hello from fixcore" type==volume
    2 requests with status 200 sent.
    ```
    """

    @property
    def name(self) -> str:
        return "http"

    def info(self) -> str:
        return "Perform http request with incoming data."

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--compress"),
            ArgInfo("--timeout", expects_value=True, help_text="Timeout in seconds"),
            ArgInfo("--no-ssl-verify"),
            ArgInfo("--no-body"),
            ArgInfo("--nr-of-retries", expects_value=True, help_text="Number of retries"),
            ArgInfo("--auth", expects_value=True, help_text="Basic auth <username>:<password>"),
            ArgInfo(None, expects_value=True, help_text="<method> <url> <headers> <query_params>"),
        ]

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
        arg_parser.add_argument("--auth", dest="auth", default=None, type=str)
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
                args.auth,
            )
        else:
            raise AttributeError("No URL provided to connect to.")

    def perform_requests(self, template: HttpRequestTemplate) -> Callable[[JsStream], AsyncIterator[JsonElement]]:
        retries_left = template.retries

        async def perform_request(e: JsonElement) -> int:
            nonlocal retries_left
            data = None if template.no_body else (JsonPayload(e) if isinstance(e, (dict, list)) else e)
            authuser, authpass = template.auth.split(":", 1) if template.auth else (None, None)
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
                    ssl=False if template.no_ssl_verify else self.dependencies.cert_handler.client_context,
                    auth=BasicAuth(login=authuser, password=(authpass if authpass else "")) if authuser else None,
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

        async def iterate_stream(in_stream: JsStream) -> AsyncIterator[JsonElement]:
            results: Dict[int, int] = defaultdict(lambda: 0)
            async with in_stream.stream() as streamer:
                async for elem in streamer:
                    status_code = await perform_request(elem)
                    results[status_code] += 1
            summary = ", ".join(f"{count} requests with status {status}" for status, count in results.items())
            if results:
                yield f"{summary} sent."

        return iterate_stream

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        # command name is the default scheme: http, https etc.
        default_scheme = kwargs.get("cmd_name", "http")
        template = self.parse_args(default_scheme, arg)
        return CLIFlow(self.perform_requests(template), required_permissions={Permission.read})


class WorkflowsCommand(CLICommand):
    """
    ```shell
    workflows list
    workflows show <id>
    workflows run <id>
    workflows stop <task_id>
    workflows running
    workflows history
    workflows history <id> --started-before <date> --started-after <date> --has-errors --limit <num>
    workflows log <workflow-run-id>
    ```

    - `workflows list`: get the list of all workflows in the system
    - `workflows show <id>`: show the current definition of the workflow defined by given identifier.
    - `workflows run <id>`: run the workflow as if the trigger would be triggered.
    - `workflows stop <task_id>`: stop a running workflow execution.
    - `workflows running`: show all currently running workflows.
    - `workflows history`: aggregated history of all workflows.
    - `workflows history <id>`: show all runs of this workflow based on defined filter criteria.
    - `workflows log <workflow-run-id>`: show the log of the workflow run.

    The workflows that currently available are all hard-wired into fixcore.
    We will support user defined workflows in the future.

    *Note:*

    If a workflow is triggered, while it is already running, the invocation will wait for the current run to finish.
    This means that there will be no parallel execution of workflows with the same identifier at any moment in time.

    ## Options
    - `--id` <id> [optional]: The identifier of this workflow.
    - `--started-before` <date> [optional]: Filter for workflow runs that started before this date.
    - `--started-after` <date> [optional]: Filter for workflow runs that started after this date.
    - `--has-errors` [optional]: Filter for workflow runs that have errors.
    - `--limit` <num> [optional]: Limit the number of workflow runs to show.

    ## Examples

    ```shell
    # print all available workflows in the system
    > workflows list
    collect
    cleanup
    metrics
    collect_and_cleanup

    # show a specific workflows by identifier
    > workflows show collect
    id: collect
    name: collect
    steps:
    - action:
        message_type: pre_collect
      name: pre_collect
      on_error: Continue
      timeout: 10.0
    - action:
        message_type: collect
      name: collect
      on_error: Continue
      timeout: 10.0
    - action:
        message_type: post_collect
      name: post_collect
      on_error: Continue
      timeout: 10.0
    - action:
        message_type: pre_generate_metrics
      name: pre_generate_metrics
      on_error: Continue
      timeout: 10.0
    - action:
        message_type: generate_metrics
      name: generate_metrics
      on_error: Continue
      timeout: 10.0
    - action:
        message_type: post_generate_metrics
      name: post_generate_metrics
      on_error: Continue
      timeout: 10.0
    triggers:
    - filter_data: null
      message_type: start_collect_workflow
    on_surpass: Wait

    # run the workflow directly without waiting for a trigger
    > workflows run collect
    Workflow collect started with id cb1013a4-8e81-11ec-8fc0-dad780437c54.

    # show all currently running workflows
    > workflows running
    workflow: collect_and_cleanup
    started: '2022-11-04T12:33:32Z'
    task-id: e514fbd2-5c3c-11ed-894d-dad780437c53
    progress: 16%
    current-step: collect
    step-info:
      collect:
        digitalocean:
          '10225075': in progress
        aws:
          '882347060974':
            collect-global: in progress
        k8s: done

    # show the history of all workflows
    > workflows history
    collect:
      count: 264
      last_run: '2022-11-04T12:33:32Z'
      runs_with_errors: 1
      average_duration: 18s
    collect_and_cleanup:
      count: 3416
      last_run: '2022-11-04T12:00:00Z'
      runs_with_errors: 0
      average_duration: 34s

    # show the history of a specific workflow
    > workflows history collect --started-after 2022-11-03 --started-before 2022-11-05 --has-errors --limit 10
    id: 037f23c6-5c1b-11ed-bb8b-dad780437c53
    task_started_at: '2022-11-04T08:31:01Z'
    duration: 87.786464
    errors: 19

    # show the log of a specific workflow run
    > workflows log 037f23c6-5c1b-11ed-bb8b-dad780437c53
    2022-11-04T08:31:01Z: collect: collect: aws: 882347060974: collect-global: in progress
    [aws:123456789] Access Denied to aws_account 123456789
    [aws:234567890] An AWS UnauthorizedOperation error occurred while collecting account test
    ```
    """

    @property
    def name(self) -> str:
        return "workflows"

    def info(self) -> str:
        return "Manage all workflows."

    def args_info(self) -> ArgsInfo:
        return {
            "show": [ArgInfo(None, help_text="<workflow-id>")],
            "list": [],
            "run": [ArgInfo(None, help_text="<workflow-id>")],
            "stop": [ArgInfo(None, help_text="<task-id>")],
            "running": [],
            "history": [
                ArgInfo(None, help_text="<workflow-id>"),
                ArgInfo("--started-before", help_text="<date>", value_hint="date", expects_value=True),
                ArgInfo("--started-after", help_text="<date>", value_hint="date", expects_value=True),
                ArgInfo("--limit", help_text="<number of entries>", expects_value=True),
                ArgInfo("--has-errors"),
            ],
            "log": [ArgInfo(None, help_text="<workflow-run-id>")],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLISource:
        async def list_workflows() -> Tuple[int, AsyncIterator[JsonElement]]:
            listed = await self.dependencies.task_handler.list_workflows()

            async def iterate() -> AsyncIterator[JsonElement]:
                for wf in listed:
                    yield wf.id

            return len(listed), iterate()

        async def show_workflow(wf_id: str) -> AsyncIterator[JsonElement]:
            matching = [wf for wf in await self.dependencies.task_handler.list_workflows() if wf.id == wf_id]
            if matching:
                yield to_js(matching[0])
            else:
                yield f"No workflow with this id: {wf_id}"

        async def run_workflow(wf_id: str) -> AsyncIterator[str]:
            info = await self.dependencies.task_handler.start_task_by_descriptor_id(TaskDescriptorId(wf_id))
            if info and info.scheduled_next:
                task = info.running_task
                yield (
                    f"Workflow {task.descriptor.id} already running with id {task.id}. "
                    "Scheduled next run after this one is completed"
                )
            elif info:
                task = info.running_task
                yield f"Workflow {task.descriptor.id} started with id {task.id}."
            else:
                yield f"No workflow with this id: {wf_id}"

        async def running_workflows() -> Tuple[int, JsStream]:
            tasks = await self.dependencies.task_handler.running_tasks()

            def info(rt: RunningTask) -> JsonElement:
                # show progress only if the task is still active
                progress = (
                    {
                        "progress": f"{rt.progress.percentage}%",
                        "current-step": rt.current_step.name,
                        "step-info": rt.current_step_progress.info_json(),
                    }
                    if rt.is_active
                    else {"progress": "done"}
                )
                # only show the number of error messages, not the actual messages (it can get big)
                messages = {"errors": f"{len(rt.info_messages)} errors"} if rt.info_messages else {}
                return {
                    "workflow": rt.descriptor.id,
                    "started": to_json(rt.task_started_at),
                    "task-id": rt.id,
                    **messages,
                    **progress,
                }

            return len(tasks), stream.iterate(info(t) for t in tasks if isinstance(t.descriptor, Workflow))

        async def show_log(wf_id: str) -> Tuple[int, JsStream]:
            rtd = await self.dependencies.db_access.running_task_db.get(wf_id)
            if rtd:
                messages = [msg.info() for msg in rtd.info_messages()]
                if messages:
                    return len(messages), stream.iterate(messages)
                else:
                    return 0, stream.just("No error messages for this run.")
            else:
                return 0, stream.just(f"No workflow task with this id: {wf_id}")

        def running_task_data(rtd: RunningTaskData) -> Json:
            result = {
                "id": rtd.id,
                "task_started_at": to_json(rtd.task_started_at),
                "duration": to_json(rtd.task_duration),
            }
            if rtd.has_error or rtd.has_info:
                result["errors"] = len(rtd.info_messages())
            return result

        async def history_aggregation() -> JsStream:
            info = await self.dependencies.db_access.running_task_db.aggregated_history()
            return stream.just(info)

        async def history_of(history_args: List[str]) -> Tuple[int, JsStream]:
            parser = NoExitArgumentParser()
            parser.add_argument("workflow")
            parser.add_argument("--started-after", dest="started_after", type=date_parser.parse)
            parser.add_argument("--started-before", dest="started_before", type=date_parser.parse)
            parser.add_argument("--has-errors", dest="has_errors", action="store_true", default=None)
            parser.add_argument("--limit", type=int, default=10)
            parsed = parser.parse_args(history_args)
            context = await self.dependencies.db_access.running_task_db.filtered(
                descriptor_id=parsed.workflow,
                started_after=parsed.started_after,
                started_before=parsed.started_before,
                with_error=parsed.has_errors,
                limit=parsed.limit,
            )
            cursor: AsyncCursor = context.cursor
            try:
                return cursor.count() or 0, stream.map(cursor, running_task_data)  # type: ignore
            finally:
                cursor.close()

        async def stop_workflow(task_id: TaskId) -> AsyncIterator[str]:
            if await self.dependencies.task_handler.stop_task(task_id) is not None:
                yield f"Workflow Task {task_id} stopped."
            else:
                yield "No running workflow with this id."

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] == "show":
            return CLISource.single(partial(show_workflow, args[1].strip()), required_permissions={Permission.read})
        elif arg and len(args) == 1 and args[0] == "history":
            return CLISource.single(history_aggregation, required_permissions={Permission.read})
        elif arg and len(args) == 2 and args[0] == "history":
            return CLISource.only_count(
                partial(history_of, re.split("\\s+", args[1])), required_permissions={Permission.read}
            )
        elif arg and len(args) == 2 and args[0] == "log":
            return CLISource.only_count(partial(show_log, args[1].strip()), required_permissions={Permission.read})
        elif arg and len(args) == 2 and args[0] == "run":
            return CLISource.single(partial(run_workflow, args[1].strip()), required_permissions={Permission.admin})
        elif arg and len(args) == 2 and args[0] == "stop":
            return CLISource.single(partial(stop_workflow, args[1].strip()), required_permissions={Permission.admin})
        elif arg and len(args) == 1 and args[0] == "running":
            return CLISource.only_count(running_workflows, required_permissions={Permission.read})
        elif arg and len(args) == 1 and args[0] == "list":
            return CLISource.only_count(list_workflows, required_permissions={Permission.read})
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


@make_parser
def path_value_parser() -> Parser:
    key = yield variable_p
    yield equals_p
    value = yield json_value_p
    return key, value


path_values_parser = path_value_parser.sep_by(comma_p)


class ConfigsCommand(CLICommand):
    """
    ```shell
    configs list
    configs show <cfg_id>
    configs set <cfg_id> <prop>=<value> [, <prop>=<value>]
    configs edit <cfg_id>
    configs copy <cfg_id> <new_cfg_id>
    configs update <cfg_id> <path>
    configs delete <cfg_id>
    ```

    - `configs list`: get the list of all config ids in the system.
    - `configs show <cfg_id>`: show the configuration with provided identifier.
    - `configs set <cfg_id> <prop>=<value>`: set one or more property values in the configuration with provided id.
    - `configs edit <cfg_id>`: edit the complete configuration with provided id as file
    - `configs copy <cfg_id> <new_cfg_id>`: copy the configuration with provided id
       to a new configuration with the provided new id.
    - `configs update <cfg_id> <path>`: update or create the configuration with provided id with content of given file.
    - `configs delete <cfg_id>`: delete the configuration with given identifier.

    ## Parameters
    - cfg_id [mandatory]: The identifier of the configuration.
    - prop: the path of the property to set. Nested properties can be accessed via `.`.
    - value: the value of the property path to set. It can be any json conform element.
    - path: the path of the file that holds the configuration to upate.

    ## Examples

    ```shell
    # Set properties of the configuration "test".
    # Note: if the configuration does not exist, it is created automatically.
    > config set test prop_a=test, prop_b=2, array_prop=[1,2,3,4]
    array_prop:
    - 1
    - 2
    - 3
    - 4
    prop_a: test
    prop_b: 2

    # Update the same configuration by setting only one property.
    > config set test prop_a="some other value"
    array_prop:
    - 1
    - 2
    - 3
    - 4
    prop_a: some other value
    prop_b: 2

    # This will open the configuration in your local editor.
    # Once the editor is closed, the configuration is updated.
    > config edit test

    # Update the configuration test by loading the provided config file.
    > config update test /path/to/my/local/config.yaml

    # Copy the configuration test to a new configuration test2.
    > config copy test test2

    # Get the list of all configuration keys.
    > config list
    config_test
    fix.core
    fix.worker.1
    fix.worker.2
    fix.metrics

    # Delete the config with name
    > config delete config_test
    Config config_test has been deleted.
    ```
    """

    @property
    def name(self) -> str:
        return "configs"

    def info(self) -> str:
        return "Manage configuration settings."

    def args_info(self) -> ArgsInfo:
        return {
            "list": [],
            "set": [ArgInfo(None, expects_value=True, help_text="<config_id> <key>=<value>")],
            "show": [ArgInfo(None, expects_value=True, help_text="<config_id> e.g. fix.core")],
            "edit": [ArgInfo(None, expects_value=True, help_text="<config_id>")],
            "copy": [ArgInfo(None, expects_value=True, help_text="<config_id> <new_config_id>")],
            "update": [
                ArgInfo(None, expects_value=True, help_text="<config_id> /path/to/config.yaml", value_hint="file")
            ],
            "delete": [ArgInfo(None, expects_value=True, help_text="<config_id>")],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def show_config(cfg_id: ConfigId) -> AsyncIterator[JsonElement]:
            cfg = await self.dependencies.config_handler.config_yaml(cfg_id)
            yield cfg if cfg else f"No config with this id: {cfg_id}"

        async def delete_config(cfg_id: ConfigId) -> AsyncIterator[str]:
            await self.dependencies.config_handler.delete_config(cfg_id)
            yield f"Config {cfg_id} has been deleted."

        async def send_file(content: str) -> AsyncIterator[str]:
            async with TemporaryDirectory() as temp_dir:
                path = os.path.join(temp_dir, "config.yaml")
                async with aiofiles.open(path, "w") as f:
                    await f.write(content)
                yield path

        async def set_config(cfg_id: ConfigId, updates: List[Tuple[str, JsonElement]]) -> AsyncIterator[JsonElement]:
            cfg = await self.dependencies.config_handler.get_config(cfg_id)
            updated = cfg.config if cfg else {}
            for prop, js in updates:
                updated = set_value_in_path(js, prop, updated)
            await self.dependencies.config_handler.put_config(ConfigEntity(cfg_id, updated))
            yield await self.dependencies.config_handler.config_yaml(cfg_id)

        async def edit_config(cfg_id: ConfigId) -> AsyncIterator[str]:
            # Editing a config is a two-step process:
            # 1) download the config and make it available to edit
            # 2) upload the config file and update the config from content --> update_config
            yml = await self.dependencies.config_handler.config_yaml(cfg_id, revision=True)
            if not yml:
                raise AttributeError(f"No config with this id: {cfg_id}")
            return send_file(yml)

        async def copy_config(from_cfg_id: ConfigId, to_cfg_id: ConfigId) -> AsyncIterator[str]:
            cfg = await self.dependencies.config_handler.get_config(from_cfg_id)
            if not cfg:
                raise AttributeError(f"No config with this id: {from_cfg_id}")
            await self.dependencies.config_handler.copy_config(from_cfg_id, to_cfg_id)
            yield f"Config {from_cfg_id} has been copied to {to_cfg_id}."

        async def update_config(cfg_id: ConfigId) -> AsyncIterator[str]:
            # Usually invoked by resh automatically via edit_config, but can also be triggered manually.
            # A config with given id is changed by the content of uploaded file "config"
            try:
                content = ""
                async with aiofiles.open(ctx.uploaded_files["config.yaml"], "r") as f:
                    content = await f.read()
                    updated: Json = yaml.safe_load(content)
                    revision = updated.pop("_revision", None)
                await self.dependencies.config_handler.put_config(ConfigEntity(cfg_id, updated, revision))
            except Exception as ex:
                log.debug(f"Could not update the config: {ex}.", exc_info=ex)
                # Yaml file: add the error as comment on top
                error = "\n".join(f"## {line}" for line in str(ex).splitlines())
                message = f"## Update the config failed. Please correct.\n{error}\n\n"
                # Remove error message from previous check
                config = "\n".join(dropwhile(lambda m: m.startswith("##") or len(m.strip()) == 0, content.splitlines()))
                async for file in send_file(message + config):
                    yield file

        async def list_configs() -> Tuple[int, JsStream]:
            ids = [i async for i in self.dependencies.config_handler.list_config_ids()]
            return len(ids), stream.iterate(ids)

        args = re.split("\\s+", arg, maxsplit=2) if arg else []
        if arg and len(args) == 2 and (args[0] == "show" or args[0] == "get"):
            return CLISource.single(partial(show_config, args[1]), required_permissions={Permission.admin})
        elif arg and len(args) == 2 and args[0] == "delete":
            return CLISource.single(partial(delete_config, args[1]), required_permissions={Permission.admin})
        elif arg and len(args) == 3 and args[0] == "set":
            update = path_values_parser.parse(args[2])
            return CLISource.single(partial(set_config, args[1], update), required_permissions={Permission.admin})
        elif arg and len(args) == 2 and args[0] == "edit":
            config_id = args[1]
            return CLISource.single(
                partial(edit_config, config_id),
                produces=MediaType.FilePath,
                envelope={CLIEnvelope.action: "edit", CLIEnvelope.command: f"configs update {config_id}"},
                required_permissions={Permission.admin},
            )
        elif arg and len(args) == 3 and args[0] == "copy":
            return CLISource.single(partial(copy_config, args[1], args[2]), required_permissions={Permission.admin})
        elif arg and len(args) == 3 and args[0] == "update":
            config_id = args[1]
            return CLISource.single(
                partial(update_config, config_id),
                produces=MediaType.FilePath,
                envelope={CLIEnvelope.action: "edit", CLIEnvelope.command: f"configs update {config_id}"},
                requires=[CLIFileRequirement("config.yaml", args[2])],
                required_permissions={Permission.admin},
            )
        elif arg and len(args) == 1 and args[0] == "list":
            return CLISource.only_count(list_configs, required_permissions={Permission.read})
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


@lru_cache(maxsize=1024)
def get_session_strategy(policy: SuggestionPolicy, session_id: str, clouds: FrozenSet[str]) -> SuggestionStrategy:
    return get_suggestion_strategy(policy, clouds)


def add_tod_block(info: Table, policy: SuggestionPolicy, session_id: str, clouds: FrozenSet[str]) -> None:
    """
    Add a block with the current tip of day to the info table.
    """
    strategy = get_session_strategy(policy, session_id, clouds)
    sod = strategy.suggest()
    info.add_row(Text("Tip of the day:", style="#762dd7 italic"))
    info.add_row(Text(sod.command_line, style="bold"))
    info.add_row(Text(sod.description, style="dim"))


FixWorkerConfigId = ConfigId("fix.worker")


class WelcomeCommand(CLICommand, InternalPart):
    """
    ```shell
    welcome
    ```
    Show a welcome message to the user.
    """

    with open(os.path.dirname(__file__) + "/../static/ck-unicode-truecolor.ans", "r", encoding="utf-8") as ckf:
        ck = Text.from_ansi(ckf.read())

    @property
    def name(self) -> str:
        return "welcome"

    def info(self) -> str:
        return "Show a welcome message to the user."

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def welcome() -> str:
            info = Table.grid(expand=True)
            info.add_column(justify="center")
            info.add_row(Text("Fix Inventory", style="bold"))
            info.add_row(Text(f"Version: {version()}", style="dim"))

            info.add_row(Padding("", pad=(0, 0, 0, 0)))
            fixworker_config = await self.dependencies.config_handler.get_config(FixWorkerConfigId)
            if fixworker_config:
                confiugured_collectors = frozenset(
                    fixworker_config.config.get("fixworker", {}).get("collector", []) or []
                )
            else:
                confiugured_collectors = frozenset()

            add_tod_block(info, SuggestionPolicy.DAILY, ctx.env.get("session_id", ""), confiugured_collectors)
            # ck mascot is centered (rendered if color is enabled)
            center_horizont = (
                int((ctx.console_renderer.width - 22) / 2)
                if ctx.console_renderer is not None and ctx.console_renderer.width is not None
                else 0
            )
            center_vertical = (
                # this is the height of the area that we show
                max(0, int(ctx.console_renderer.height - 27))
                if ctx.console_renderer is not None and ctx.console_renderer.height is not None
                else 0
            )
            grid = Table.grid(expand=True)
            grid.add_column()
            grid.add_row(Padding("", pad=(center_vertical, 0, 0, 0)))
            grid.add_row(Padding(WelcomeCommand.ck if ctx.supports_color() else "", pad=(0, 0, 1, center_horizont)))
            grid.add_row(info)
            grid.add_row(
                Panel(
                    "[b]> help[/b] for on-line help\n"
                    "[b]> help[/b] [i]<cmd>[/i] to get help on a command\n"
                    "[b]> totd[/b] to see another tip of the day"
                )
            )

            res = ctx.render_console(grid)
            return res

        return CLISource.single(lambda: stream.just(welcome()), required_permissions={Permission.read})  # type: ignore


class TipOfTheDayCommand(CLICommand):
    """
    ```shell
    totd
    ```
    Show the tip of the day.
    """

    @property
    def name(self) -> str:
        return "totd"

    def info(self) -> str:
        return "Show the tip of the day to the user."

    def args_info(self) -> ArgsInfo:
        return []

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def totd() -> str:
            info = Table.grid(expand=True)
            info.add_column(justify="center")
            fixworker_config = await self.dependencies.config_handler.get_config(FixWorkerConfigId)
            if fixworker_config:
                confiugured_collectors = frozenset(
                    fixworker_config.config.get("fixworker", {}).get("collector", []) or []
                )
            else:
                confiugured_collectors = frozenset()
            add_tod_block(info, SuggestionPolicy.NON_REPEATING, ctx.env.get("session_id", ""), confiugured_collectors)

            res = ctx.render_console(info)
            return res

        return CLISource.single(lambda: stream.just(totd()), required_permissions={Permission.read})  # type: ignore


class CertificateCommand(CLICommand):
    """
    ```shell
    certificate create --common-name <common-name> [--dns-names <dns-name>...<dns-name>] \
    [--ip-addresses <ip-address>...<ip-address>] [--days-valid <days-valid>]
    ```

    Create a new TLS key and certificate based on the internal root CA certificate.
    This can be used to create a self-signed certificate for additional components that communicate with Fix Inventory.


    ## Parameters
    - common-name [mandatory]: server name protected by the ssl certificate.
    - dns-names [optional]: DNS names that the certificate should be valid for.
    - ip-addresses [optional]: IP addresses that the certificate should be valid for.
    - days-valid [optional, default to 365]: number of days the certificate should be valid.

    ## Examples

    ```shell
    > tls create --common-name "example.com" --dns-names "example.com" "*.example.com" --days-valid 365
    Received a file host_key.pem, which is stored to ./host_key.pem.
    Received a file host_cert.pem, which is stored to ./host_cert.pem.
    ```
    """

    @property
    def name(self) -> str:
        return "certificate"

    def info(self) -> str:
        return "Create TLS certificates."

    def args_info(self) -> ArgsInfo:
        return {
            "create": [
                ArgInfo("--common-name", True, help_text="Common name like: example.com"),
                ArgInfo("--dns-names", True, help_text="List of other dns names: example.org example.io"),
                ArgInfo("--ip-addresses", True, help_text="List of ip addresses: 1.2.3.4 2.3.4.5"),
            ]
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def create_certificate(
            common_name: str, dns_names: List[str], ip_addresses: List[str], days_valid: int
        ) -> AsyncIterator[str]:
            key, cert = self.dependencies.cert_handler.create_key_and_cert(
                common_name, dns_names, ip_addresses, days_valid
            )
            async with TemporaryDirectory() as tmpdir:
                key_file = os.path.join(tmpdir, f"{common_name}.key")
                cert_file = os.path.join(tmpdir, f"{common_name}.crt")
                write_cert_to_file(cert, cert_file, rename=False)
                write_key_to_file(key, key_file, rename=False)
                yield key_file
                yield cert_file

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if len(args) == 2 and args[0] == "create":
            parser = NoExitArgumentParser()
            parser.add_argument("--common-name", required=True)
            parser.add_argument("--dns-names", nargs="+", default=[])
            parser.add_argument("--ip-addresses", nargs="+", default=[])
            parser.add_argument("--days-valid", type=int, default=365)
            parsed = parser.parse_args(args[1].split())
            return CLISource.with_count(
                partial(
                    create_certificate, parsed.common_name, parsed.dns_names, parsed.ip_addresses, parsed.days_valid
                ),
                2,
                produces=MediaType.FilePath,
                required_permissions={Permission.admin},
            )
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


class ReportCommand(CLICommand, EntityProvider):
    """
    ```shell
    report benchmarks list
    report benchmark show <benchmark-id>
    report benchmark run <benchmark-id>
                         [--accounts <account-id>]
                         [--severity <level>]
                         [--only-failing]
                         [--only-check-results]
                         [--sync-security-section]
                         [--run-id <run-id>]
    report benchmark load <benchmark-id>
                         [--accounts <account-id>]
                         [--severity <level>]
                         [--only-failing]
                         [--only-check-results]
    report checks list
    report checks show <check-id>
    report checks run <check-id>
                      [--accounts <account-id>]
                      [--severity <level>]
                      [--only-failing]
                      [--only-check-results]
    report checks failing-resources <check-id>
    ```

    List and run benchmarks as well as specific benchmark checks.
    Benchmarks are a collection of checks that are run against all or specific accounts.
    Every check has a severity, that can also be used to filter relevant checks.

    The result of a benchmark run is a report in Markdown format.
    By default, this report is rendered and displayed in the console.
    It is also possible to write the result to a file and open it in an external viewer.

    ## Parameters
    - `--accounts` [optional]: List of account ids (space separated) to run the benchmark against.
        If not specified, the benchmark is run against all accounts.
    - `--severity` [optional]: Severity level to filter checks. One of `info`, `low`, `medium`, `high`, `critical`
    - `--run-id` [optional]: Only valid in combination with `--sync-security-section`.
        All changed section will contain a reference to the report run.
        In case no run-id is provided, a unique identifier is generated.

    ## Options
    - `--only-failing` [optional]: Only include checks that are failing in the report.
    - `--only-check-results` [optional]: Only include the check result, not the benchmark structure in the report.
                                         This is useful, if you want to process the result with other action commands.
    - `--sync-security-section` [optional]: Synchronize the result of the benchmark with the security section of
                                            related nodes.

    ## Examples

    ```shell
    # List all available chekcs
    > report checks list
    aws_apigateway_authorizers_enabled
    aws_s3_account_level_public_access_blocks

    # Display the details of a specific check
    > report check show aws_apigateway_authorizers_enabled
      ... output suppressed ...

    # Perform the check against all accounts available, showing only a result if the check fails.
    > report check run aws_apigateway_authorizers_enabled --only-failing
      ... output suppressed ...

    # Perform the check against all defined accounts, showing only a result if the check fails.
    > report check run aws_apigateway_authorizers_enabled --accounts 111 222 --only-failing
      ... output suppressed ...

    # List all available benchmarks
    > report benchmarks list
    aws_cis_1_5

    # Display the details of a specific benchmark
    > report benchmark show aws_cis_1_5
    report_benchmark:
      ... output suppressed ...

    # Run benchmark against all accounts available
    > report benchmark run aws_cis_1_5
      ... output suppressed ...

    # Load the benchmark from a previous run with sync enabled
    > report benchmark load aws_cis_1_5
      ... output suppressed ...

    # Run benchmark against account 111 and 222, check only critical checks
    # The resulting report should contain only failed checks.
    > report benchmark run aws_cis_1_5 --accounts 111 222  --severity critical --only-failing
      ... output suppressed ...
    ```
    """

    @property
    def name(self) -> str:
        return "report"

    def args_info(self) -> ArgsInfo:
        run_args = [
            ArgInfo("--accounts", True, help_text="Space delimited list of accounts"),
            ArgInfo(
                "--severity",
                True,
                help_text="The severity level to filter checks",
                possible_values=[s.value for s in ReportSeverity],
            ),
            ArgInfo("--only-failing", False, help_text="Filter only failing checks."),
            ArgInfo("--only-check-results", False, help_text="Only dump results."),
            ArgInfo("--sync-security-section", False, help_text="Sync security section."),
            ArgInfo("--run-id", False, help_text="Identifier for this specific run."),
        ]
        return {
            "benchmark": {
                "list": [],
                "run": [ArgInfo(None, help_text="<benchmark-id>"), *run_args],
                "show": [ArgInfo(None, help_text="<benchmark-id>")],
            },
            "checks": {
                "list": [],
                "run": [ArgInfo(None, help_text="<check-id>"), *run_args],
                "show": [ArgInfo(None, help_text="<check-id>")],
                "failing-resources": [
                    ArgInfo(None, help_text="<check-id>"),
                    ArgInfo("--accounts", True, help_text="Space delimited list of accounts"),
                ],
            },
        }

    def info(self) -> str:
        return "Generate reports."

    @staticmethod
    def is_run_action(arg: Optional[str]) -> bool:
        return ReportCommand.action_from_arg(arg) in ("benchmark_run", "check_run", "benchmark_load")

    @staticmethod
    def action_from_arg(arg: Optional[str]) -> Optional[str]:
        args = re.split("\\s+", arg.strip(), maxsplit=3) if arg else []
        if len(args) == 2 and args[0] in ("benchmark", "benchmarks") and args[1] == "list":
            return "benchmark_list"
        elif len(args) == 3 and args[0] in ("benchmark", "benchmarks") and args[1] == "show":
            return "benchmark_show"
        elif len(args) >= 3 and args[0] in ("benchmark", "benchmarks") and args[1] == "run":
            return "benchmark_run"
        elif len(args) >= 3 and args[0] in ("benchmark", "benchmarks") and args[1] == "load":
            return "benchmark_load"
        elif len(args) == 2 and args[0] in ("check", "checks") and args[1] == "list":
            return "check_list"
        elif len(args) == 3 and args[0] in ("check", "checks") and args[1] == "show":
            return "check_show"
        elif len(args) >= 3 and args[0] in ("check", "checks") and args[1] == "run":
            return "check_run"
        elif len(args) >= 3 and args[0] in ("check", "checks") and args[1] == "failing-resources":
            return "check_failing_resources"
        else:
            return None

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def list_benchmarks() -> AsyncIterator[str]:
            for benchmark in await self.dependencies.inspector.list_benchmarks():
                yield benchmark.id

        async def show_benchmark(bid: str) -> AsyncIterator[str]:
            if benchmark := await self.dependencies.inspector.benchmark(bid):
                model = await self.dependencies.config_handler.get_configs_model()
                kind = model.get(BenchmarkConfig.kind)
                js = to_json(benchmark)
                yield kind.create_yaml(js) if isinstance(kind, ComplexKind) else yaml.safe_dump(js)

        async def show_check(cid: str) -> AsyncIterator[str]:
            model = await self.dependencies.config_handler.get_configs_model()
            kind = model.get("fix_core_report_check")
            for check in await self.dependencies.inspector.list_checks(check_ids=[cid]):
                yield kind.create_yaml(to_js(check)) if isinstance(kind, ComplexKind) else yaml.safe_dump(to_js(check))

        async def list_checks() -> AsyncIterator[str]:
            for check in await self.dependencies.inspector.list_checks():
                yield check.id

        async def run_benchmark(parsed_args: Namespace) -> AsyncIterator[Json]:
            results = await self.dependencies.inspector.perform_benchmarks(
                ctx.graph_name,
                benchmark_names=parsed_args.identifier,
                accounts=parsed_args.accounts,
                severity=parsed_args.severity,
                only_failing=parsed_args.only_failing,
                sync_security_section=parsed_args.sync_security_section,
                report_run_id=parsed_args.run_id,
            )
            for result in results.values():
                if not result.is_empty():
                    for node in result.to_graph(parsed_args.only_check_results):
                        yield node

        async def load_benchmark(parsed_args: Namespace) -> AsyncIterator[Json]:
            results = await self.dependencies.inspector.load_benchmarks(
                ctx.graph_name,
                benchmark_names=parsed_args.identifier,
                accounts=parsed_args.accounts,
                severity=parsed_args.severity,
                only_failing=parsed_args.only_failing,
            )
            for result in results.values():
                if not result.is_empty():
                    for node in result.to_graph(parsed_args.only_check_results):
                        yield node

        async def run_check(parsed_args: Namespace) -> AsyncIterator[Json]:
            result = await self.dependencies.inspector.perform_checks(
                ctx.graph_name,
                check_ids=parsed_args.identifier,
                accounts=parsed_args.accounts,
                severity=parsed_args.severity,
                only_failing=parsed_args.only_failing,
            )
            if not parsed_args.only_failing or result.has_failed():
                for node in result.to_graph(parsed_args.only_check_results):
                    yield node

        async def show_help() -> AsyncIterator[str]:
            yield f"Do not understand: {arg}\n\n" + self.rendered_help(ctx)

        run_parser = NoExitArgumentParser()
        run_parser.add_argument("identifier", nargs="+")
        run_parser.add_argument("--accounts", nargs="+")
        run_parser.add_argument("--severity", type=ReportSeverity, choices=list(ReportSeverity))
        run_parser.add_argument("--only-failing", action="store_true", default=False)
        run_parser.add_argument("--only-check-results", action="store_true", default=False)
        run_parser.add_argument("--sync-security-section", action="store_true", default=False)
        run_parser.add_argument("--run-id", type=str, default=None)

        action = self.action_from_arg(arg)
        args = re.split("\\s+", arg.strip(), maxsplit=2) if arg else []
        if action == "benchmark_list":
            return CLISource.no_count(list_benchmarks, required_permissions={Permission.read})
        elif action == "benchmark_show":
            return CLISource.no_count(partial(show_benchmark, args[2].strip()), required_permissions={Permission.read})
        elif action == "benchmark_run":
            parsed = run_parser.parse_args(args[2].split() if len(args) > 2 else [])
            return CLISource.no_count(partial(run_benchmark, parsed), required_permissions={Permission.read})
        elif action == "benchmark_load":
            parsed = run_parser.parse_args(args[2].split() if len(args) > 2 else [])
            return CLISource.no_count(partial(load_benchmark, parsed), required_permissions={Permission.read})
        elif action == "check_list":
            return CLISource.no_count(list_checks, required_permissions={Permission.read})
        elif action == "check_show":
            return CLISource.no_count(partial(show_check, args[2].strip()), required_permissions={Permission.read})
        elif action == "check_run":
            parsed = run_parser.parse_args(args[2].split() if len(args) > 2 else [])
            return CLISource.no_count(partial(run_check, parsed), required_permissions={Permission.read})
        elif action == "check_failing_resources":
            run_parser = NoExitArgumentParser()
            run_parser.add_argument("identifier")
            run_parser.add_argument("--accounts", nargs="+")
            parsed = run_parser.parse_args(args[2].split() if len(args) > 2 else [])
            return CLISource.no_count(
                partial(
                    self.dependencies.inspector.list_failing_resources,
                    ctx.graph_name,
                    parsed.identifier,
                    parsed.accounts,
                ),
                required_permissions={Permission.read},
            )
        else:
            return CLISource.single(show_help, required_permissions={Permission.read})


class AppsCommand(CLICommand):
    """
    ```shell
    apps search [pattern] [--index-url https://cdn.some.engineering/fixinventory/apps/index.json]
    app info <app_name> [--index-url https://cdn.some.engineering/fixinventory/apps/index.json]
    app install <app_name> [--index-url https://cdn.some.engineering/fixinventory/apps/index.json]
    app edit <app_name>
    app uninstall <app_name>
    app update <app_name>|all
    apps list
    app run <app_name> [--dry-run] --config [config_name]
    ```

    - `apps search [pattern]`: Lists all apps available in the index
      https://cdn.some.engineering/fixinventory/apps/index.json (or other URL if specified).
      Supports filtering by pattern.
    - `app info <app_name>`: Show information about an app.
    - `app install <app_name>`: Install an app.
    - `app edit <app_name>`: Edit an app.
    - `app uninstall <app_name>`: Uninstall an app.
    - `app update <app_name>|all`: Update an app or all apps.
    - `apps list`: List all installed apps.
    - `app run <app_name> [--dry-run] [--config <config_name>]`: Run an app.


    ## Parameters
    - `app_name` [required]: The identifier of the infrastructure app.
    - `pattern` [optional]: Pattern for searching for apps. Supports glob wildcards such as * and ?.

    ## Options
    - `--index-url <url>`: The index file to use for searching for apps.
      Defaults to https://cdn.some.engineering/fixinventory/apps/index.json.
    - `--dry-run`: Run the app but do not make any changes.
    - `--config <config_name>`: The configuration to use to run the app. Defaults to the default configuration.
    """

    @property
    def name(self) -> str:
        return "apps"

    def info(self) -> str:
        return "Manage infrastructure apps."

    def args_info(self) -> ArgsInfo:
        return {
            "search": [
                ArgInfo(None, True, help_text="<pattern>"),
                ArgInfo("--index-url", True, help_text="<index-url>", option_group="source"),
            ],
            "info": [
                ArgInfo(None, True, help_text="<app_name>"),
                ArgInfo("--index-url", True, help_text="<index-url>", option_group="source"),
            ],
            "install": [
                ArgInfo(None, True, help_text="<app_name>"),
                ArgInfo("--index-url", True, help_text="<index-url>", option_group="source"),
            ],
            "edit": [ArgInfo(None, True, help_text="<app_name>")],
            "uninstall": [ArgInfo(None, True, help_text="<app_name>")],
            "update": [ArgInfo(None, True, help_text="<app_name>")],
            "list": [ArgInfo(None, False)],
            "run": [
                ArgInfo(None, True, help_text="<app_name>"),
                ArgInfo("--dry-run", False),
                ArgInfo("--config", True, help_text="<config_name>"),
            ],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def apps_search(pattern: Optional[str], url: Optional[str]) -> AsyncIterator[JsonElement]:
            async for manifest in self.dependencies.infra_apps_package_manager.search(pattern, url):
                yield {
                    "name": manifest.name,
                    "description": manifest.description,
                    "version": manifest.version,
                }

        async def app_info(app_name: InfraAppName, url: Optional[str]) -> AsyncIterator[JsonElement]:
            yield await self.dependencies.infra_apps_package_manager.info(app_name, url)

        async def app_install(app_name: InfraAppName, url: Optional[str]) -> AsyncIterator[JsonElement]:
            manifest = await self.dependencies.infra_apps_package_manager.install(app_name, url)
            yield f"App {app_name} version {manifest.version} installed successfully"

        async def send_file(content: str) -> AsyncIterator[str]:
            async with TemporaryDirectory() as temp_dir:
                path = os.path.join(temp_dir, "manifest.yaml")
                async with aiofiles.open(path, "w") as f:
                    await f.write(content)
                yield path

        async def edit_app(app_name: InfraAppName) -> AsyncIterator[str]:
            # Editing a config is a two-step process:
            # 1) download the config and make it available to edit
            # 2) upload the config file and update the config from content --> update_config
            manifest = await self.dependencies.infra_apps_package_manager.get_manifest(app_name)
            if not manifest:
                raise AttributeError(f"No app with this name: {app_name}")
            yml = yaml.safe_dump(to_js(manifest))
            return send_file(yml)

        async def update_app(app_name: InfraAppName) -> AsyncIterator[str]:
            # Usually invoked by resh automatically via edit_app, but can also be triggered manually.
            # An app with given name is changed by the content of uploaded file "app_name.yaml"
            content = ""
            try:
                async with aiofiles.open(ctx.uploaded_files["manifest.yaml"], "r") as f:
                    content = await f.read()
                    manifest: AppManifest = from_js(yaml.safe_load(content), AppManifest)
                await self.dependencies.infra_apps_package_manager.update_from_manifest(manifest)
            except Exception as ex:
                log.debug(f"Could not update the app manifest: {ex}.", exc_info=ex)
                # Yaml file: add the error as comment on top
                error = "\n".join(f"## {line}" for line in str(ex).splitlines())
                message = f"## Update the app failed. Please correct.\n{error}\n\n"
                # Remove error message from previous check
                config = "\n".join(dropwhile(lambda m: m.startswith("##") or len(m.strip()) == 0, content.splitlines()))
                async for file in send_file(message + config):
                    yield file

        async def app_uninstall(app_name: InfraAppName) -> AsyncIterator[JsonElement]:
            await self.dependencies.infra_apps_package_manager.delete(app_name)
            yield f"App {app_name} uninstalled"

        async def app_update(app_name: InfraAppName) -> AsyncIterator[JsonElement]:
            updated_manifest = await self.dependencies.infra_apps_package_manager.update(app_name)
            yield f"App {app_name} updated sucessfully to the latest version ({updated_manifest.version})"

        async def app_update_all() -> AsyncIterator[JsonElement]:
            async for name, result in self.dependencies.infra_apps_package_manager.update_all():
                if isinstance(result, Failure):
                    yield f"App {name} failed to update: {result}"
                else:
                    yield f"App {name} updated sucessfully to the latest version ({result.version})"

        async def apps_list() -> AsyncIterator[JsonElement]:
            async for app in self.dependencies.infra_apps_package_manager.list():
                yield app

        async def app_run(
            in_stream: JsStream, app_name: InfraAppName, dry_run: bool, config: Optional[str], argv: List[str]
        ) -> AsyncIterator[JsonElement]:
            runtime = self.dependencies.infra_apps_runtime
            manifest = await self.dependencies.infra_apps_package_manager.get_manifest(app_name)
            if not manifest:
                raise ValueError(f"App {app_name} is not installed.")
            app_config = None
            config = config or f"fix.apps.{app_name}"
            ce = await self.dependencies.config_handler.get_config(ConfigId(config))
            if ce:
                app_config = ce.config
            else:
                raise ValueError(f"Config {config} not found.")

            async def stream_to_iterator() -> AsyncIterator[JsonElement]:
                async with in_stream.stream() as streamer:
                    async for item in streamer:
                        yield item

            stdin = stream_to_iterator()
            if dry_run:
                return runtime.generate_template(
                    graph=ctx.graph_name, manifest=manifest, config=app_config, stdin=stdin, argv=argv
                )
            else:
                return runtime.execute(
                    graph=ctx.graph_name, manifest=manifest, config=app_config, stdin=stdin, argv=argv, ctx=ctx
                )

        args = re.split("\\s+", arg, maxsplit=2) if arg else []
        if len(args) == 1 and args[0] == "search":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("--index-url", dest="url", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(partial(apps_search, None, parsed.url), required_permissions={Permission.read})
        elif len(args) >= 2 and args[0] == "search":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("pattern", type=str, nargs="*")
            parser.add_argument("--index-url", dest="url", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(apps_search, " ".join(parsed.pattern), parsed.url), required_permissions={Permission.read}
            )
        elif len(args) == 2 and args[0] == "info":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("app_name", type=str)
            parser.add_argument("--index-url", dest="url", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(app_info, InfraAppName(parsed.app_name), parsed.url), required_permissions={Permission.read}
            )
        elif len(args) >= 2 and args[0] == "install":
            parser = NoExitArgumentParser()
            source_group = parser.add_mutually_exclusive_group()
            source_group.add_argument("--index-url", dest="url", type=str)
            parser.add_argument("command", type=str)
            parser.add_argument("app_name", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())

            return CLISource.single(
                partial(
                    app_install,
                    InfraAppName(parsed.app_name),
                    parsed.url,
                ),
                required_permissions={Permission.admin},
            )
        elif arg and len(args) == 2 and args[0] == "edit":
            app_name = InfraAppName(args[1])
            return CLISource.single(
                partial(edit_app, app_name),
                produces=MediaType.FilePath,
                envelope={CLIEnvelope.action: "edit", CLIEnvelope.command: f"apps update {app_name}"},
                required_permissions={Permission.admin},
            )
        elif arg and len(args) == 3 and args[0] == "update":
            app_name = InfraAppName(args[1])
            return CLISource.single(
                partial(update_app, app_name),
                produces=MediaType.FilePath,
                envelope={CLIEnvelope.action: "edit", CLIEnvelope.command: f"apps update {app_name}"},
                requires=[CLIFileRequirement("manifest.yaml", args[2])],
                required_permissions={Permission.admin},
            )
        elif len(args) == 2 and args[0] == "uninstall":
            return CLISource.single(
                partial(app_uninstall, InfraAppName(args[1])), required_permissions={Permission.admin}
            )
        elif len(args) == 2 and args[0] == "update" and args[1] == "all":
            return CLISource.single(app_update_all, required_permissions={Permission.admin})
        elif len(args) == 2 and args[0] == "update":
            return CLISource.single(partial(app_update, InfraAppName(args[1])), required_permissions={Permission.admin})
        elif len(args) == 1 and args[0] == "list":
            return CLISource.single(apps_list, required_permissions={Permission.read})
        elif len(args) >= 2 and args[0] == "run":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("app_name", type=str)
            parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=False)
            parser.add_argument("--config", dest="config", type=str, default=None)
            parsed, argv = parser.parse_known_args(args_parts_parser.parse(arg))

            in_source_position = kwargs.get("position") == 0

            if in_source_position:
                return CLISource.no_count(
                    partial(
                        app_run,
                        in_stream=stream.empty(),
                        app_name=InfraAppName(parsed.app_name),
                        dry_run=parsed.dry_run,
                        config=parsed.config,
                        argv=argv,
                    ),
                    required_permissions={Permission.read},
                )
            else:
                return CLIFlow(
                    partial(
                        app_run,
                        app_name=InfraAppName(parsed.app_name),
                        dry_run=parsed.dry_run,
                        config=parsed.config,
                        argv=argv,
                    ),
                    required_permissions={Permission.read},
                )
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


class UserCommand(CLICommand):
    """
    ```shell
    user add <email> --fullname <name> --password <secret> --role <role> --role <role>
    user delete <email>
    user role add <email> <role>
    user role delete <email> <role>
    user password <email> <password>
    user list
    user show <email>
    ```

    Manage the database of users.

    Note: the user database is stored as configuration item in the configuration store.
    The password of the user is stored as hash using pbkdf2_hmac with sha512 and 210000 iterations.
    It is stored in /etc/shadow format.
    It is possible to maintain the user database externally by using config overrides.

    Every user uses the email address as unique identifier.
    Email + password is used for authentication.
    The allowed actions of a user are defined by the roles assigned to the user.

    ## Parameters
    - `<email>`: The email address of the user.
    - `--fullname` - Full name of the user
    - `--password` - Password of the user
    - `--role` - Role of the user. Can be repeated multiple times.

    ## Examples
    ```shell
    # Add a user with a given name and read-only role. The password will be stored as hash.
    > users add matthias@some.engineering --fullname "Matthias Veit" --role read-only --password changeme
    email: matthias@some.engineering
    fullname: Matthias Veit
    roles:
    - read-only

    # List all users of the system.
    > user list
    admin@some.engineering
    matthias@some.engineering
    test@test.de

    # Show a specific user.
    > users show matthias@some.engineering
    email: matthias@some.engineering
    fullname: Matthias Veit
    roles:
    - read-only

    # Add a role to a user.
    > user role add matthias@some.engineering admin
    email: matthias@some.engineering
    fullname: Matthias Veit
    roles:
    - read-only
    - admin

    # Remove a role from a user.
    > user role delete matthias@some.engineering admin
    email: matthias@some.engineering
    fullname: Matthias Veit
    roles:
    - read-only

    # Change the password of a user.
    > user password matthias@some.engineering bombproof
    Password for matthias@some.engineering updated

    # Delete a user.
    > user delete matthias@some.engineering
    User matthias@some.engineering deleted
    """

    @property
    def name(self) -> str:
        return "user"

    def args_info(self) -> ArgsInfo:
        return {
            "add": [
                ArgInfo(None, True, help_text="<email>"),
                ArgInfo("--fullname", True, help_text="<name>"),
                ArgInfo("--password", True, help_text="<secret>"),
                ArgInfo(
                    "--role",
                    True,
                    help_text="<role>",
                    possible_values=list(AllowedRoleNames),
                    can_occur_multiple_times=True,
                ),
            ],
            "delete": [
                ArgInfo(None, True, help_text="<email>"),
            ],
            "role": {
                "add": [
                    ArgInfo(None, True, help_text="<email>"),
                    ArgInfo(None, True, help_text="<role>"),
                ],
                "delete": [
                    ArgInfo(None, True, help_text="<email>"),
                    ArgInfo(None, True, help_text="<role>"),
                ],
            },
            "password": [ArgInfo(None, True, help_text="<email>"), ArgInfo(None, True, help_text="<password>")],
            "list": [ArgInfo(None, False)],
            "show": [ArgInfo(None, True, help_text="<email>")],
        }

    def info(self) -> str:
        return "Manage users"

    @staticmethod
    def user_to_json(email: Email, user: FixInventoryUser) -> JsonElement:
        return {
            "email": email,
            "fullname": user.fullname,
            "roles": list(user.roles),
        }

    async def add_user(
        self, email: Email, fullname: str, password: Password, roles: List[str]
    ) -> AsyncIterator[JsonElement]:
        user = await self.dependencies.user_management.create_user(email, fullname, password, roles)
        yield self.user_to_json(email, user)

    async def delete_user(self, email: Email) -> AsyncIterator[JsonElement]:
        await self.dependencies.user_management.delete_user(email)
        yield f"User {email} deleted"

    async def add_roles(self, email: Email, role: str) -> AsyncIterator[JsonElement]:
        if user := await self.dependencies.user_management.user(email):
            updated = user.roles.union({role})
            user = await self.dependencies.user_management.update_user(email, roles=list(updated))
            yield self.user_to_json(email, user)
        else:
            raise AttributeError(f"User {email} not found")

    async def delete_role(self, email: Email, role: str) -> AsyncIterator[JsonElement]:
        if user := await self.dependencies.user_management.user(email):
            updated = user.roles.difference({role})
            user = await self.dependencies.user_management.update_user(email, roles=list(updated))
            yield self.user_to_json(email, user)
        else:
            raise AttributeError(f"User {email} not found")

    async def change_password(self, email: Email, password: Password) -> AsyncIterator[JsonElement]:
        await self.dependencies.user_management.update_user(email, password=password)
        yield f"Password for {email} updated"

    async def list_users(self) -> AsyncIterator[JsonElement]:
        for email in await self.dependencies.user_management.users():
            yield email

    async def show_user(self, email: Email) -> AsyncIterator[JsonElement]:
        if user := await self.dependencies.user_management.user(email):
            yield self.user_to_json(email, user)
        else:
            raise AttributeError(f"User {email} not found")

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        args = args_parts_unquoted_parser.parse(arg.strip()) if arg else []
        if len(args) >= 2 and args[0] == "add":
            parser = NoExitArgumentParser()
            parser.add_argument("email", type=str)
            parser.add_argument("--fullname", type=str, required=True)
            parser.add_argument("--password", type=str, required=True)
            parser.add_argument("--role", type=str, action="append", required=True, choices=AllowedRoleNames)
            parsed = parser.parse_args(args[1:])
            return CLISource.single(
                partial(self.add_user, Email(parsed.email), parsed.fullname, Password(parsed.password), parsed.role),
                envelope={CLIEnvelope.no_history: "yes"},
                required_permissions={Permission.admin},
            )
        elif len(args) == 2 and args[0].startswith("del"):
            return CLISource.single(partial(self.delete_user, Email(args[1])), required_permissions={Permission.admin})
        elif len(args) > 3 and args[0] == "role" and args[1] == "add":
            assert args[3] in AllowedRoleNames, "Role must be one of: " + ", ".join(AllowedRoleNames)
            return CLISource.single(
                partial(self.add_roles, Email(args[2]), args[3]), required_permissions={Permission.admin}
            )
        elif len(args) > 3 and args[0] == "role" and args[1].startswith("del"):
            return CLISource.single(
                partial(self.delete_role, Email(args[2]), args[3]), required_permissions={Permission.admin}
            )
        elif len(args) >= 3 and args[0] in ("passwd", "password"):
            user_email = ctx.user.email if ctx.user else None
            email = Email(args[1])
            return CLISource.single(
                partial(self.change_password, email, Password(args[2])),
                envelope={CLIEnvelope.no_history: "yes"},
                required_permissions={Permission.read} if user_email == email else {Permission.admin},
            )
        elif len(args) == 1 and args[0] == "list":
            return CLISource.no_count(self.list_users, required_permissions={Permission.read})
        elif len(args) == 2 and args[0] == "show":
            return CLISource.no_count(partial(self.show_user, args[1]), required_permissions={Permission.read})
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


class GraphCommand(CLICommand):
    """
    ```shell
    graph list [pattern]
    graph copy [--force] [from_graph_namae] <to_graph_name>
    graph snapshot [from_graph_name] <snapshot_label>
    graph delete <graph_name>
    graph export [--force] [graph_name] <file_name>
    graph import [--force] [graph_name] <file_name>
    ```

    - `graph list [pattern]`: Lists all graphs. Supports filtering by pattern.
    - `graph copy [--force] [from_graph_name] <to_graph_name>`: Copies the graph.
       If the target graph already exists, and a --force flag is provided, the graph will be overwritten.
    - `graph snapshot [from_graph_name] <snapshot_label>`: Make a graph snapshot.
    - `graph delete <graph_name>`: Delete a graph.
    - `graph export [--force] [graph_name] <file_name>`: Export the graph into a file. If the file already exists,
       and a --force flag is provided, the file will be overwritten.
    - `graph import [--force] [graph_name] <file_name>`: Import the graph from a file. If the graph already exists,
       and a --force flag is provided, the graph will be overwritten.

    ## Parameters
    - `pattern` [optional]: Pattern for searching for graphs. Supports regex.
    - `from_graph_name` [required]: The name of the graph to make a copy or snapshot from.
    - `to_graph_name` [optional]: The name of the target graph to make a copy.
       If not specified, the name of the current graph is used.
    - `file_name` [required]: The name of the file to save the graph to.

    ## Options
    - `--force`: Overwrite the target graph or file if it already exists.
    """

    @property
    def name(self) -> str:
        return "graph"

    def info(self) -> str:
        return "Operations on graphs."

    def args_info(self) -> ArgsInfo:
        return {
            "list": [
                ArgInfo(None, True, help_text="<pattern>"),
            ],
            "copy": [
                ArgInfo(None, True, help_text="<from_graph_name>"),
                ArgInfo(None, True, help_text="<to_graph_name>"),
                ArgInfo("--force", False),
            ],
            "snapshot": [
                ArgInfo(None, True, help_text="<from_graph_name>"),
                ArgInfo(None, True, help_text="<to_graph_name>"),
            ],
            "delete": [
                ArgInfo(None, True, help_text="<graph_name>"),
            ],
            "export": [
                ArgInfo(None, True, help_text="<from_graph_name>"),
                ArgInfo(None, True, help_text="<to_graph_name>"),
                ArgInfo("--force", False),
            ],
            "import": [
                ArgInfo(None, True, help_text="<from_graph_name>"),
                ArgInfo(None, True, help_text="<to_graph_name>"),
                ArgInfo("--force", False),
            ],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def graph_list(pattern: Optional[str]) -> AsyncIterator[JsonElement]:
            graphs = await self.dependencies.graph_manager.list(pattern)
            for graph in graphs:
                yield graph

        async def graph_copy(
            source: Optional[GraphName], destination: GraphName, force: bool
        ) -> AsyncIterator[JsonElement]:
            if not source:
                source = ctx.graph_name
            result_name = await self.dependencies.graph_manager.copy(source, destination, replace_existing=force)
            yield f"Graph {source} copied to {result_name}."

        async def graph_snapshot(source: Optional[GraphName], label: str) -> AsyncIterator[JsonElement]:
            if not source:
                source = ctx.graph_name
            snapshot_name = await self.dependencies.graph_manager.snapshot(source, label)
            yield f"Graph {source} snapshoted to {snapshot_name}."

        async def graph_delete(graph_name: GraphName) -> AsyncIterator[JsonElement]:
            await self.dependencies.graph_manager.delete(graph_name)
            yield f"Graph {graph_name} deleted."

        async def write_result_to_file(export_lines: AsyncIterator[str], file_name: str) -> AsyncIterator[JsonElement]:
            async with TemporaryDirectory() as temp_dir:
                path = os.path.join(temp_dir, uuid_str())
                async with aiofiles.open(path, "w") as f:
                    async for line in export_lines:
                        await f.write(line + "\n")
                yield FilePath.user_local(file_name, path).json()

        async def graph_export(graph_name: Optional[GraphName], file_name: str) -> AsyncIterator[JsonElement]:
            if not graph_name:
                graph_name = ctx.graph_name
            lines = self.dependencies.graph_manager.export_graph(graph_name)
            return write_result_to_file(lines, file_name)

        async def graph_import(
            graph_name: Optional[GraphName], file_name: str, force: bool
        ) -> AsyncIterator[JsonElement]:
            if not graph_name:
                graph_name = ctx.graph_name

            path = ctx.uploaded_files.get("dump")
            if not path:
                raise ValueError(f"File {file_name} was not uploaded.")

            async with aiofiles.open(path, "r") as f:

                async def lines_iterator() -> AsyncIterator[str]:
                    async for line in f:
                        yield line.strip()

                await self.dependencies.graph_manager.import_graph(graph_name, lines_iterator(), replace_existing=force)
            yield f"Graph {graph_name} imported from {file_name}."

        args = re.split("\\s+", arg, maxsplit=2) if arg else []
        if args[0] == "list":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("pattern", type=str, nargs="?", default=None)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(partial(graph_list, parsed.pattern), required_permissions={Permission.read})
        elif args[0] == "copy":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("source", type=str, nargs="?", default=None)
            parser.add_argument("destination", type=str)
            parser.add_argument("--force", action="store_true")
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(graph_copy, GraphName(parsed.source), GraphName(parsed.destination), parsed.force),
                required_permissions={Permission.admin},
            )
        elif args[0] == "snapshot":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("source", type=str, nargs="?", default=None)
            parser.add_argument("label", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(graph_snapshot, parsed.source, parsed.label), required_permissions={Permission.admin}
            )
        elif args[0] == "delete":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("graph_name", type=str)
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(graph_delete, GraphName(parsed.graph_name)), required_permissions={Permission.admin}
            )
        elif args[0] == "export":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("graph_name", type=str, nargs="?", default=None)
            parser.add_argument("file_name", type=str)
            parser.add_argument("--force", action="store_true")
            parsed = parser.parse_args(strip_quotes(arg or "").split())
            return CLISource.single(
                partial(graph_export, parsed.graph_name, parsed.file_name),
                MediaType.FilePath,
                required_permissions={Permission.read},
            )
        elif args[0] == "import":
            parser = NoExitArgumentParser()
            parser.add_argument("command", type=str)
            parser.add_argument("graph_name", type=str, nargs="?", default=None)
            parser.add_argument("file_name", type=str)
            parser.add_argument("--force", action="store_true")
            parsed = parser.parse_args(strip_quotes(arg or "").split())

            return CLISource.single(
                partial(graph_import, parsed.graph_name, parsed.file_name, parsed.force),
                MediaType.Json,
                [CLIFileRequirement("dump", parsed.file_name)],
                required_permissions={Permission.admin},
            )

        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


class DbCommand(CLICommand, PreserveOutputFormat):
    """
    ```
    db sync <db-engine> --host <host> --port <port> --user <user> --password <password> --database <database>
                   --arg key=value --arg key2=value2
                   --complete-schema --drop-existing-tables --batch-size <batch-size>
    ```

    Takes the result of a search expression and synchronizes the data to an SQL database.
    All matching tables will be updated with the result of the search expression.

    If invoked without a search command, the entire graph will be exported.

    By default, the database tables will be updated only for the data that is returned by the search expression.
    This behaviour can be overridden by using the `--complete-schema` flag, which will export the entire schema
    always. This is useful when you want to have a consistent database scheme, no matter which data gets exported.

    The `--drop-existing-tables` can come in handy, if you only want to export a subset of data from a graph and
    make sure everything from the last export is cleaned up. This flag does not have any effect in combination with
    `--complete-schema`.

    ## Parameters

    - `db-engine` - The database engine to use. The following engines are supported:
        - postgresql
        - mariadb
        - mysql
        - sqlite
        - snowflake
    - `--host` - The host of the database server.
    - `--port` - The port of the database server.
    - `--user` - The user to use for authentication.
    - `--password` - The password to use for authentication.
    - `--database` - The database to use.
    - `--arg` - A key-value pair that will be passed to the connection driver.
                This property can be used multiple times.
    - `--batch-size` - The number of rows that will be inserted in a single batch.

    ## Options

    - `--complete-schema` - Export the entire schema, no matter which data gets exported.
    - `--drop-existing-tables` - Drop all tables that are not part of the current export.

    ## Examples

    ```
    # Sync the complete graph to a sqlite database
    > db sync sqlite --database fix.db --drop-existing

    # Sync the complete graph to a postgresql database
    > db sync postgresql --host localhost --port 5432 --database fix --user ci --password bombproof

    # Sync the complete graph to a mariadb database
    > db sync mariadb --host localhost --port 3306 --user root --password pw --database test

    # Sync the complete graph to a mysql database
    > db sync mysql --host localhost --port 3306 --user root --password pw --database test

    # Sync the complete graph to a snowflake database
    > db sync snowflake --host localhost --port 3306 --user root --password pw --database test
      --arg warehouse=compute_wh --arg role=accountadmin

    # Select a subset of data and sync it to a sqlite database
    > search --with-edges is(graph_root) -[0:2]-> | db sync sqlite --database fix.db
    ```
    """

    @property
    def name(self) -> str:
        return "db"

    def args_info(self) -> ArgsInfo:
        return {
            "sync": [
                ArgInfo(
                    expects_value=False,
                    possible_values=["mariadb", "mysql", "postgresql", "sqlite", "snowflake"],
                    help_text="<db-engine>",
                ),
                ArgInfo(name="--host", expects_value=True, help_text="host-name"),
                ArgInfo(name="--port", expects_value=True, help_text="port"),
                ArgInfo(name="--user", expects_value=True, help_text="username"),
                ArgInfo(name="--password", expects_value=True, help_text="password"),
                ArgInfo(name="--database", expects_value=True, help_text="database"),
                ArgInfo(name="--arg", can_occur_multiple_times=True, expects_value=True, help_text="key=value"),
                ArgInfo(name="--batch-size", expects_value=True, help_text="count"),
            ]
        }

    def info(self) -> str:
        return "Synchronizes data to an SQL database."

    async def list_kinds_of_query(
        self, query: Optional[Query], graph_name: GraphName, model: Model
    ) -> List[ComplexKind]:
        assert query is not None, "No query provided, not sure what to synchronize?"
        assert query.aggregate is None, "Aggregates are not supported for synchronization"
        db = self.dependencies.db_access.get_graph_db(graph_name)
        aggregate_by_kind = Aggregate(
            [AggregateVariable(AggregateVariableName("reported.kind"), "kind")],
            [AggregateFunction("sum", 1)],
        )
        query = evolve(query, aggregate=aggregate_by_kind)
        async with await db.search_aggregation(QueryModel(query, model)) as cursor:
            return [
                kind
                async for elem in cursor
                if (
                    (kind_name := value_in_path(elem, ["group", "kind"]))
                    and (kind := model.get(kind_name))
                    and isinstance(kind, ComplexKind)
                )
            ]

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        in_source_position = kwargs.get("position") == 0
        db_lookup = dict(mysql="mysql+pymysql", mariadb="mariadb+pymysql")

        async def sync_database_result(p: Namespace, maybe_stream: Optional[JsStream]) -> AsyncIterator[JsonElement]:
            async with TemporaryDirectory() as temp_dir:
                # optional: path of the output file
                file_output: Optional[Path] = Path(temp_dir) / "db" if p.db == "sqlite" else None
                db_string = f"{db_lookup.get(p.db, p.db)}://"
                if p.user:
                    db_string += p.user
                    if p.password:
                        db_string += f":{p.password}"
                    db_string += "@"
                if p.host:
                    db_string += p.host
                    if p.port:
                        db_string += f":{p.port}"
                if p.database:
                    database = str(file_output) if file_output is not None else p.database
                    db_string += f"/{database}"
                db_string += "?" + "&".join([f"{k}={v}" for pl in p.arg for k, v in pl])
                db_config = EngineConfig(db_string, p.batch_size)

                sync_fn = partial(database_synchronize, db_config, p.complete_schema, p.drop_existing_tables)
                if maybe_stream is not None:  # search | db sync
                    await sync_fn(query=ctx.query, in_stream=maybe_stream)
                else:
                    fix_model = await self.dependencies.model_handler.load_model(ctx.graph_name)
                    query = Query(parts=[Part(term=IsTerm(["graph_root"]), navigation=NavigateUntilLeaf)])
                    graph_db = self.dependencies.db_access.get_graph_db(ctx.graph_name)
                    async with await graph_db.search_graph_gen(
                        QueryModel(query, fix_model, ctx.env), timeout=timedelta(weeks=200000)
                    ) as cursor:
                        await sync_fn(query=query, in_stream=stream.iterate(cursor))

                if file_output is not None:
                    assert p.database, "No database name provided. Use the --database <name> argument."
                    yield FilePath.user_local(p.database, file_output).json()
                else:
                    yield "Database synchronized."

        async def database_synchronize(
            engine_config: EngineConfig,
            complete_model: bool,
            drop_existing_tables: bool,
            query: Optional[Query],
            in_stream: JsStream,
        ) -> None:
            fix_model = await self.dependencies.model_handler.load_model(ctx.graph_name)

            if complete_model:
                complex_kinds = list(fix_model.complex_kinds())
                kinds = list(fix_model.kinds.values())
            else:
                # only export the kinds that are exported by this query
                complex_kinds = await self.list_kinds_of_query(query, ctx.graph_name, fix_model)
                tct = [
                    ck
                    for kind in complex_kinds
                    for ck in kind.transitive_complex_types(with_bases=True, with_properties=True)
                ]
                sk = [kind for kind in fix_model.kinds.values() if isinstance(kind, SimpleKind)]
                kinds = [*tct, *sk]

            kind_by_name = {k.fqn: from_js(to_js(k), RCKind) for k in kinds}
            rcm = RCModel(kind_by_name)

            edges = {
                (kind.fqn, succ)
                for kind in complex_kinds
                for succ_lists in kind.successor_kinds.values()
                for succ in succ_lists
                if succ in kind_by_name
            }

            # lookup map for edges: id -> kind. Assumption: when an edge is created, the nodes already passed
            kind_by_id: Dict[str, str] = {}

            def key_fn(node: Json) -> Union[str, Tuple[str, str]]:
                assert isinstance(node, dict) and node.get("type") in ("edge", "node"), (
                    f"Expected a JSON object. Don't know how to handle >{node}<.\n"
                    "Execute `help db` to get more information on how to use this command."
                )
                if node["type"] == "edge":
                    fr = node["from"]
                    to = node["to"]
                    return kind_by_id[fr], kind_by_id[to]
                else:  # node
                    kind_by_id[node["id"]] = node["reported"]["kind"]
                    return cast(str, node["reported"]["kind"])

            async with in_stream.stream() as streamer:
                batched = BatchStream(streamer, key_fn, engine_config.batch_size, engine_config.batch_size * 10)
                await update_sql(
                    engine_config, rcm, batched, edges, swap_temp_tables=True, drop_existing_tables=drop_existing_tables
                )

        args = arg.split(maxsplit=1) if arg else []
        if len(args) == 2 and args[0] == "sync":
            parser = NoExitArgumentParser()
            parser.add_argument("db", type=str)
            parser.add_argument("--host", type=str)
            parser.add_argument("--port", type=int)
            parser.add_argument("--user", type=str)
            parser.add_argument("--password", type=str)
            parser.add_argument("--database", type=str)
            parser.add_argument("--arg", type=key_value_parser.parse, nargs="+", action="append", default=[])
            parser.add_argument("--complete-schema", action="store_true")
            parser.add_argument("--drop-existing-tables", action="store_true")
            # Batch Size Restrictions:
            # SQLite before 3.32.0: 999
            # MySQL/MariaDB: 16MB batch size
            # Postgres/Snowflake: no limit other than available memory
            # --> we use 999 as a safe default
            parser.add_argument("--batch-size", type=int, default=999)
            parsed_args = parser.parse_args(args_parts_unquoted_parser.parse(args[1]))
            produces = MediaType.FilePath if parsed_args.db == "sqlite" else MediaType.Json
            if in_source_position:
                # in this position we fall back to exporting the whole graph
                return CLISource.single(
                    fn=partial(sync_database_result, parsed_args, None),
                    envelope={CLIEnvelope.no_history: "yes"},
                    produces=produces,
                    required_permissions={Permission.read},
                )
            else:
                # sync = partial(database_synchronize, db_config, p.complete_schema, p.drop_existing_tables, ctx.query)
                return CLIFlow(
                    fn=partial(sync_database_result, parsed_args),
                    envelope={CLIEnvelope.no_history: "yes"},
                    produces=produces,
                    required_permissions={Permission.read},
                )
        else:
            raise AttributeError("Wrong or insufficient arguments. Execute `help db` to get more information.")


class TimeSeriesCommand(CLICommand):
    """
    ```
    timeseries snapshot --name <time series> <aggregate search>
    timeseries get --name <time series> --start <time> --end <time> --granularity <duration|integer>
                   --group <group> --filter <var><op><value>
    timeseries list
    timeseries downsample
    ```

    The timeseries command can be used to add data to a time series or to retrieve data from a time series.

    To append values to a time series, it's necessary to perform an aggregate search query on a graph.
    As this graph reflects the present state of affairs,
    running an aggregate search on it essentially captures the current state into the time series.
    By regularly taking snapshots of the time series using the same aggregate search query,
    you can effectively track how things evolve over time.

    To retrieve data from a time series, you need to specify the name of the time series, as well as a time range.
    It is possible to group the data by a certain variable, and to filter the data by a certain variable.

    All available timeseries can be retrieved with the `timeseries list` command.

    The `timeseries downsample` command can be used to downsample all time series.
    See fix.core db configuration to configure the buckets that are used for downsampling.
    General idea of downsample: higher resolution and more datapoints for recent data,
                                lower resolution and less datapoints for older data.

    ## Parameters

    - `--name` - The name of the time series.
    - `--start` - The start of the time range.
    - `--end` - The end of the time range.
    - `--group` - The variable(s) to select in the group. Can be repeated multiple times.
    - `--filter` - The variable(s) to filter. Can be repeated multiple times.
    - `--granularity` - The granularity of the time series. Can be a duration or an integer.


    ## Examples

    ```
    # compute the number of instances per instance type and store it in a time series
    > timeseries snapshot --name instances aggregate(instance_type: sum(1)): is(instance)

    # retrieve the number of instances per instance type since yesterday
    > timeseries get --name instances --start @yesterday@ --end @now@

    # downsample existing time series
    > timeseries downsample

    # list all time series
    > timeseries list
    ```
    """

    @property
    def name(self) -> str:
        return "timeseries"

    def info(self) -> str:
        return "Operations on time series."

    def args_info(self) -> ArgsInfo:
        return {
            "list": [],
            "snapshot": [
                ArgInfo("--name", help_text="<time series>."),
                ArgInfo(expects_value=True, value_hint="search"),
            ],
            "get": [
                ArgInfo("--name", expects_value=True, help_text="<time series>"),
                ArgInfo("--start", expects_value=True, value_hint="datetime", help_text="<time series>"),
                ArgInfo("--end", expects_value=True, value_hint="datetime", help_text="<time series>"),
                ArgInfo("--group", expects_value=True, can_occur_multiple_times=True, help_text="<group>"),
                ArgInfo("--filter", expects_value=True, can_occur_multiple_times=True, help_text="<var><op><value>"),
                ArgInfo("--granularity", expects_value=True, help_text="<duration|integer>"),
                ArgInfo("--aggregation", expects_value=True, possible_values=["avg", "sum", "min", "max"]),
            ],
            "downsample": [],
        }

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def snapshot_time_series(part: str) -> AsyncIterator[str]:
            parser = NoExitArgumentParser()
            parser.add_argument("--name", type=str, required=True)
            parsed, rest = parser.parse_known_args(args_parts_parser.parse(part))
            graph_name = ctx.graph_name
            graph_db = self.dependencies.db_access.get_graph_db(graph_name)
            model = await self.dependencies.model_handler.load_model(graph_name)
            query = await self.dependencies.template_expander.parse_query(" ".join(rest), ctx.section, env=ctx.env)
            query_model = QueryModel(query, model, ctx.env)
            res = await self.dependencies.db_access.time_series_db.add_entries(parsed.name, query_model, graph_db)
            yield f"{res} entries added to time series {parsed.name}."

        async def load_time_series(part: str) -> Tuple[CLISourceContext, AsyncIterator[Json]]:
            def parse_duration_or_int(s: str) -> Union[int, timedelta]:
                try:
                    return parse_duration(s)
                except ParseError:
                    return int(s)

            parser = NoExitArgumentParser()
            parser.add_argument("--name", type=str, required=True)
            parser.add_argument("--start", type=parse_time_or_delta, required=True)
            parser.add_argument("--end", type=parse_time_or_delta, required=True)
            parser.add_argument("--group", type=str, nargs="*", default=None)
            parser.add_argument("--filter", type=predicate_term.parse, nargs="*", default=None)
            parser.add_argument("--granularity", type=parse_duration_or_int, default=5)
            parser.add_argument("--aggregation", choices=["avg", "sum", "min", "max"], default="avg")
            p = parser.parse_args(args_parts_unquoted_parser.parse(part))
            timeout = if_set(ctx.env.get("search_timeout"), duration)
            cursor = await self.dependencies.db_access.time_series_db.load_time_series(
                p.name,
                p.start,
                p.end,
                group_by=p.group,
                filter_by=p.filter,
                granularity=p.granularity,
                timeout=timeout,
                aggregation=p.aggregation,
            )
            return CLISourceContext(cursor.count(), cursor.full_count()), cursor

        async def list_ts() -> Tuple[int, JsGen]:
            ts = await self.dependencies.db_access.time_series_db.list_time_series()
            return len(ts), stream.iterate([to_js(a) for a in ts])

        async def downsample() -> Tuple[int, JsGen]:
            ts = await self.dependencies.db_access.time_series_db.downsample()
            if isinstance(ts, str):
                return 1, stream.just(ts)
            elif ts:
                return len(ts), stream.iterate([{k: v} for k, v in ts.items()])
            else:
                return 1, stream.just("No time series to downsample.")

        args = re.split("\\s+", arg, maxsplit=1) if arg else []
        if arg and len(args) == 2 and args[0] == "snapshot":
            return CLISource.single(
                partial(snapshot_time_series, args[1].strip()), required_permissions={Permission.read}
            )
        elif arg and len(args) == 2 and args[0] == "get":
            return CLISource(partial(load_time_series, args[1].strip()), required_permissions={Permission.read})
        elif arg and len(args) == 1 and args[0] == "list":
            return CLISource.only_count(list_ts, required_permissions={Permission.read})
        elif arg and len(args) == 1 and args[0] == "downsample":
            return CLISource.only_count(downsample, required_permissions={Permission.read})
        else:
            return CLISource.single(
                lambda: stream.just(self.rendered_help(ctx)), required_permissions={Permission.read}
            )


class DetectSecretsCommand(CLICommand):
    """
    ```
    detect-secrets [--path <path>] [--with-secrets]
    ```

    The detect-secrets command is able to detect secrets in resources or strings.

    A path can be defined, to not check the whole resource but only a specific property.
    This is usually recommended, since a lot of the properties are not relevant for secret detection.

    If the `--with-secrets` flag is provided, the command will filter all incoming resources and pass
    only those that contain secrets.


    ## Parameters

    - `--path` - The property path to check on every incoming element. Can be defined multiple times.
    - `--with-secrets` - Filter elements to only pass if a secret has been detected.

    ## Examples

    ```
    # Detect secrets anywhere in the node. Also return all resources no matter if secrets are found.
    > search is(kubernetes_pod) | detect-secrets
    potential_secret=AWS_SECRET_ACCESS_KEY=aeDrhaA3tXjkwIVJ43PHmkCi5, secret_detected=true, secret_type=Secret Keyword,
    kind=kubernetes_pod, name=collect, age=14d19h, last_update=90s, cloud=k8s, account=dev, region=jobs

    # Detect secrets anywhere in the node. Only return if a secret is found.
    > search is(kubernetes_pod) | detect-secrets --with-secrets
    potential_secret=AWS_SECRET_ACCESS_KEY=aeDrhaA3tXjkwIVJ43PHmkCi5, secret_detected=true, secret_type=Secret Keyword,
    kind=kubernetes_pod, name=collect, age=14d19h, last_update=90s, cloud=k8s, account=dev, region=jobs

    # Find a secret with a specific path in a resource. Only return if a secret is found.
    > search is(kubernetes_pod) | detect-secrets --with-secrets --path pod_spec.containers[*].args[*]
    potential_secret=AWS_SECRET_ACCESS_KEY=aeDrhaA3tXjkwIVJ43PHmkCi5, secret_detected=true, secret_type=Secret Keyword,
    kind=kubernetes_pod, name=collect, age=14d19h, last_update=90s, cloud=k8s, account=dev, region=jobs
    ```
    """

    @property
    def name(self) -> str:
        return "detect-secrets"

    def args_info(self) -> ArgsInfo:
        return [
            ArgInfo("--path", expects_value=True, value_hint="property", can_occur_multiple_times=True),
            ArgInfo("--with-secrets"),
        ]

    def info(self) -> str:
        return "Detect secrets in resources or strings"

    def additional_properties_to_show(self) -> List[Tuple[List[str], str]]:
        return [(["info"], "info")]

    @lru_cache(maxsize=1)  # cache is only used to not configure multiple times
    def configure_detect(self) -> None:
        with default_settings() as settings:
            sj = settings.json()
        # adjust the settings:
        override = defaultdict(dict, {"HexHighEntropyString": {"limit": 5}, "Base64HighEntropyString": {"limit": 5}})
        disabled: Set[str] = set()
        sj["plugins_used"] = [p | override[p["name"]] for p in sj.get("plugins_used", []) if p["name"] not in disabled]
        # make this the default settings
        configure_settings_from_baseline(sj)

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        parser = NoExitArgumentParser()
        parser.add_argument(
            "--path",
            type=lambda x: PropertyPath.from_string(ctx.variable_in_section(x)),
            nargs="*",
            default=[],
            action="append",
        )
        parser.add_argument("--with-secrets", action="store_true")
        parsed = parser.parse_args(args_parts_unquoted_parser.parse(arg) if arg else [])

        def walk_element(el: JsonElement) -> Iterator[Tuple[str, PotentialSecret]]:
            if isinstance(el, dict):
                for v in el.values():
                    yield from walk_element(v)
            elif isinstance(el, list):
                for v in el:
                    yield from walk_element(v)
            elif isinstance(el, str) and len(el):
                for secret in scan.scan_line(el):
                    r: str = plugins.initialize.from_secret_type(secret.type).format_scan_result(secret)  # type: ignore
                    if r.startswith("True"):
                        yield el, secret

        async def detect_secrets_in(content: JsStream) -> JsGen:
            self.configure_detect()  # make sure all plugins are loaded
            async with content.stream() as in_stream:
                async for element in in_stream:
                    paths = [p for pl in parsed.path for p in pl]
                    paths = paths or [PropertyPath.from_list([ctx.section]) if is_node(element) else EmptyPath]
                    found_secrets = False
                    for path in paths:
                        if to_check_js := path.value_in(element):
                            for secret_string, possible_secret in walk_element(to_check_js):
                                found_secrets = True
                                if isinstance(element, dict):
                                    element["info"] = {
                                        "secret_detected": True,
                                        "potential_secret": secret_string,
                                        "secret_type": possible_secret.type,
                                    }
                                yield element
                                break
                        if found_secrets:
                            break  # no need to check other paths
                    if not found_secrets and not parsed.with_secrets:
                        yield element

        return CLIFlow(detect_secrets_in)


@frozen
class ResourceRefinementMatch:
    on: PropertyPath
    value: JsonElement

    def matches(self, js: JsonElement) -> bool:
        return self.on.value_in(js) == self.value


@frozen
class ResourceRefinement:
    kind: str
    matches: ResourceRefinementMatch
    path: List[str]
    value: JsonElement


ResourceRefinements = [
    ResourceRefinement(
        kind="instance",
        matches=ResourceRefinementMatch(PropertyPath.from_list(["reported", "instance_status"]), value="terminated"),
        path=["kind", "metadata", "state-icon"],
        value="instance_terminated",
    ),
]


class RefineResourceDataCommand(CLICommand, InternalPart):
    """
    Internal command to adjust resource data for the UI to display.
    Not intended for direct use.
    """

    @property
    def name(self) -> str:
        return "refine-resource-data"

    def args_info(self) -> ArgsInfo:
        return []

    def info(self) -> str:
        return "Refine resource data"

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext, **kwargs: Any) -> CLIAction:
        async def load_model() -> Model:
            return await self.dependencies.model_handler.load_model(ctx.graph_name)

        def setup_stream(in_stream: JsStream) -> JsStream:
            def with_dependencies(model: Model) -> JsStream:
                async def process_element(el: JsonElement) -> JsonElement:
                    if (
                        is_node(el)
                        and (fqn := value_in_path(el, NodePath.reported_kind))
                        and isinstance(kind := model.get(fqn), ComplexKind)
                    ):
                        for refinement in ResourceRefinements:
                            if kind.is_a(refinement.kind) and refinement.matches.matches(el):
                                set_value_in_path(refinement.value, refinement.path, el)  # type: ignore
                    return el

                return in_stream | pipe.map(process_element)  # type: ignore

            return stream.call(load_model) | pipe.flatmap(with_dependencies)  # type: ignore

        return CLIFlow(setup_stream, required_permissions={Permission.read})


def all_commands(d: TenantDependencies) -> List[CLICommand]:
    commands = [
        AggregateCommand(d, "search"),
        AggregateToCountCommand(d, "search"),
        AncestorsPart(d, "search"),
        CertificateCommand(d, "setup", allowed_in_source_position=True),
        ChunkCommand(d, "misc"),
        CleanCommand(d, "action"),
        ConfigsCommand(d, "setup", allowed_in_source_position=True),
        CountCommand(d, "search"),
        DetectSecretsCommand(d, "action"),
        DbCommand(d, "action", allowed_in_source_position=True),
        DescendantsPart(d, "search"),
        DumpCommand(d, "format"),
        EchoCommand(d, "misc", allowed_in_source_position=True),
        EnvCommand(d, "misc", allowed_in_source_position=True),
        ExecuteTaskCommand(d, "action", allowed_in_source_position=True),
        ExecuteSearchCommand(d, "search", allowed_in_source_position=True),
        FlattenCommand(d, "misc"),
        FormatCommand(d, "format"),
        HeadCommand(d, "search"),
        HistoryPart(d, "search", allowed_in_source_position=True),
        HttpCommand(d, "action"),
        JobsCommand(d, "action", allowed_in_source_position=True),
        JqCommand(d, "misc"),
        JsonCommand(d, "misc", allowed_in_source_position=True),
        KindsCommand(d, "search", allowed_in_source_position=True),
        LimitPart(d, "search"),
        ListCommand(d, "format"),
        TemplatesCommand(d, "search", allowed_in_source_position=True),
        PredecessorsPart(d, "search"),
        ProtectCommand(d, "action"),
        RefineResourceDataCommand(d, "action"),
        ReportCommand(d, "misc", allowed_in_source_position=True),
        SearchPart(d, "search", allowed_in_source_position=True),
        SetDesiredCommand(d, "action"),
        SetMetadataCommand(d, "action"),
        SleepCommand(d, "misc", allowed_in_source_position=True),
        SortPart(d, "search"),
        SuccessorsPart(d, "search"),
        SystemCommand(d, "setup", allowed_in_source_position=True),
        TagCommand(d, "action"),
        TailCommand(d, "search"),
        TimeSeriesCommand(d, "action", allowed_in_source_position=True),
        UniqCommand(d, "misc"),
        UserCommand(d, "setup", allowed_in_source_position=True),
        WorkflowsCommand(d, "action", allowed_in_source_position=True),
        WelcomeCommand(d, "misc", allowed_in_source_position=True),
        TipOfTheDayCommand(d, "misc", allowed_in_source_position=True),
        WriteCommand(d, "misc"),
        AppsCommand(d, "misc", allowed_in_source_position=True),
        GraphCommand(d, "setup", allowed_in_source_position=True),
    ]
    # commands that are only available when the system is started in debug mode
    if d.config.runtime.debug:
        commands.extend(
            [
                FileCommand(d, "misc"),
                UploadCommand(d, "misc"),
            ]
        )

    return commands


def alias_names() -> Dict[str, str]:
    # command alias -> command name
    return {
        "match": "search",
        "query": "search",
        "https": "http",
        "kind": "kinds",
        "config": "configs",
        "tags": "tag",
        "predecessor": "predecessors",
        "successor": "successors",
        "descendant": "descendants",
        "ancestor": "ancestors",
        "job": "jobs",
        "lists": "list",
        "template": "templates",
        "ts": "timeseries",
        "workflow": "workflows",
        "app": "apps",
        "man": "help",
        "users": "user",
    }
