from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os.path
import re
import shutil
import tarfile
import tempfile
from abc import abstractmethod, ABC
from argparse import Namespace
from asyncio import iscoroutine, Queue, Future, Task
from asyncio.subprocess import Process
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
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
    AsyncGenerator,
)

import aiofiles
import jq
from aiostream import stream
from aiostream.aiter_utils import is_async_iterable
from aiostream.core import Stream
from parsy import Parser, string

from core.analytics import AnalyticsEventSender
from core.async_extensions import run_async
from core.cli import key_values_parser, strip_quotes, is_node, JsGen, NoExitArgumentParser, is_edge
from core.db.db_access import DbAccess
from core.db.model import QueryModel
from core.error import CLIParseError, ClientError, CLIExecutionError
from core.message_bus import MessageBus
from core.model.graph_access import Section
from core.model.model import Model, Kind, ComplexKind, DictionaryKind, SimpleKind
from core.model.model_handler import ModelHandler
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
from core.query.model import Query, P, Template
from core.query.query_parser import parse_query
from core.query.template_expander import tpl_props_p, TemplateExpander
from core.task.job_handler import JobHandler
from core.types import Json, JsonElement
from core.util import (
    AccessJson,
    uuid_str,
    value_in_path_get,
    value_in_path,
    utc,
    shutdown_process,
    if_set,
    duration,
    identity,
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
from core.worker_task_queue import WorkerTask, WorkerTaskQueue

log = logging.getLogger(__name__)


class CLIDependencies:
    def __init__(self, **deps: Any) -> None:
        self.lookup: Dict[str, Any] = deps

    def extend(self, **deps: Any) -> CLIDependencies:
        self.lookup = {**self.lookup, **deps}
        return self

    @property
    def args(self) -> Namespace:
        return self.lookup["args"]  # type: ignore

    @property
    def message_bus(self) -> MessageBus:
        return self.lookup["message_bus"]  # type:ignore

    @property
    def event_sender(self) -> AnalyticsEventSender:
        return self.lookup["event_sender"]  # type:ignore

    @property
    def db_access(self) -> DbAccess:
        return self.lookup["db_access"]  # type:ignore

    @property
    def model_handler(self) -> ModelHandler:
        return self.lookup["model_handler"]  # type:ignore

    @property
    def job_handler(self) -> JobHandler:
        return self.lookup["job_handler"]  # type:ignore

    @property
    def worker_task_queue(self) -> WorkerTaskQueue:
        return self.lookup["worker_task_queue"]  # type:ignore

    @property
    def template_expander(self) -> TemplateExpander:
        return self.lookup["template_expander"]  # type:ignore

    @property
    def forked_tasks(self) -> Queue[Tuple[Task[JsonElement], str]]:
        return self.lookup["forked_tasks"]  # type:ignore


@dataclass
class CLIContext:
    env: Dict[str, str] = field(default_factory=dict)
    uploaded_files: Dict[str, str] = field(default_factory=dict)  # id -> path


EmptyContext = CLIContext()


class MediaType(Enum):
    Json = 1
    FilePath = 2

    @property
    def json(self) -> bool:
        return self == MediaType.Json

    @property
    def file_path(self) -> bool:
        return self == MediaType.FilePath

    def __repr__(self) -> str:
        return "application/json" if self == MediaType.Json else "application/octet-stream"


@dataclass
class CLICommandRequirement:
    name: str


@dataclass
class CLIFileRequirement(CLICommandRequirement):
    path: str  # local client path


class CLIAction(ABC):
    def __init__(self, produces: MediaType, requires: Optional[List[CLICommandRequirement]]) -> None:
        self.produces = produces
        self.required = requires if requires else []

    @staticmethod
    def make_stream(in_stream: JsGen) -> Stream:
        return in_stream if isinstance(in_stream, Stream) else stream.iterate(in_stream)


class CLISource(CLIAction):
    def __init__(
        self,
        fn: Callable[[], Union[Tuple[Optional[int], JsGen], Awaitable[Tuple[Optional[int], JsGen]]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> None:
        super().__init__(produces, requires)
        self._fn = fn

    async def source(self) -> Tuple[Optional[int], Stream]:
        res = self._fn()
        count, gen = await res if iscoroutine(res) else res  # type: ignore
        return count, self.make_stream(await gen if iscoroutine(gen) else gen)

    @staticmethod
    def with_count(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        count: Optional[int],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> CLISource:
        async def combine() -> Tuple[Optional[int], JsGen]:
            res = fn()
            gen = await res if iscoroutine(res) else res  # type: ignore
            return count, gen

        return CLISource(combine, produces, requires)

    @staticmethod
    def single(
        fn: Callable[[], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> CLISource:
        return CLISource.with_count(fn, 1, produces, requires)

    @staticmethod
    def empty() -> CLISource:
        return CLISource.with_count(stream.empty, 0)


class CLIFlow(CLIAction):
    def __init__(
        self,
        fn: Callable[[JsGen], Union[JsGen, Awaitable[JsGen]]],
        produces: MediaType = MediaType.Json,
        requires: Optional[List[CLICommandRequirement]] = None,
    ) -> None:
        super().__init__(produces, requires)
        self._fn = fn

    async def flow(self, in_stream: JsGen) -> Stream:
        gen = self._fn(self.make_stream(in_stream))
        return self.make_stream(await gen if iscoroutine(gen) else gen)  # type: ignore


class CLICommand(ABC):
    """
    The CLIPart is the base for all participants of the cli execution.
    Source: generates a stream of objects
    Flow: transforms the elements in a stream of objects
    Sink: takes a stream of objects and creates a result
    """

    def __init__(self, dependencies: CLIDependencies):
        self.dependencies = dependencies

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def help(self) -> str:
        # if not defined in subclass, fallback to inline doc
        doc = inspect.getdoc(type(self))
        return doc if doc else f"{self.name}: no help available."

    @abstractmethod
    def info(self) -> str:
        pass

    @abstractmethod
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
        pass


class InternalPart(ABC):
    """
    Internal parts can be executed but are not shown via help.
    They usually get injected by the CLI Interpreter to ease usability.
    """


class OutputTransformer(ABC):
    """
    Mark all commands that transform the output stream (formatting).
    """


class PreserveOutputFormat(ABC):
    """
    Mark all commands where the output should not be flattened to default line output.
    """


# A QueryPart is a command that can be used on the command line.
# Such a part is not executed, but builds a query, which is executed.
# Therefore, the parse method is implemented in a dummy fashion here.
# The real interpretation happens in CLI.create_query.
class QueryPart(CLICommand, ABC):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
        return CLISource.empty()


class QueryAllPart(QueryPart):
    """
    Usage: query [--include-edges] <property.path> <op> <value"

    Part of a query.
    With this command you can query all sections directly.
    In order to define the section, all parameters have to be prefixed by the section name.

    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Parameter:
        --include-edges: This flag indicates, that not only nodes should be returned, but also all related edges.

    Example:
        query reported.prop1 == "a"          # matches documents with reported section like { "prop1": "a" ....}
        query desired.some.nested in [1,2,3] # matches documents with desired section like { "some": { "nested" : 1 ..}
        query reported.array[*] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }
        query reported.array[1] == 2         # matches documents with reported section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "query"

    def info(self) -> str:
        return "Matches a property in all sections."


class ReportedPart(QueryPart):
    """
    Usage: reported <property.path> <op> <value"

    Part of a query.
    The reported section contains the values directly from the collector.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        reported prop1 == "a"             # matches documents with reported section like { "prop1": "a" ....}
        reported some.nested in [1,2,3]   # matches documents with reported section like { "some": { "nested" : 1 ..}..}
        reported array[*] == 2            # matches documents with reported section like { "array": [1, 2, 3] ... }
        reported array[1] == 2            # matches documents with reported section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.reported

    def info(self) -> str:
        return "Matches a property in the reported section."


class DesiredPart(QueryPart):
    """
    Usage: desired <property.path> <op> <value"

    Part of a query.
    The desired section contains values set by tools to change the state of this node.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        desired prop1 == "a"             # matches documents with desired section like { "prop1": "a" ....}
        desired prop1 =~ "a.*"           # matches documents with desired section like { "prop1": "a" ....}
        desired some.nested in [1,2,3]   # matches documents with desired section like { "some": { "nested" : 1 ..}..}
        desired array[*] == 2            # matches documents with desired section like { "array": [1, 2, 3] ... }
        desired array[1] == 2            # matches documents with desired section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.desired

    def info(self) -> str:
        return "Matches a property in the desired section."


class MetadataPart(QueryPart):
    """
    Usage: metadata <property.path> <op> <value"

    Part of a query.
    The metadata section is set by the collector and holds additional meta information about this node.
    With this command you can query this section for a matching property.
    The property is the complete path in the json structure.
    Operation is one of: <=, >=, >, <, ==, !=, =~, !~, in, not in
    value is a json encoded value to match.

    Example:
        metadata prop1 == "a"             # matches documents with metadata section like { "prop1": "a" ....}
        metadata prop1 =~ "a.*"           # matches documents with metadata section like { "prop1": "a" ....}
        metadata some.nested in [1,2,3]   # matches documents with metadata section like { "some": { "nested" : 1 ..}..}
        metadata array[*] == 2            # matches documents with metadata section like { "array": [1, 2, 3] ... }
        metadata array[1] == 2            # matches documents with metadata section like { "array": [1, 2, 3] ... }

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return Section.metadata

    def info(self) -> str:
        return "Matches a property in the metadata section."


class PredecessorPart(QueryPart):
    """
    Usage: predecessors [edge_type]

    Part of a query.
    Select all predecessors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | predecessors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "predecessors"

    def info(self) -> str:
        return "Select all predecessors of this node in the graph."


class SuccessorPart(QueryPart):
    """
    Usage: successors [edge_type]

    Part of a query.
    Select all successors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | successors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "successors"

    def info(self) -> str:
        return "Select all successor of this node in the graph."


class AncestorPart(QueryPart):
    """
    Usage: ancestors [edge_type]

    Part of a query.
    Select all ancestors of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | ancestors | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "ancestors"

    def info(self) -> str:
        return "Select all ancestors of this node in the graph."


class DescendantPart(QueryPart):
    """
    Usage: descendants [edge_type]

    Part of a query.
    Select all descendants of this node in the graph.
    The graph may contain different types of edges (e.g. the delete graph or the dependency graph).
    In order to define which graph to walk, the edge_type can be specified.

    Parameter:
        edge_type [Optional, defaults to dependency]: This argument defines which edge type to use.

    Example:
        metadata prop1 == "a" | descendants | match prop2 == "b"

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "descendants"

    def info(self) -> str:
        return "Select all descendants of this node in the graph."


class AggregatePart(QueryPart):
    """
    Usage: aggregate [group_prop, .., group_prop]: [function(), .. , function()]

    Part of a query.
    Using the results of a query by aggregating over properties of this result
    by aggregating over given properties and applying given aggregation functions.

    Parameter:
        group_prop: the name of the property to use for grouping. Multiple grouping variables are possible.
                    Every grouping variable can be renamed via an as name directive. (prop as prop_name)
        function(): grouping function to be applied on every resulting node.
                    Following functions are possible: sum, count, min, max, avg
                    The function contains the variable name (e.g.: min(path.to.prop))
                    It is possible to use static values (e.g.: sum(1))
                    It is possible to use simple math expressions in the function (e.g. min(path.to.prop * 3 + 2))
                    It is possible to name the result of this function (e.g. count(foo) as number_of_foos)

    Example:
        aggregate reported.kind as kind, reported.cloud.name as cloud, reported.region.name as region : sum(1) as count
            [
                { "count": 228, "group": { "cloud": "aws", "kind": "aws_ec2_instance", "region": "us-east-1" }},
                { "count": 326, "group": { "cloud": "gcp", "kind": "gcp_instance", "region": "us-west1" }},
                .
                .
            ]
        aggregate reported.instance_status as status: sum(reported.cores) as cores, sum(reported.memory) as mem
            [
                { "cores": 116, "mem": 64 , "group": { "status": "busy" }},
                { "cores": 2520, "mem": 9824, "group": { "status": "running" }},
                { "cores": 257, "mem": 973, "group": { "status": "stopped" }},
                { "cores": 361, "mem": 1441, "group": { "status": "terminated" }},
            ]

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "aggregate"

    def info(self) -> str:
        return "Aggregate this query by the provided specification"


class MergeAncestorsPart(QueryPart):
    """
    Usage: merge_ancestors [kind, kind as name, ..., kind]

    For all query results, merge the nodes with ancestor nodes of given kind.
    Multiple ancestors can be provided.
    Note: the first defined ancestor kind is used to stop the search of all other kinds.
          This should be taken into consideration when the list of ancestor kinds is defined!
    The resulting reported content of the ancestor node is merged into the current reported node
    with the kind name or the alias.

    Parameter:
        kind [Mandatory] [as name]: search the ancestors of this node for a node of define kind.
                                    Merge the result into the current node either under the kind name or the alias name.

    Example:
        compute_instance: the graph os traversed starting with the current node in direction to the root.
                          When a node is found, which is of type compute_instance, the reported content of this node
                          is merged with the reported content of the compute_instance node:
                          { "id": "xyz", "reported": { "kind": "ebs", "compute_instance": { props from compute_instance}
        compute_instance as ci:
                          { "id": "xyz", "reported": { "kind": "ebs", "ci": { props from compute_instance}


    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
    """

    @property
    def name(self) -> str:
        return "merge_ancestors"

    def info(self) -> str:
        return "Merge the results of this query with the content of ancestor nodes of given type"


class HeadCommand(QueryPart):
    """
    Usage: head [num]

    Take <num> number of elements from the input stream and send them downstream.
    The rest of the stream is discarded.

    Parameter:
        num [optional, defaults to 100]: the number of elements to take from the head

    Example:
         json [1,2,3,4,5] | head 2  # will result in [1, 2]
         json [1,2,3,4,5] | head    # will result in [1, 2, 3, 4, 5]
    """

    @property
    def name(self) -> str:
        return "head"

    def info(self) -> str:
        return "Return n first elements of the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
        size = self.parse_size(arg)
        return CLIFlow(lambda in_stream: stream.take(in_stream, size))

    @staticmethod
    def parse_size(arg: Optional[str]) -> int:
        return abs(int(arg)) if arg else 100


class TailCommand(QueryPart):
    """
    Usage: tail [num]

    Take the last <num> number of elements from the input stream and send them downstream.
    The beginning of the stream is consumed, but discarded.

    Parameter:
        num [optional, defaults to 100]: the number of elements to return from the end.

    Example:
         json [1,2,3,4,5] | tail 2  # will result in [4, 5]
         json [1,2,3,4,5] | head    # will result in [1, 2, 3, 4, 5]
    """

    @property
    def name(self) -> str:
        return "tail"

    def info(self) -> str:
        return "Return n last elements of the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
        size = HeadCommand.parse_size(arg)
        return CLIFlow(lambda in_stream: stream.takelast(in_stream, size))


class CountCommand(QueryPart):
    """
    Usage: count [arg]

    In case no arg is given: it counts the number of instances provided to count.
    In case of arg: it pulls the property with the name of arg and counts the occurrences of this property.

    Parameter:
        arg [optional]: Instead of counting the instances, count the occurrences of given instance.

    Example:
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count    # will result in [[ "total matched: 3", "total unmatched: 0" ]]
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count a  # will result in [[ "1:1", "2:1", "3:1", .... ]]
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count b  # will result in [[ "total matched: 0", "total unmatched: 3" ]]
    """

    @property
    def name(self) -> str:
        return "count"

    def info(self) -> str:
        return "Count incoming elements or sum defined property."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        get_path = arg.split(".") if arg else None
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
    Usage: echo <message>

    Send the provided message to downstream.

    Example:
        echo "test"              # will result in ["test"]
    """

    @property
    def name(self) -> str:
        return "echo"

    def info(self) -> str:
        return "Send the provided message to downstream"

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        return CLISource.single(lambda: stream.just(strip_quotes(arg if arg else "")))


class JsonCommand(CLICommand):
    """
    Usage: json <json>

    The defined json will be parsed and written to the out stream.
    If the defined element is a json array, each element will be send downstream.

    Example:
        json "test"              # will result in ["test"]
        json [1,2,3,4] | count   # will result in [{ "matched": 4, "not_matched": 0 }]
    """

    @property
    def name(self) -> str:
        return "json"

    def info(self) -> str:
        return "Parse json and pass parsed objects to the output stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
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
    Usage: sleep <seconds>

    Sleep the amount of seconds. An empty string is emitted.

    Example:
        sleep 123        # will result in [""] after 123 seconds
    """

    @property
    def name(self) -> str:
        return "sleep"

    def info(self) -> str:
        return "Suspend execution for an interval of time"

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:

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
    Usage: aggregate_to_count

    This command transforms the output of an aggregation query to the output of the count command.
    { "group": { "name": "group_name" }, "count": 123 }  --> group_name: 123
    Expected group key: `name`
    Expected function key: `count`

    It is usually not invoked directly but automatically invoked when there is a query | count cli command.
    """

    @property
    def name(self) -> str:
        return "aggregate_to_count"

    def info(self) -> str:
        return "Convert the output of an aggregate query to the result of count."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
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
    Usage: execute_query [--include-edges] <query>

    A query is performed against the graph database and all resulting elements will be emitted.
    To learn more about the query, visit https://docs.some.engineering/

    Parameter:
        --include-edges: This flag indicates, that not only nodes should be returned, but also all related edges.


    Example:
        execute_query isinstance("ec2") and (cpu>12 or cpu<3)  # will result in all matching elements [{..}, {..}, ..]

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
        section [optional, defaults to "reported"]: on which section the query is performed
    """

    @property
    def name(self) -> str:
        return "execute_query"

    def info(self) -> str:
        return "Query the database and pass the results to the output stream."

    @staticmethod
    def parse_known(arg: str) -> Tuple[Dict[str, Any], str]:
        parser = NoExitArgumentParser()
        parser.add_argument("--include-edges", dest="include-edges", action="store_true")
        parsed, rest = parser.parse_known_args(arg.split(maxsplit=1))
        return vars(parsed), " ".join(rest)

    @staticmethod
    def argument_string(args: Dict[str, Any]) -> str:
        result = ""
        for key, value in args.items():
            if value is True:
                result += f"--{key}"
        return result + " " if result else ""

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        # db name is coming from the env
        graph_name = ctx.env["graph"]
        if not arg:
            raise CLIParseError("query command needs a query to execute, but nothing was given!")

        # Read all argument flags / options
        parsed, rest = self.parse_known(arg)

        # all templates are expanded at this point, so we can call the parser directly.
        query = parse_query(rest)
        db = self.dependencies.db_access.get_graph_db(graph_name)

        async def prepare() -> Tuple[Optional[int], AsyncIterator[Json]]:
            model = await self.dependencies.model_handler.load_model()
            query_model = QueryModel(query, model)
            await db.to_query(query_model)  # only here to validate the query itself (can throw)
            count = ctx.env.get("count", "true").lower() != "false"
            timeout = if_set(ctx.env.get("query_timeout"), duration)
            context = (
                await db.query_aggregation(query_model)
                if query.aggregate
                else (
                    await db.query_graph_gen(query_model, with_count=count, timeout=timeout)
                    if parsed.get("include-edges")
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

        return CLISource(prepare)


class EnvCommand(CLICommand):
    """
    Usage: env

    Emits the provided environment.
    This is useful to inspect the environment given to the CLI interpreter.

    Example:
        env  # will result in a json object representing the env. E.g.: [{ "env_var1": "test", "env_var2": "foo" }]
    """

    @property
    def name(self) -> str:
        return "env"

    def info(self) -> str:
        return "Retrieve the environment and pass it to the output stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        return CLISource.with_count(lambda: stream.just(ctx.env), len(ctx.env))


class ChunkCommand(CLICommand):
    """
    Usage: chunk [num]

    Take <num> number of elements from the input stream, put them in a list and send a stream of list downstream.
    The last chunk might have a lower size than the defined chunk size.

    Parameter:
        num [optional, defaults to 100]: the number of elements to put into a chunk.

    Example:
         json [1,2,3,4,5] | chunk 2  # will result in [[1, 2], [3, 4], [5]]
         json [1,2,3,4,5] | chunk    # will result in [[1, 2, 3, 4, 5]]

    See:
        flatten for the reverse operation.
    """

    @property
    def name(self) -> str:
        return "chunk"

    def info(self) -> str:
        return "Chunk incoming elements in batches."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        size = int(arg) if arg else 100
        return CLIFlow(lambda in_stream: stream.chunks(in_stream, size))


class FlattenCommand(CLICommand):
    """
    Usage: flatten

    Take array elements from the input stream and put them to the output stream one after the other,
    while preserving the original order.

    Example:
         json [1, 2, 3, 4, 5] | chunk 2 | flatten  # will result in [1, 2, 3, 4, 5]
         json [1, 2, 3, 4, 5] | flatten            # nothing to flat [1, 2, 3, 4, 5]
         json [[1, 2], 3, [4, 5]] | flatten        # will result in [1, 2, 3, 4, 5]

    See:
        chunk which is able to put incoming elements into chunks
    """

    @property
    def name(self) -> str:
        return "flatten"

    def info(self) -> str:
        return "Take incoming batches of elements and flattens them to a stream of single elements."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        def iterate(it: Any) -> Stream:
            return stream.iterate(it) if is_async_iterable(it) or isinstance(it, Iterable) else stream.just(it)

        return CLIFlow(lambda in_stream: stream.flatmap(in_stream, iterate))


class UniqCommand(CLICommand):
    """
    Usage: uniq

    All elements flowing through the uniq command are analyzed and all duplicates get removed.
    Note: a hash value is computed from json objects, which is ignorant of the order of properties,
    so that {"a": 1, "b": 2} is declared equal to {"b": 2, "a": 1}

    Example:
        json [1, 2, 3, 1, 2, 3] | uniq                     # will result in [1, 2, 3]
        json [{"a": 1, "b": 2}, {"b": 2, "a": 1}] | uniq   # will result in [{"a": 1, "b": 2}]
    """

    @property
    def name(self) -> str:
        return "uniq"

    def info(self) -> str:
        return "Remove all duplicated objects from the stream."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
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
    Usage: jq <filter>

    Use the well known jq JSON processor to manipulate incoming json.
    Every element from the incoming stream is passed to the this jq command.
    See: https://stedolan.github.io/jq/ for a list of possible jq arguments.

    Parameter:
        filter: the filter argument for jq.

    Example:
        $> query is(aws_ec2_instance) | jq '.reported.id'
           ["id-1", "id-2"]
           Query all aws ec2 instances and then only pick the reported.id.
        $> query is(aws_ec2_instance) | jq '. | {id: .reported.id, rev:.revision}'
           [{"id": "id-1", "rev": "1"}, {"id": "id-2", "rev": "5"}]

    See also: format, list.
    """

    @property
    def name(self) -> str:
        return "jq"

    def info(self) -> str:
        return "Filter and process json."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        if not arg:
            raise AttributeError("jq requires an argument to be parsed")

        compiled = jq.compile(strip_quotes(arg))

        def process(in_json: Json) -> Json:
            out = compiled.input(in_json).all()
            result = out[0] if len(out) == 1 else out
            return cast(Json, result)

        return CLIFlow(lambda in_stream: stream.map(in_stream, process))


class KindCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: kind [-p property_path] [name_of_kind]

    kind gives information about the graph data kinds.

    Use case 1: show all available kinds:
    $> kind
    This will list all available kinds and print the name as list.

    Use case 2: show all details about a specific kind:
    $> kind graph_root
    This will show all available information about the given kind.

    Use case 3: I want to know the kind of a property in my model
    $> kind reported.tags.owner
    Lookup the type of the given property in the model.
    Assume a complex model A with reported properties: name:string, tags:dictionary[string, string]
    A lookup of property name reported.tags.owner will yield the type string


    Parameter:
        name_of_kind: the name of the kind to show more detailed information.
        -p <path>: the path of the property where want to know the kind


    Example:
        kind                   # will result in the list of kinds e.g. [ cloud, account, region ... ]
        kind graph_root        # will show information about graph root. { "name": "graph_root", .... }
        kind -p reported.tags  # will show the kind of the property with this path.
    """

    @property
    def name(self) -> str:
        return "kind"

    def info(self) -> str:
        return "Retrieves information about the graph data kinds."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
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
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_desired, arg, ctx.env["graph"], self.patch(arg, **ctx.env))
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
    Usage: set_desired [property]=[value]

    Set one or more desired properties for every database node that is received on the input channel.
    The desired state of each node in the database is merged with this new desired state, so that
    existing desired state not defined in this command is not touched.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    The result of this command will emit the complete object with desired and reported state:
    { "id": "..", "desired": { .. }, "reported": { .. } }

    Parameter:
       One or more parameters of form [property]=[value] separated by a space.
       [property] is the name of the property to set.
       [value] is a json primitive type: string, int, number, boolean or null.
       Quotation marks for strings are optional.


    Example:
        query isinstance("ec2") | set_desired a=b b="c" num=2   # will result in
            [
                { "id": "abc" "desired": { "a": "b", "b: "c" "num": 2, "other": "abc" }, "reported": { .. } },
                .
                .
                { "id": "xyz" "desired": { "a": "b", "b: "c" "num": 2 }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | set_desired a=b
            [
                { "id": "id1", "desired": { "a": b }, "reported": { .. } },
                { "id": "id2", "desired": { "a": b }, "reported": { .. } },
            ]
        json ["id1", "id2"] | set_desired a=b
            [
                { "id": "id1", "desired": { "a": b }, "reported": { .. } },
                { "id": "id2", "desired": { "a": b }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "set_desired"

    def info(self) -> str:
        return "Allows to set arbitrary properties as desired for all incoming database objects."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class CleanCommand(SetDesiredStateBase):
    """
    Usage: clean [reason]

    Mark incoming objects for cleaning.
    All objects marked as such will be eventually cleaned in the next delete run.

    An optional reason can be provided.
    This reason is used to log each marked element, which can be useful to understand the reason
    a resource is cleaned later on.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    The result of this command will emit the complete object with desired and reported state:
    { "id": "..", "desired": { .. }, "reported": { .. } }

    Parameter:
        reason [optional]: the reason why this resource is marked for cleaning

    Example:
        query isinstance("ec2") and atime<"-2d" | clean
            [
                { "id": "abc" "desired": { "delete": true }, "reported": { .. } },
                .
                .
                { "id": "xyz" "desired": { "delete": true }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | clean
            [
                { "id": "id1", "desired": { "delete": true }, "reported": { .. } },
                { "id": "id2", "desired": { "delete": true }, "reported": { .. } },
            ]
        json ["id1", "id2"] | clean
            [
                { "id": "id1", "desired": { "delete": true }, "reported": { .. } },
                { "id": "id2", "desired": { "delete": true }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "clean"

    def info(self) -> str:
        return "Mark all incoming database objects for cleaning."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        return {"clean": True}

    async def set_desired(
        self, arg: Optional[str], graph_name: str, patch: Json, items: List[Json]
    ) -> AsyncIterator[JsonElement]:
        reason = f"Reason: {arg}" if arg else "No reason provided."
        async for elem in super().set_desired(arg, graph_name, patch, items):
            uid = value_in_path(elem, NodePath.node_id)
            r_id = value_in_path_get(elem, NodePath.reported_id, "<no id>")
            r_name = value_in_path_get(elem, NodePath.reported_name, "<no name>")
            r_kind = value_in_path_get(elem, NodePath.reported_kind, "<no kind>")
            log.info(f"Node id={r_id}, name={r_name}, kind={r_kind} marked for cleanup. {reason}. ({uid})")
            yield elem


class SetMetadataStateBase(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        buffer_size = 1000
        func = partial(self.set_metadata, ctx.env["graph"], self.patch(arg, **ctx.env))
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
    Usage: set_metadata [property]=[value]

    Set one or more metadata properties for every database node that is received on the input channel.
    The metadata state of each node in the database is merged with this new metadata state, so that
    existing metadata state not defined in this command is not touched.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    Parameter:
       One or more parameters of form [property]=[value] separated by a space.
       [property] is the name of the property to set.
       [value] is a json primitive type: string, int, number, boolean or null.
       Quotation marks for strings are optional.


    Example:
        query isinstance("ec2") | set_metadata a=b b="c" num=2   # will result in
            [
                { "id": "abc" "metadata": { "a": "b", "b: "c" "num": 2, "other": "abc" }, "reported": { .. } },
                .
                .
                { "id": "xyz" "metadata": { "a": "b", "b: "c" "num": 2 }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | set_metadata a=b
            [
                { "id": "id1", "metadata": { "a": b }, "reported": { .. } },
                { "id": "id2", "metadata": { "a": b }, "reported": { .. } },
            ]
        json ["id1", "id2"] | set_metadata a=b
            [
                { "id": "id1", "metadata": { "a": b }, "reported": { .. } },
                { "id": "id2", "metadata": { "a": b }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "set_metadata"

    def info(self) -> str:
        return "Allows to set arbitrary properties as metadata for all incoming database objects."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class ProtectCommand(SetMetadataStateBase):
    """
    Usage: protect

    Mark incoming objects as protected.
    All objects marked as such will be safe from deletion.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    Example:
        query isinstance("ec2") and atime<"-2d" | protect
            [
                { "id": "abc" "metadata": { "protected": true }, "reported": { .. } },
                .
                .
                { "id": "xyz" "metadata": { "protected": true }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | clean
            [
                { "id": "id1", "metadata": { "protected": true }, "reported": { .. } },
                { "id": "id2", "metadata": { "protected": true }, "reported": { .. } },
            ]
        json ["id1", "id2"] | clean
            [
                { "id": "id1", "metadata": { "protected": true }, "reported": { .. } },
                { "id": "id2", "metadata": { "protected": true }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "protect"

    def info(self) -> str:
        return "Mark all incoming database objects as protected."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        return {"protected": True}


class FormatCommand(CLICommand, OutputTransformer):
    """
    Usage: format <format string>

    This command creates a string from the json input based on the format string.
    The format string might contain placeholders in curly braces that access properties of the json object.
    If a property is not available, it will result in the string `null`.

    Parameter:
        format_string [mandatory]: a string with any content with placeholders to be filled by the object.

    Example:
        json {"a":"b", "b": {"c":"d"}} | format {a}!={b.c}          # This will result in [ "b!=d" ]
        json {"b": {"c":[0,1,2,3]}} | format only select >{b.c[2]}< # This will result in [ "only select >2<" ]
        json {"b": {"c":[0,1,2,3]}} | format only select >{b.c[2]}< # This will result in [ "only select >2<" ]
        json {} | format {a}:{b.c.d}:{foo.bla[23].test}             # This will result in [ "null:null:null" ]
    """

    @property
    def name(self) -> str:
        return "format"

    def info(self) -> str:
        return "Transform incoming objects as string with a defined format."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        def fmt(elem: Any) -> str:
            # wrap the object to account for non existent values.
            # if a format value is not existent, render is as null (json conform).
            wrapped = AccessJson(elem, "null") if isinstance(elem, dict) else elem
            return arg.format_map(wrapped)  # type: ignore

        return CLIFlow(lambda in_stream: in_stream if arg is None else stream.map(in_stream, fmt))


@make_parser
def list_single_arg_parse() -> Parser:
    name = yield variable_dp
    as_name = yield (space_dp >> string("as") >> space_dp >> literal_dp).optional()
    return name, as_name


list_arg_parse = list_single_arg_parse.sep_by(comma_p, min=1)


class DumpCommand(CLICommand, OutputTransformer):
    """
    Usage: dump

    Dump all properties of an incoming element.
    If no output format is given, the output is transformed to fit on one line per element using the list command.
    Dump will maintain all incoming properties.

    See: list, jq, format
    """

    @property
    def name(self) -> str:
        return "dump"

    def info(self) -> str:
        return "Dump all properties of incoming objects."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        # Dump returns the same stream as provided without changing anything.
        # Since it is an OutputTransformer, the resulting transformer will be dump (not list).
        return CLIFlow(identity)


class ListCommand(CLICommand, OutputTransformer):
    """
    Usage: list [props_to_show]

    This command creates a string from the json input based on the defined properties to show.

    If no prop is defined a predefined list of properties will be shown:
        - reported.kind as kind
        - reported.id as id
        - reported.name as name
        - reported.age as age
        - ancestors.cloud.reported.name as cloud
        - ancestors.account.reported.name as account
        - ancestors.region.reported.name as region
        - ancestors.zone.reported.name as zone

    If props_to_show is defined, it will override the default and will show the defined properties.
    The syntax for props_to_show is a comma delimited list of property paths.
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


    Parameter:
        props_to_show [optional]: a space delimited definition of properties to show

    Example:
        $> query is(aws_ec2_instance) limit 3 | list
          kind=aws_ec2_instance, id=1, name=sun, ctime=2020-09-10T13:24:45Z, cloud=aws, account=prod, region=us-west-2
          kind=aws_ec2_instance, id=2, name=moon, ctime=2021-09-21T01:08:11Z, cloud=aws, account=dev, region=us-west-2
          kind=aws_ec2_instance, id=3, name=star, ctime=2021-09-25T23:28:40Z, cloud=aws, account=int, region=us-east-1

        $> query is(aws_ec2_instance) limit 3 | list reported.name
          name=sun
          name=moon
          name=star

        # section name is missing, reported is used automatically
        $> query is(aws_ec2_instance) limit 3 | list kind, name
          kind=aws_ec2_instance, name=sun
          kind=aws_ec2_instance, name=moon
          kind=aws_ec2_instance, name=star

        $> query is(aws_ec2_instance) limit 3 | list kind as a, name as b
          a=aws_ec2_instance, b=sun
          a=aws_ec2_instance, b=moon
          a=aws_ec2_instance, b=star

        $> query is(aws_ec2_instance) limit 3 | list kind as a, name as b, does_not_exist
          a=aws_ec2_instance, b=sun
          a=aws_ec2_instance, b=moon
          a=aws_ec2_instance, b=star
    """

    # This is the list of properties to show in the list command by default
    default_properties_to_show = [
        ("reported.kind", "kind"),
        ("reported.id", "id"),
        ("reported.name", "name"),
        ("reported.age", "age"),
        ("reported.last_update", "last_update"),
        ("ancestors.cloud.reported.name", "cloud"),
        ("ancestors.account.reported.name", "account"),
        ("ancestors.region.reported.name", "region"),
        ("ancestors.zone.reported.name", "zone"),
    ]
    dot_re = re.compile("[.]")

    @property
    def name(self) -> str:
        return "list"

    def info(self) -> str:
        return "Transform incoming objects as string with defined properties."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        def adjust_path(p: List[str]) -> List[str]:
            root = p[0]
            if root in Section.all or root == "id" or root == "kinds":
                return p
            else:
                return [Section.reported, *p]

        def to_str(name: str, elem: JsonElement) -> str:
            if isinstance(elem, dict):
                return ", ".join(f"{to_str(k, v)}" for k, v in sorted(elem.items()))
            elif isinstance(elem, list):
                return f"{name}=[" + ", ".join(str(e) for e in elem) + "]"
            else:
                return f"{name}={elem}"

        props: List[Tuple[List[str], str]] = []
        for prop, as_name in list_arg_parse.parse(arg) if arg else self.default_properties_to_show:
            path = adjust_path(self.dot_re.split(prop))
            as_name = path[-1] if prop == as_name or as_name is None else as_name
            props.append((path, as_name))

        def fmt_json(elem: Json) -> JsonElement:
            if is_node(elem):
                result = ""
                first = True
                for prop_path, name in props:
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
    Usage: jobs

    List all jobs in the system.

    Example
        jobs   # Could show
            [ { "id": "d20288f0", "command": "echo hi!", "trigger": { "cron_expression": "* * * * *" } ]

    See: add_job, delete_job
    }
    """

    @property
    def name(self) -> str:
        return "jobs"

    def info(self) -> str:
        return "List all jobs in the system."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        async def jobs() -> Tuple[int, AsyncIterator[JsonElement]]:
            listed = await self.dependencies.job_handler.list_jobs()

            async def iterate() -> AsyncIterator[JsonElement]:
                for job in listed:
                    wait = {"wait": {"message_type": job.wait[0].message_type}} if job.wait else {}
                    yield {"id": job.id, "trigger": to_js(job.trigger), "command": job.command.command, **wait}

            return len(listed), iterate()

        return CLISource(jobs)


class AddJobCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: add_job [<cron_expression>] [<event_name> :] <command>

    Add a job which either runs
        - scheduled via defined cron expression
        - event triggered via defined name of event to trigger this job
        - combined scheduled + event trigger once the schedule triggers this job,
          it is possible to wait for an incoming event, before the command is executed.

    The result of `add_job` will be a job identifier, which identifies this job uniquely and can be used to
    delete the job again.
    Note: the command is not allowed to run longer than 1 hour. It is killed in such a case.
    Note: if an event to wait for is specified, it has to arrive in 24 hours, otherwise the job is aborted.

    Parameter:
        cron_expression [optional]:  defines the recurrent schedule in crontab format.
        event_name [optional]:       if defined, the command waits for the specified event _after_ the next scheduled
                                     time has been reached. No waiting happens, if this parameter is not defined.
        command [mandatory]:         the CLI command that will be executed, when the job is triggered.
                                     Note: multiple commands can be defined by separating them via escaped semicolon.


    Example:
        # print hello world every minute to the console
        add_job * * * * * echo hello world
        # every morning at 4: wait for message of type collect_done and print a message
        add_job 0 4 * * * collect_done: match is instance("compute_instance") and cores>4 \\| format id
        # wait for message of type collect_done and print a message
        add_job collect_done echo hello world

    See: delete_job, jobs
    """

    @property
    def name(self) -> str:
        return "add_job"

    def info(self) -> str:
        return "Add job to the system."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        async def add_job() -> AsyncIterator[str]:
            if not arg:
                raise AttributeError("No parameters provided for add_job!")
            job = await self.dependencies.job_handler.parse_job_line("cli", arg, ctx.env)
            await self.dependencies.job_handler.add_job(job)
            yield f"Job {job.id} added."

        return CLISource.single(add_job)


class DeleteJobCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: delete_job [job_id]

    Delete a job by a given job identifier.
    Note: a job with an unknown id can not be deleted. It will not raise any error, but show a different message.


    Parameter:
        job_id [mandatory]: defines the identifier of the job to be deleted.

    Example:
        delete_job 123  # will delete the job with id 123

    See: add_job, jobs
    """

    @property
    def name(self) -> str:
        return "delete_job"

    def info(self) -> str:
        return "Remove job from the system."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        async def delete_job() -> AsyncIterator[str]:
            if not arg:
                raise AttributeError("No parameters provided for delete_job!")
            job = await self.dependencies.job_handler.delete_job(arg)
            yield f"Job {arg} deleted." if job else f"No job with this id: {arg}"

        return CLISource.single(delete_job)


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
        "cloud": ["reported", "cloud", "id"],
        "account": ["reported", "account", "id"],
        "region": ["reported", "region", "id"],
        "zone": ["reported", "zone", "id"],
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
    Usage: tag update [--nowait] [tag_name new_value]
           tag delete [--nowait] [tag_name]

    This command can be used to update or delete a specific tag.
    Tags have a name and value - both name and value are strings.

    When this command is issued, the change is done on the cloud resource via the cloud specific provider.
    In case of success, the resulting change is performed in the related cloud.
    The change in the graph data itself might take up to the next collect run.

    The command would wait for th worker to report the result back synchronously.
    Once the cli command returns, also the tag update/delete is finished.
    If the command should not wait for the result, the action can be performed in background via the --nowait flag.

    There are 2 modes of operations:
    - The incoming elements are defined by a query:
      Example: `match x>2 | tag delete foo`
      All elements that match the query are updated.
    - The incoming elements are defined by a string or string array:
      Example: `echo id_of_node_23` | tag delete foo`
               `json ["id1", "id2", "id3"] | tag delete foo`
      In this case the related strings are interpreted as id and loaded from the graph.


    Parameter:
        command_name [mandatory]: is either update or delete
        tag_name [mandatory]: the name of the tag to change
        tag_value: in case of update: the new value of the tag_name
        --nowait if this flag is defined, the cli will send the tag command to the worker
                 and will not wait for the task to finish.


    Example:
        match x>2 | tag delete foo  # will result in [ { "id1": "success" }, { "id2": "success" } .. {} ]
        echo "id1" | tag delete foo  # will result in [ { "id1": "success" } ]
        json ["id1", "id2"] | tag delete foo  # will result in [ { "id1": "success" }, { "id2": "success" } ]


    Environment Variables:
        graph: the name of the graph to operate on.
    """

    @property
    def name(self) -> str:
        return "tag"

    def info(self) -> str:
        return "Update a tag with provided value or delete a tag"

    def timeout(self) -> timedelta:
        return timedelta(seconds=30)

    def load_by_id_merged(self, model: Model, in_stream: Stream, **env: str) -> Stream:
        async def load_element(items: List[JsonElement]) -> AsyncIterator[JsonElement]:
            # collect ids either from json dict or string
            ids: List[str] = [i["id"] if is_node(i) else i for i in items]  # type: ignore
            # one query to load all items that match given ids (max 1000 as defined in chunk size)
            query = Query.by(P("_key").is_in(ids)).merge_preamble({"merge_with_ancestors": "cloud,account,region,zone"})
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

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIFlow:
        parts = re.split(r"\s+", arg if arg else "")
        pl = len(parts)
        if pl >= 2 and parts[0] == "delete":
            nowait, tag = (parts[1] == "--nowait", parts[2]) if pl == 3 else (False, parts[1])
            fn: Callable[[Json], Tuple[str, Dict[str, str], Json]] = lambda item: (
                "tag",
                self.carz_from_node(item),
                {"delete": [tag], "node": item},
            )  # noqa: E731
        elif pl >= 3 and parts[0] == "update":
            nowait, tag, vin = (parts[1] == "--nowait", parts[2], parts[3]) if pl == 4 else (False, parts[1], parts[2])
            value = double_quoted_or_simple_string_dp.parse(vin)
            fn = lambda item: (  # noqa: E731
                "tag",
                self.carz_from_node(item),
                {"update": {tag: value}, "node": item},
            )
        else:
            raise AttributeError("Expect update tag_key tag_value or delete tag_key")

        def setup_stream(in_stream: Stream) -> Stream:
            def with_dependencies(model: Model) -> Stream:
                load = self.load_by_id_merged(model, in_stream, **ctx.env)
                result_handler = self.handle_result(model, **ctx.env)
                return self.send_to_queue_stream(stream.map(load, fn), result_handler, not nowait)

            # dependencies are not resolved directly (no async function is allowed here)
            dependencies = stream.call(self.dependencies.model_handler.load_model)
            return stream.flatmap(dependencies, with_dependencies)

        return CLIFlow(setup_stream)


class TasksCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: tasks

    List all running tasks.

    Example:
        tasks
        # Could return this output
         [
          { "id": "123", "descriptor": { "id": "231", "name": "example-job" }, "started_at": "2021-09-17T12:07:39Z" }
         ]

    """

    @property
    def name(self) -> str:
        return "tasks"

    def info(self) -> str:
        return "Lists all currently running tasks."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        async def tasks_source() -> Tuple[int, Stream]:
            tasks = await self.dependencies.job_handler.running_tasks()
            return len(tasks), stream.iterate(
                {
                    "id": t.id,
                    "started_at": to_json(t.task_started_at),
                    "descriptor": {"id": t.descriptor.id, "name": t.descriptor.name},
                }
                for t in tasks
            )

        return CLISource(tasks_source)


class StartTaskCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: start_task <name of task>

    Start a task with given task descriptor id.

    The configured surpass behaviour of a task definition defines, if multiple tasks of the same task definition
    are allowed to run in parallel.
    In case parallel tasks are forbidden a new task can not be started.
    If a task could be started or not is returned as result message of this command.

    Parameter:
        task_name [mandatory]:  The name of the related task definition.

    Example:
        start_task example_task # Will return Task 6d96f5dc has been started

    See: add_job, delete_job, jobs
    """

    @property
    def name(self) -> str:
        return "start_task"

    def info(self) -> str:
        return "Start a task with the given name."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
        async def start_task() -> AsyncIterator[str]:
            if not arg:
                raise CLIParseError("Name of task is not provided")

            task = await self.dependencies.job_handler.start_task_by_descriptor_id(arg)
            yield f"Task {task.id} has been started" if task else "Task can not be started."

        return CLISource.single(start_task)


class FileCommand(CLICommand, InternalPart):
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
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
    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLISource:
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
    Usage: system backup create [name]
           system backup restore <path>

    system backup create [name]:

    Create a system backup for the complete database, which contains:
    - backup of all graph data
    - backup of all model data
    - backup of all persisted jobs/tasks data
    - backup of all subscribers data
    - backup of all configuration data

    This backup can be restored via system backup restore.
    Since this command creates a complete backup, it can be restored to an empty database.

    Note: a backup acquires a global write lock. This basically means, that *no write* can be
          performed, while the backup is created!
    Note: the backup is not encrypted.

    Parameter:
        name [optional] - name of the backup file.
                          If no name is provided the name will be `backup_yyyyMMdd_hmm`.
                          Example: backup_20211022_1028

    Example:
        system backup create                  # this will create a backup written to backup_{time_now}.
        system backup create backup bck_1234  # this will create a backup written to bck_1234.


    system backup restore:

    Restores the complete database state from a previously generated backup.
    All existing data in the database will be overwritten.
    This command will not wipe any existing data: if there are collections in the database, that are not included
    in the backup, it will not be deleted by this process.
    In order to restore exactly the same state as in the backup, you should start from an empty database.

    Note: a backup acquires a global write lock. This basically means, that *no write* can be
          performed, while the backup is restored!
    Note: After the restore process is done, the ckcore process will stop. It should be restarted by
          the process supervisor automatically. The restart is necessary to take effect from the changed
          underlying data source.

    path [mandatory] - path to the local backup file.

    Example:
        system backup restore /path/to/backup    # this will restore the backup from the given local path.

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
                "--progress", "false",           # do not show progress
                "--threads", "8",                # default is 2
                "--log.level", "error",          # only print error messages
                "--output-directory", temp_dir,  # directory to write to
                "--overwrite", "true",           # required for existing directories
                "--server.endpoint", args.graphdb_server.replace("http", "http+tcp"),
                "--server.authentication", "false" if args.graphdb_no_ssl_verify else "true",
                "--server.database", args.graphdb_database,
                "--server.username", args.graphdb_username,
                "--server.password", args.graphdb_password,
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
                "--progress", "false",           # do not show progress
                "--threads", "8",                # default is 2
                "--log.level", "error",          # only print error messages
                "--input-directory", temp_dir,   # directory to write to
                "--overwrite", "true",           # required for existing db collections
                "--server.endpoint", args.graphdb_server.replace("http", "http+tcp"),
                "--server.authentication", "false" if args.graphdb_no_ssl_verify else "true",
                "--server.database", args.graphdb_database,
                "--server.username", args.graphdb_username,
                "--server.password", args.graphdb_password,
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

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
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
        else:
            raise CLIParseError(f"system: Can not parse {arg}")


class WriteCommand(CLICommand):
    """
    Usage: write [--format <format>] <file-name>

    Writes the result of this command to a file with given name.

    The format can be defined via the format flag. Following formats are available:
    - json [default]: the result will be an array of json objects.
    - ndjson (newline delimited json): every line in the output is a json document representing one node.
    - yaml: every node is converted to yaml. The entries are delimited by the yaml object delimiter (---).
    - text: all nodes are rendered as plain text.
    - cytoscape: https://js.cytoscape.org/#notation/elements-json.
    - graphml: render the elements in graphml http://graphml.graphdrawing.org.
    - dot: render the elements in graphviz dot format: https://graphviz.org/doc/info/lang.html

    If no format is defined, the format is guessed by the file name extension.
    Example: test.json -> json, test.yml -> yaml, test.graphml -> graphml, test.txt -> text

    Parameter:
        file-name [mandatory]:  The name of the file to write to.
        format [optional]: Defines the format of the content of the file.
                           One of: json, ndjson, yaml, text, cytoscape, graphml, dot

    Example:
        query all limit 3 | write out.json # Write 3 nodes to the file out.json in json format.
        query all limit 3 | list | write --format text out.txt # Write 3 nodes to the file out.txt in text format.
    """

    @property
    def name(self) -> str:
        return "write"

    def info(self) -> str:
        return "Writes the incoming stream of data to a file in the defined format."

    formats = {
        "ndjson": respond_ndjson,
        "json": respond_json,
        "text": respond_text,
        "yaml": respond_yaml,
        "cytoscape": respond_cytoscape,
        "graphml": respond_graphml,
        "dot": respond_dot,
    }

    mediatype_to_format = {**{f: f for f in formats}, "yml": "yaml", "js": "json", "txt": "text"}

    @staticmethod
    async def write_result_to_file(
        in_stream: Stream,
        file_name: str,
        renderer: Callable[[AsyncIterator[Json]], AsyncGenerator[str, None]],
    ) -> AsyncIterator[str]:
        temp_dir: str = tempfile.mkdtemp()
        path = os.path.join(temp_dir, file_name)
        try:
            async with aiofiles.open(path, "w") as f:
                async with in_stream.stream() as streamer:
                    async for out in renderer(streamer):
                        await f.write(out)
            yield path
        finally:
            shutil.rmtree(temp_dir)

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
        parser = NoExitArgumentParser()
        parser.add_argument("--format", dest="format")
        parser.add_argument("filename")
        parsed = parser.parse_args(arg.split() if arg else [])
        if parsed.format and parsed.format not in self.formats:
            raise AttributeError(f'Format not available: {parsed.format}! Available: {", ".join(self.formats)}')
        filename: str = parsed.filename
        filename_extension = filename.rsplit(".", 1)
        fmt_name = parsed.format
        # if format is not defined, try to guess it from the file name extension: test.json -> json
        if not fmt_name and len(filename_extension) == 2:
            fmt_name = self.mediatype_to_format.get(filename_extension[1])
        # if it is not defined and can not be guessed, use json as default.
        fmt = self.formats[fmt_name if fmt_name else "json"]

        def write_file(in_stream: Stream) -> AsyncIterator[str]:
            return self.write_result_to_file(in_stream, parsed.filename, fmt)

        return CLIFlow(write_file, MediaType.FilePath)


class TemplatesCommand(CLICommand, PreserveOutputFormat):
    """
    Usage: templates
           templates <name_of_template>
           templates add <name_of_template> <query_template>
           templates update <name_of_template> <query_template>
           templates delete <name_of_template>
           templates test key1=value1, key2=value2, ..., keyN=valueN <template_to_expand>


    templates: get the list of all templates
    templates <name>: get the current definition of the template defined by given template name
    templates add <name> <template>: add a query template to the query template library under given name.
    templates update <name> <template>: update a query template in the query template library.
    templates delete <name>: delete the query template with given name.
    templates test k=v <template_to_expand>: test the defined template.

    Placeholders are defined in 2 double curly braces {{placeholder}}
    and get replaced by the provided placeholder value during render time.
    The name of the placeholder can be any valid alphanumeric string.
    The template 'is({{kind}})' with expand parameters kind=volume becomes
    'is(volume)' during expand time.

    Parameter:
        name_of_template:  The name of the query template.
        query_template:  The query with template placeholders.
        key=value: any number of key/value pairs separated by comma

    Example:
        $> templates test kind=volume is({{kind}})
        is(volume)
        $> templates add filter_kind is({{kind}})
        Template filter_kind added to the query library.
        is({{kind}})
        > templates
        filter_kind: is({{kind}})
        $> templates filter_kind
        is({{kind}})
        $> templates delete filter_kind
        Template filter_kind deleted from the query library.
    """

    @property
    def name(self) -> str:
        return "templates"

    def info(self) -> str:
        return "Access the query template library."

    def parse(self, arg: Optional[str] = None, ctx: CLIContext = EmptyContext) -> CLIAction:
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
            # try to render the template with dummy values and see if the query can be parsed
            try:
                rendered_query = self.dependencies.template_expander.render(template_query, defaultdict(lambda: True))
                parse_query(rendered_query)
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


def all_commands(d: CLIDependencies) -> List[CLICommand]:
    commands = [
        AddJobCommand(d),
        AggregatePart(d),
        AggregateToCountCommand(d),
        AncestorPart(d),
        ChunkCommand(d),
        CleanCommand(d),
        CountCommand(d),
        DeleteJobCommand(d),
        DescendantPart(d),
        DesiredPart(d),
        DumpCommand(d),
        EchoCommand(d),
        EnvCommand(d),
        ExecuteQueryCommand(d),
        FlattenCommand(d),
        FormatCommand(d),
        HeadCommand(d),
        JobsCommand(d),
        JqCommand(d),
        JsonCommand(d),
        KindCommand(d),
        ListCommand(d),
        TemplatesCommand(d),
        MergeAncestorsPart(d),
        MetadataPart(d),
        PredecessorPart(d),
        ProtectCommand(d),
        QueryAllPart(d),
        ReportedPart(d),
        SetDesiredCommand(d),
        SetMetadataCommand(d),
        SleepCommand(d),
        StartTaskCommand(d),
        SuccessorPart(d),
        SystemCommand(d),
        TagCommand(d),
        TailCommand(d),
        TasksCommand(d),
        UniqCommand(d),
        WriteCommand(d),
    ]
    # commands that are only available when the system is started in debug mode
    if d.args.debug:
        commands.extend([FileCommand(d), UploadCommand(d)])

    return commands


def aliases() -> Dict[str, str]:
    # command alias -> command name
    return {"match": "reported", "start_workflow": "start_task", "start_job": "start_task"}
