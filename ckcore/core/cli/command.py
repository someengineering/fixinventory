import asyncio
import json
import logging
import re
from abc import abstractmethod, ABC
from datetime import timedelta
from functools import partial
from typing import Optional, Any, AsyncGenerator, Hashable, Iterable, Union, Callable, Awaitable, cast

import jq
from aiostream import stream
from aiostream.aiter_utils import is_async_iterable
from aiostream.core import Stream
from parsy import Parser, string
from typing import Dict, List, Tuple


from core.cli.cli import (
    CLISource,
    CLISink,
    Sink,
    Source,
    CLICommand,
    Flow,
    CLIDependencies,
    CLIPart,
    key_values_parser,
    ReportedPart,
    DesiredPart,
    MetadataPart,
    Predecessor,
    Successor,
    Ancestor,
    Descendant,
    QueryPart,
    AggregatePart,
    MergeAncestorsPart,
    Result,
    InternalPart,
    QueryAllPart,
    strip_quotes,
    CountCommand,
    HeadCommand,
    TailCommand,
)
from core.db.model import QueryModel
from core.error import CLIParseError, ClientError
from core.model.graph_access import Section
from core.model.model import Model, Kind, ComplexKind, DictionaryKind, SimpleKind
from core.model.resolve_in_graph import NodePath
from core.model.typed_model import to_js
from core.parse_util import double_quoted_or_simple_string_dp, space_dp, make_parser, variable_dp, literal_dp, comma_p
from core.query.model import Query, P
from core.query.query_parser import parse_query
from core.types import Json, JsonElement
from core.util import AccessJson, uuid_str, value_in_path_get, value_in_path
from core.worker_task_queue import WorkerTask

log = logging.getLogger(__name__)


# check if a is a json node element
def is_node(a: Any) -> bool:
    return "id" in a and Section.reported in a if isinstance(a, dict) else False


class EchoSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        return stream.just(strip_quotes(arg if arg else ""))


class JsonSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
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
        return stream.iterate(elements)


class SleepSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        async def sleep(secs: float) -> AsyncGenerator[JsonElement, None]:
            for _ in range(0, 1):
                await asyncio.sleep(secs)
                yield ""

        if not arg:
            raise AttributeError("Sleep needs an argument!")
        try:
            sleep_time = float(arg)
            return sleep(sleep_time)
        except Exception as ex:
            raise AttributeError("Sleep needs the time in seconds as arg.") from ex


class AggregateToCount(CLICommand, InternalPart):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        name_path = ["group", "name"]
        count_path = ["count"]

        async def to_count(in_stream: AsyncGenerator[JsonElement, None]) -> AsyncGenerator[JsonElement, None]:
            null_value = 0
            total = 0
            async for elem in in_stream:
                name = value_in_path(elem, name_path)
                count = value_in_path_get(elem, count_path, 0)
                if name is None:
                    null_value = count
                else:
                    total += count
                    yield f"{name}: {count}"
            yield f"total matched: {total}"
            yield f"total unmatched: {null_value}"

        return to_count


class ExecuteQuerySource(CLISource, InternalPart):
    """
    Usage: execute_query <query>

    A query is performed against the graph database and all resulting elements will be emitted.
    To learn more about the query, visit todo: link is missing.

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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        # db name and section is coming from the env
        graph_name = env["graph"]
        if not arg:
            raise CLIParseError("query command needs a query to execute, but nothing was given!")
        query = parse_query(arg)
        model = await self.dependencies.model_handler.load_model()
        db = self.dependencies.db_access.get_graph_db(graph_name)
        query_model = QueryModel(query, model)
        db.to_query(query_model)  # only here to validate the query itself (can throw)
        return db.query_aggregation(query_model) if query.aggregate else db.query_list(query_model)


class EnvSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        return stream.just(env)


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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        size = int(arg) if arg else 100
        return lambda in_stream: stream.chunks(in_stream, size)


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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        def iterate(it: Any) -> Stream:
            return stream.iterate(it) if is_async_iterable(it) or isinstance(it, Iterable) else stream.just(it)

        return lambda in_stream: stream.flatmap(in_stream, iterate)


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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
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

        return lambda in_stream: stream.filter(in_stream, has_not_seen)


class JqCommand(CLICommand):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        if not arg:
            raise AttributeError("jq requires an argument to be parsed")

        compiled = jq.compile(strip_quotes(arg))

        def process(in_json: Json) -> Json:
            out = compiled.input(in_json).all()
            result = out[0] if len(out) == 1 else out
            return cast(Json, result)

        return lambda in_stream: stream.map(in_stream, process)


class KindSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
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
                props = to_js(sorted(kind.all_props(), key=lambda k: k.name))
                return {"name": kind.fqn, "bases": list(kind.kind_hierarchy()), "properties": props}
            else:
                return {"name": kind.fqn}

        def with_dependencies(model: Model) -> Stream:
            if show_kind:
                result = kind_to_js(model[show_kind]) if show_kind in model else f"No kind with this name: {show_kind}"
            elif show_path:
                result = kind_to_js(model.kind_by_path(Section.without_section(show_path)))
            else:
                result = sorted(list(model.kinds.keys()))

            return stream.just(result)

        dependencies = stream.call(self.dependencies.model_handler.load_model)
        return stream.flatmap(dependencies, with_dependencies)


class SetDesiredStateBase(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        func = partial(self.set_desired, arg, env["graph"], self.patch(arg, **env))
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)

    async def set_desired(
        self, arg: Optional[str], graph_name: str, patch: Json, items: List[Json]
    ) -> AsyncGenerator[Json, None]:
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
    ) -> AsyncGenerator[Json, None]:
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        func = partial(self.set_metadata, env["graph"], self.patch(arg, **env))
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)

    async def set_metadata(self, graph_name: str, patch: Json, items: List[Json]) -> AsyncGenerator[JsonElement, None]:
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


class FormatCommand(CLICommand):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        def fmt(elem: Any) -> str:
            # wrap the object to account for non existent values.
            # if a format value is not existent, render is as null (json conform).
            wrapped = AccessJson(elem, "null") if isinstance(elem, dict) else elem
            return arg.format_map(wrapped)  # type: ignore

        return lambda in_stream: in_stream if arg is None else stream.map(in_stream, fmt)


@make_parser
def list_single_arg_parse() -> Parser:
    name = yield variable_dp
    as_name = yield (space_dp >> string("as") >> space_dp >> literal_dp).optional()
    return name, as_name


list_arg_parse = list_single_arg_parse.sep_by(comma_p, min=1)


class ListCommand(CLICommand):
    """
    Usage: list [props_to_show]

    This command creates a string from the json input based on the defined properties to show.

    If no prop is defined a predefined list of properties will be shown:
        - reported.kind
        - reported.id
        - reported.name
        - reported.ctime
        - metadata.ancestors.cloud.name as cloud
        - metadata.ancestors.account.name as account
        - metadata.ancestors.region.name as region
        - metadata.ancestors.zone.name as zone

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
        ("reported.ctime", "ctime"),
        ("metadata.ancestors.cloud.name", "cloud"),
        ("metadata.ancestors.account.name", "account"),
        ("metadata.ancestors.region.name", "region"),
        ("metadata.ancestors.zone.name", "zone"),
    ]
    dot_re = re.compile("[.]")

    @property
    def name(self) -> str:
        return "list"

    def info(self) -> str:
        return "Transform incoming objects as string with defined properties."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
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

        def fmt(elem: JsonElement) -> str:
            result = ""
            first = True
            for path, name in props:
                value = value_in_path(elem, path)
                if value is not None:
                    delim = "" if first else ", "
                    result += f"{delim}{to_str(name, value)}"
                    first = False
            return result

        return lambda in_stream: stream.map(in_stream, fmt)


class JobsSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        for job in await self.dependencies.job_handler.list_jobs():
            wait = {"wait": {"message_type": job.wait[0].message_type}} if job.wait else {}
            yield {"id": job.id, "trigger": to_js(job.trigger), "command": job.command.command, **wait}


class AddJobSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        if not arg:
            raise AttributeError("No parameters provided for add_job!")
        job = await self.dependencies.job_handler.parse_job_line("cli", arg)
        await self.dependencies.job_handler.add_job(job)
        yield f"Job {job.id} added."


class DeleteJobSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        if not arg:
            raise AttributeError("No parameters provided for delete_job!")
        job = await self.dependencies.job_handler.delete_job(arg)
        yield f"Job {arg} deleted." if job else f"No job with this id: {arg}"


class SendWorkerTaskCommand(CLICommand, ABC):
    # Abstract base for all commands that send task to the work queue

    # this method expects a stream of Tuple[str, Dict[str, str], Json]
    def send_to_queue_stream(self, in_stream: Stream) -> Stream:
        async def send_to_queue(task_name: str, task_args: Dict[str, str], data: Json) -> Any:
            future = asyncio.get_event_loop().create_future()
            task = WorkerTask(uuid_str(), task_name, task_args, data, future, self.timeout())
            # enqueue this task
            await self.dependencies.worker_task_queue.add_task(task)
            # wait for the task result
            try:
                return task, await future
            except Exception as ex:
                return task, ex

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
    Usage: tag update [tag_name new_value]
           tag delete [tag_name]

    This command can be used to update or delete a specific tag.
    Tags have a name and value - both name and value are strings.

    When this command is issued, the change is done on the cloud resource via the cloud specific provider.
    In case of success, the resulting change is performed in the related cloud.
    The change in the graph data itself might take up to the next collect run.

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
        async def load_element(items: List[JsonElement]) -> AsyncGenerator[Json, None]:
            # collect ids either from json dict or string
            ids: List[str] = [i["id"] if is_node(i) else i for i in items]  # type: ignore
            # one query to load all items that match given ids (max 1000 as defined in chunk size)
            query = Query.by(P("_key").is_in(ids)).merge_preamble({"merge_with_ancestors": "cloud,account,region,zone"})
            query_model = QueryModel(query, model)
            async for a in self.dependencies.db_access.get_graph_db(env["graph"]).query_list(query_model):
                yield a

        return stream.flatmap(stream.chunks(in_stream, 1000), load_element)

    def handle_result(
        self, model: Model, **env: str
    ) -> Callable[[WorkerTask, Union[Json, Exception]], Awaitable[Json]]:
        async def to_result(task: WorkerTask, result: Union[Json, Exception]) -> Json:
            nid = value_in_path(task.data, ["node", "id"])
            if isinstance(result, Exception):
                return {"error": str(result), "id": nid}
            elif is_node(result):
                db = self.dependencies.db_access.get_graph_db(env["graph"])
                try:
                    updated: Json = await db.update_node(model, result["id"], result, None)
                    return updated
                except ClientError as ex:
                    # if the change could not be reflected in database, show success
                    log.warning(
                        f"Tag update not reflected in db. Wait until next collector run. Reason: {str(ex)}", exc_info=ex
                    )
                    return result
            else:
                log.warning(
                    f"Result from tag worker is not a node. Will not update the internal state. {json.dumps(result)}"
                )
                return result

        return to_result

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        parts = re.split(r"\s+", arg if arg else "")
        pl = len(parts)
        if pl == 2 and parts[0] == "delete":
            tag = parts[1]
            fn: Callable[[Json], Tuple[str, Dict[str, str], Json]] = lambda item: (
                "tag",
                self.carz_from_node(item),
                {"delete": [tag], "node": item},
            )  # noqa: E731
        elif pl == 3 and parts[0] == "update":
            tag = parts[1]
            value = double_quoted_or_simple_string_dp.parse(parts[2])
            fn = lambda item: (  # noqa: E731
                "tag",
                self.carz_from_node(item),
                {"update": {tag: value}, "node": item},
            )
        else:
            raise AttributeError("Expect update tag_key tag_value or delete tag_key")

        def setup_stream(in_stream: Stream) -> Stream:
            def with_dependencies(model: Model) -> Stream:
                load = self.load_by_id_merged(model, in_stream, **env)
                to_queue = self.send_to_queue_stream(stream.map(load, fn))
                # return stream.starmap(to_queue, partial(self.handle_result, model, env=env))
                return stream.starmap(to_queue, self.handle_result(model, **env))

            # dependencies are not resolved directly (no async function is allowed here)
            dependencies = stream.call(self.dependencies.model_handler.load_model)
            return stream.flatmap(dependencies, with_dependencies)

        return setup_stream


class TasksSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        tasks = await self.dependencies.job_handler.running_tasks()
        return stream.iterate(
            {
                "id": t.id,
                "started_at": to_js(t.task_started_at),
                "descriptor": {"id": t.descriptor.id, "name": t.descriptor.name},
            }
            for t in tasks
        )


class StartTaskSource(CLISource):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        if not arg:
            raise CLIParseError("Name of task is not provided")

        task = await self.dependencies.job_handler.start_task_by_descriptor_id(arg)
        yield f"Task {task.id} has been started" if task else "Task can not be started."


class ListSink(CLISink):
    @property
    def name(self) -> str:
        return "out"

    def info(self) -> str:
        return "Creates a list of results."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Sink[List[JsonElement]]:
        return stream.list  # type: ignore


def all_sources(d: CLIDependencies) -> List[CLISource]:
    return [
        AddJobSource(d),
        DeleteJobSource(d),
        EchoSource(d),
        EnvSource(d),
        ExecuteQuerySource(d),
        JobsSource(d),
        JsonSource(d),
        KindSource(d),
        SleepSource(d),
        StartTaskSource(d),
        TasksSource(d),
    ]


def all_sinks(d: CLIDependencies) -> List[CLISink]:
    return [ListSink(d)]


def all_commands(d: CLIDependencies) -> List[CLICommand]:
    return [
        AggregateToCount(d),
        ChunkCommand(d),
        CleanCommand(d),
        CountCommand(d),
        FlattenCommand(d),
        FormatCommand(d),
        HeadCommand(d),
        JqCommand(d),
        ListCommand(d),
        ProtectCommand(d),
        SetDesiredCommand(d),
        SetMetadataCommand(d),
        TagCommand(d),
        TailCommand(d),
        UniqCommand(d),
    ]


def all_query_parts(d: CLIDependencies) -> List[QueryPart]:
    return [
        QueryAllPart(d),
        ReportedPart(d),
        DesiredPart(d),
        MetadataPart(d),
        Predecessor(d),
        Successor(d),
        Ancestor(d),
        Descendant(d),
        AggregatePart(d),
        MergeAncestorsPart(d),
    ]


def all_parts(d: CLIDependencies) -> List[CLIPart]:
    result: List[CLIPart] = []
    result.extend(all_query_parts(d))
    result.extend(all_sources(d))
    result.extend(all_commands(d))
    result.extend(all_sinks(d))
    return result


def aliases() -> Dict[str, str]:
    # command alias -> command name
    return {"match": "reported", "start_workflow": "start_task", "start_job": "start_task"}
