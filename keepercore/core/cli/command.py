import asyncio
import json
from abc import abstractmethod, ABC
from functools import partial
from typing import List, Optional, Any, Tuple, AsyncGenerator, Hashable, Iterable

from aiostream import stream
from aiostream.aiter_utils import is_async_iterable
from aiostream.core import Stream

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
)
from core.db.model import QueryModel
from core.error import CLIParseError
from core.query.query_parser import parse_query
from core.types import Json, JsonElement
from core.util import AccessJson


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
        arg_str = arg if arg else ""
        js_str = arg_str if arg_str.strip() else '""'
        try:
            js = json.loads(js_str)
        except Exception:
            js = js_str
        if isinstance(js, list):
            elements = js
        elif isinstance(js, (str, int, float, bool, dict)):
            elements = [js]
        else:
            raise AttributeError(f"json does not understand {arg}.")
        return stream.iterate(elements)  # type: ignore


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
        js = json.loads(arg)
        if isinstance(js, list):
            elements = js
        elif isinstance(js, (str, int, float, bool, dict)):
            elements = [js]
        else:
            raise AttributeError(f"json does not understand {arg}.")
        return stream.iterate(elements)  # type: ignore


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


class MatchSource(CLISource):
    """
    Usage: match <query>

    A query is performed against the graph database and all resulting elements will be emitted.
    To learn more about the query, visit todo: link is missing.

    Example:
        match isinstance("ec2") and (cpu>12 or cpu<3)  # will result in all matching elements [{..}, {..}, .. {..}]

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
        section [optional, defaults to "reported"]: on which section the query is performed
    """

    @property
    def name(self) -> str:
        return "match"

    def info(self) -> str:
        return "Query the database and pass the results to the output stream."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        # db name and section is coming from the env
        graph_name = env["graph"]
        query_section = env.get("section", "reported")
        if not arg:
            raise CLIParseError("match command needs a query to execute, but nothing was given!")
        query = parse_query(arg)
        model = await self.dependencies.model_handler.load_model()
        db = self.dependencies.db_access.get_graph_db(graph_name)
        query_model = QueryModel(query, model, query_section)
        db.to_query(query_model)  # only here to validate the query itself (can throw)
        return db.query_list(query_model)


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
        return stream.just(env)  # type: ignore


class CountCommand(CLICommand):
    """
    Usage: count [arg]

    In case no arg is given: it counts the number of instances provided to count.
    In case of arg: it pulls the property with the name of arg, translates it to a number and sums it.

    Parameter:
        arg [optional]: Instead of counting the instances, sum the property of all objects with this name.

    Example:
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count    # will result in [{ "matched": 3, "not_matched": 0 }]
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count a  # will result in [{ "matched": 6, "not_matched": 0 }]
        json [{"a": 1}, {"a": 2}, {"a": 3}] | count b  # will result in [{ "matched": 0, "not_matched": 3 }]
    """

    @property
    def name(self) -> str:
        return "count"

    def info(self) -> str:
        return "Count incoming elements or sum defined property."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        def inc_prop(o: Any) -> Tuple[int, int]:
            def prop_value() -> Tuple[int, int]:
                try:
                    return int(o[arg]), 0
                except Exception:
                    return 0, 1

            return prop_value() if arg in o else (0, 1)

        def inc_identity(_: Any) -> Tuple[int, int]:
            return 1, 0

        fn = inc_prop if arg else inc_identity

        async def count_in_stream(content: Stream) -> AsyncGenerator[JsonElement, None]:
            counter = 0
            no_match = 0

            async with content.stream() as in_stream:
                async for element in in_stream:
                    cnt, not_matched = fn(element)
                    counter += cnt
                    no_match += not_matched
            yield {"matched": counter, "not_matched": no_match}

        # noinspection PyTypeChecker
        return count_in_stream


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
        return lambda in_stream: stream.chunks(in_stream, size)  # type: ignore


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

        return lambda in_stream: stream.flatmap(in_stream, iterate)  # type: ignore


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
        return "Remove all duplicated objects from the stream"

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

        return lambda in_stream: stream.filter(in_stream, has_not_seen)  # type: ignore


class SetDesiredState(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        func = partial(self.set_desired, env["graph"], self.patch(arg, **env))
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)  # type: ignore

    async def set_desired(self, graph_name: str, patch: Json, items: List[Json]) -> AsyncGenerator[JsonElement, None]:
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = []
        for item in items:
            if "id" in item:
                node_ids.append(item["id"])
            elif isinstance(item, str):
                node_ids.append(item)
        async for update in db.update_nodes_desired(patch, node_ids, with_system_props=True):
            yield update


class DesireCommand(SetDesiredState):
    """
    Usage: desire [property]=[value]

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
        match isinstance("ec2") | desire a=b b="c" num=2   # will result in
            [
                { "id": "abc" "desired": { "a": "b", "b: "c" "num": 2, "other": "abc" }, "reported": { .. } },
                .
                .
                { "id": "xyz" "desired": { "a": "b", "b: "c" "num": 2 }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | desire a=b
            [
                { "id": "id1", "desired": { "a": b }, "reported": { .. } },
                { "id": "id2", "desired": { "a": b }, "reported": { .. } },
            ]
        json ["id1", "id2"] | desire a=b
            [
                { "id": "id1", "desired": { "a": b }, "reported": { .. } },
                { "id": "id2", "desired": { "a": b }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "desire"

    def info(self) -> str:
        return "Allows to set arbitrary properties as desired for all incoming database objects."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class MarkDeleteCommand(SetDesiredState):
    """
    Usage: mark_delete

    Mark incoming objects for deletion.
    All objects marked as such will be finally deleted in the next delete run.

    This command assumes, that all incoming elements are either objects coming from a query or are object ids.
    All objects coming from a query will have a property `id`.

    The result of this command will emit the complete object with desired and reported state:
    { "id": "..", "desired": { .. }, "reported": { .. } }

    Example:
        match isinstance("ec2") and atime<"-2d" | mark_delete
            [
                { "id": "abc" "desired": { "delete": true }, "reported": { .. } },
                .
                .
                { "id": "xyz" "desired": { "delete": true }, "reported": { .. } },
            ]
        json [{"id": "id1"}, {"id": "id2"}] | mark_delete
            [
                { "id": "id1", "desired": { "delete": true }, "reported": { .. } },
                { "id": "id2", "desired": { "delete": true }, "reported": { .. } },
            ]
        json ["id1", "id2"] | mark_delete
            [
                { "id": "id1", "desired": { "delete": true }, "reported": { .. } },
                { "id": "id2", "desired": { "delete": true }, "reported": { .. } },
            ]
    """

    @property
    def name(self) -> str:
        return "mark_delete"

    def info(self) -> str:
        return "Mark all incoming database objects for deletion."

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        return {"delete": True}


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

        return lambda in_stream: in_stream if arg is None else stream.map(in_stream, fmt)  # type: ignore


class ListSink(CLISink):
    @property
    def name(self) -> str:
        return "out"

    def info(self) -> str:
        return "Creates a list of results."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Sink[List[JsonElement]]:
        return stream.list  # type: ignore


def all_sources(d: CLIDependencies) -> List[CLISource]:
    return [EchoSource(d), JsonSource(d), EnvSource(d), MatchSource(d), SleepSource(d)]


def all_sinks(d: CLIDependencies) -> List[CLISink]:
    return [ListSink(d)]


def all_commands(d: CLIDependencies) -> List[CLICommand]:
    return [
        ChunkCommand(d),
        FlattenCommand(d),
        CountCommand(d),
        DesireCommand(d),
        FormatCommand(d),
        MarkDeleteCommand(d),
        UniqCommand(d),
    ]


def all_parts(d: CLIDependencies) -> List[CLIPart]:
    result: list[CLIPart] = []
    result.extend(all_sources(d))
    result.extend(all_commands(d))
    result.extend(all_sinks(d))
    return result
