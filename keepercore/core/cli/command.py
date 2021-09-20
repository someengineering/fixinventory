import asyncio
import json
import logging
import re
from abc import abstractmethod, ABC
from datetime import timedelta
from functools import partial
from typing import Optional, Any, AsyncGenerator, Hashable, Iterable, Union, Callable

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
)
from core.db.model import QueryModel
from core.error import CLIParseError, CLIExecutionError
from core.model.graph_access import Section
from core.model.resolve_in_graph import NodePath
from core.model.typed_model import to_js, class_fqn
from core.parse_util import quoted_or_simple_string_dp
from core.query.query_parser import (
    parse_query,
)
from core.types import Json, JsonElement
from core.util import AccessJson, uuid_str, value_in_path_get, value_in_path
from core.worker_task_queue import WorkerTask

log = logging.getLogger(__name__)


# check if a is a json node element
def is_node(a: Any) -> bool:
    return (
        "id" in a and Section.reported in a and Section.desired in a and Section.metadata in a
        if isinstance(a, dict)
        else False
    )


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

    quoted = re.compile('(^\\s*")(.*)("\\s*$)')

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        arg = arg if arg else ""
        matched = self.quoted.fullmatch(arg)
        if matched:
            arg = matched[2]
        return stream.just(arg)


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


class QuerySource(CLISource):
    """
    Usage: query <query>

    A query is performed against the graph database and all resulting elements will be emitted.
    To learn more about the query, visit todo: link is missing.

    Example:
        query isinstance("ec2") and (cpu>12 or cpu<3)  # will result in all matching elements [{..}, {..}, .. {..}]

    Environment Variables:
        graph [mandatory]: the name of the graph to operate on
        section [optional, defaults to "reported"]: on which section the query is performed
    """

    @property
    def name(self) -> str:
        return "query"

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
        query_model = QueryModel(query, model, None)
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
        def inc_prop(o: Any) -> tuple[int, int]:
            def prop_value() -> tuple[int, int]:
                try:
                    return int(o[arg]), 0
                except Exception:
                    return 0, 1

            return prop_value() if arg in o else (0, 1)

        def inc_identity(_: Any) -> tuple[int, int]:
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


class HeadCommand(CLICommand):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        size = abs(int(arg)) if arg else 100
        return lambda in_stream: stream.take(in_stream, size)


class TailCommand(CLICommand):
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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        size = abs(int(arg)) if arg else 100
        return lambda in_stream: stream.takelast(in_stream, size)


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

        return lambda in_stream: stream.filter(in_stream, has_not_seen)


class SetDesiredState(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        func = partial(self.set_desired, arg, env["graph"], self.patch(arg, **env))
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)

    async def set_desired(
        self, arg: Optional[str], graph_name: str, patch: Json, items: list[Json]
    ) -> AsyncGenerator[Json, None]:
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = []
        for item in items:
            if "id" in item:
                node_ids.append(item["id"])
            elif isinstance(item, str):
                node_ids.append(item)
        async for update in db.update_nodes_desired(patch, node_ids):
            yield update


class SetDesiredCommand(SetDesiredState):
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


class CleanCommand(SetDesiredState):
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
        self, arg: Optional[str], graph_name: str, patch: Json, items: list[Json]
    ) -> AsyncGenerator[Json, None]:
        reason = f"Reason: {arg}" if arg else "No reason provided."
        async for elem in super().set_desired(arg, graph_name, patch, items):
            uid = value_in_path(elem, NodePath.node_id)
            r_id = value_in_path_get(elem, NodePath.reported_id, "<no id>")
            r_name = value_in_path_get(elem, NodePath.reported_name, "<no name>")
            r_kind = value_in_path_get(elem, NodePath.reported_kind, "<no kind>")
            log.info(f"Node id={r_id}, name={r_name}, kind={r_kind} marked for cleanup. {reason}. ({uid})")
            yield elem


class SetMetadataState(CLICommand, ABC):
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        func = partial(self.set_metadata, env["graph"], self.patch(arg, **env))
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)

    async def set_metadata(self, graph_name: str, patch: Json, items: list[Json]) -> AsyncGenerator[JsonElement, None]:
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = []
        for item in items:
            if "id" in item:
                node_ids.append(item["id"])
            elif isinstance(item, str):
                node_ids.append(item)
        async for update in db.update_nodes_metadata(patch, node_ids):
            yield update


class SetMetadataCommand(SetMetadataState):
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


class ProtectCommand(SetMetadataState):
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


class JobsSource(CLISource):
    """
    Usage: jobs

    rist all jobs in the system.

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
        return "list all jobs in the system."

    async def parse(self, arg: Optional[str] = None, **env: str) -> Result[Source]:
        for job in await self.dependencies.job_handler.list_jobs():
            wait = {"wait": {"message_type": job.wait[0].message_type}} if job.wait else {}
            yield {"id": job.id, "trigger": to_js(job.trigger), "command": job.command.command} | wait


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

    # this method expects a stream of tuple[str, dict[str, str], Json]
    def send_to_queue_stream(self, in_stream: Stream) -> Stream:
        async def send_to_queue(task_name: str, task_args: dict[str, str], data: Json) -> Any:
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

    def load_by_id_if_string(self, in_stream: Stream, **env: str) -> Stream:
        async def load_element(item: JsonElement) -> AsyncGenerator[Json, None]:
            if isinstance(item, str):
                graph_name = env["graph"]
                node = await self.dependencies.db_access.get_graph_db(graph_name).get_node(item)
                if node:
                    yield node
            elif is_node(item):
                yield item  # type: ignore
            else:
                raise CLIExecutionError(f"Command expects a string  node element, but got {class_fqn(item)}.")

        return stream.flatmap(in_stream, load_element, task_limit=self.task_limit())

    # noinspection PyMethodMayBeStatic
    def task_limit(self) -> int:
        # override if this limit is not sufficient
        return 100

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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        def to_result(task: WorkerTask, result: Union[Json, Exception]) -> Json:
            tid = task.data["node"]["id"]  # defined by the data spec, see lines below
            if isinstance(result, Exception):
                return {tid: "error", "reason": str(result)}
            else:
                return {tid: "success"}

        parts = re.split(r"\s+", arg if arg else "")
        pl = len(parts)
        if pl == 2 and parts[0] == "delete":
            tag = parts[1]
            fn: Callable[[Json], tuple[str, dict[str, str], Json]] = lambda item: (  # noqa: E731
                "tag",
                item.get("metadata", {}),
                {"delete": [tag], "node": item},
            )
        elif pl == 3 and parts[0] == "update":
            tag = parts[1]
            value = quoted_or_simple_string_dp.parse(parts[2])
            fn = lambda item: ("tag", item.get("metadata", {}), {"update": {tag: value}, "node": item})  # noqa: E731
        else:
            raise AttributeError("Expect update tag_key tag_value or delete tag_key")

        return lambda in_stream: stream.starmap(
            self.send_to_queue_stream(stream.map(self.load_by_id_if_string(in_stream, **env), fn)), to_result
        )


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

    async def parse(self, arg: Optional[str] = None, **env: str) -> Sink[list[JsonElement]]:
        return stream.list  # type: ignore


def all_sources(d: CLIDependencies) -> list[CLISource]:
    return [
        AddJobSource(d),
        DeleteJobSource(d),
        EchoSource(d),
        EnvSource(d),
        JobsSource(d),
        JsonSource(d),
        QuerySource(d),
        SleepSource(d),
        StartTaskSource(d),
        TasksSource(d),
    ]


def all_sinks(d: CLIDependencies) -> list[CLISink]:
    return [ListSink(d)]


def all_commands(d: CLIDependencies) -> list[CLICommand]:
    return [
        ChunkCommand(d),
        CleanCommand(d),
        CountCommand(d),
        FlattenCommand(d),
        FormatCommand(d),
        HeadCommand(d),
        ProtectCommand(d),
        SetDesiredCommand(d),
        SetMetadataCommand(d),
        TagCommand(d),
        TailCommand(d),
        UniqCommand(d),
    ]


def all_query_parts(d: CLIDependencies) -> list[QueryPart]:
    return [
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


def all_parts(d: CLIDependencies) -> list[CLIPart]:
    result: list[CLIPart] = []
    result.extend(all_query_parts(d))
    result.extend(all_sources(d))
    result.extend(all_commands(d))
    result.extend(all_sinks(d))
    return result


def aliases() -> dict[str, str]:
    # command alias -> command name
    return {"match": "reported", "start_workflow": "start_task", "start_job": "start_task"}
