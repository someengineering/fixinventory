import json
from abc import abstractmethod, ABC
from functools import partial
from typing import List, Optional, Any, Tuple, AsyncGenerator, Union, Hashable

from aiostream import stream
from aiostream.core import Stream

from core.cli.cli import CLISource, CLISink, Sink, Source, CLICommand, Flow, CLIDependencies, CLIPart, key_values_parser
from core.db.model import QueryModel
from core.error import CLIParseError
from core.query.query_parser import parse_query
from core.types import Json, JsonElement


class EchoSource(CLISource):  # type: ignore
    @property
    def name(self) -> str:
        return "echo"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        js = json.loads(arg if arg else "")
        if isinstance(js, list):
            elements = js
        elif isinstance(js, (str, int, float, bool, dict)):
            elements = [js]
        else:
            raise AttributeError(f"Echo does not understand {arg}.")

        for element in elements:
            yield element


class MatchSource(CLISource):  # type: ignore
    @property
    def name(self) -> str:
        return "match"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        # db name and section is coming from the env
        db_name = env["graphdb"]
        query_section = env.get("section", "reported")
        if not arg:
            raise CLIParseError("match command needs a query to execute, but nothing was given!")
        query = parse_query(arg)
        model = await self.dependencies.model_handler.load_model()
        db = self.dependencies.db_access.get_graph_db(db_name)
        return db.query_list(QueryModel(query, model, query_section), with_system_props=True)


class EnvSource(CLISource):  # type: ignore
    @property
    def name(self) -> str:
        return "env"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Source:
        return stream.just(env)


class CountCommand(CLICommand):  # type: ignore
    @property
    def name(self) -> str:
        return "count"

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

        return count_in_stream


class ChunkCommand(CLICommand):  # type: ignore
    @property
    def name(self) -> str:
        return "chunk"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        size = int(arg) if arg else 100
        return lambda in_stream: stream.chunks(in_stream, size)


class FlattenCommand(CLICommand):  # type: ignore
    @property
    def name(self) -> str:
        return "flatten"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        return lambda in_stream: stream.flatmap(in_stream, stream.iterate)


class UniqCommand(CLICommand):  # type: ignore
    @property
    def name(self) -> str:
        return "uniq"

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


class SetDesiredState(CLICommand, ABC):  # type: ignore
    @abstractmethod
    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        # deriving classes need to define how to patch
        pass

    async def parse(self, arg: Optional[str] = None, **env: str) -> Flow:
        buffer_size = 1000
        result_section = env["result_section"].split(",") if "result_section" in env else ["reported", "desired"]
        func = partial(self.set_desired, env["graphdb"], self.patch(arg, **env), result_section)
        return lambda in_stream: stream.flatmap(stream.chunks(in_stream, buffer_size), func)

    async def set_desired(
        self, graph_name: str, patch: Json, result_section: Union[str, List[str]], items: List[Json]
    ) -> AsyncGenerator[JsonElement, None]:
        db = self.dependencies.db_access.get_graph_db(graph_name)
        node_ids = [a["_id"] for a in items if "_id" in a]
        async for update in db.update_nodes_desired(patch, node_ids, result_section):
            yield update


class DesireCommand(SetDesiredState):
    @property
    def name(self) -> str:
        return "desire"

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        if arg and arg.strip():
            return key_values_parser.parse(arg)  # type: ignore
        else:
            return {}


class MarkDeleteCommand(SetDesiredState):
    @property
    def name(self) -> str:
        return "mark_delete"

    def patch(self, arg: Optional[str] = None, **env: str) -> Json:
        return {"delete": True}


class ListSink(CLISink):  # type: ignore
    @property
    def name(self) -> str:
        return "out"

    async def parse(self, arg: Optional[str] = None, **env: str) -> Sink[List[JsonElement]]:
        return lambda in_stream: stream.list(in_stream)


def all_sources(d: CLIDependencies) -> List[CLISource]:
    return [EchoSource(d), EnvSource(d), MatchSource(d)]


def all_sinks(d: CLIDependencies) -> List[CLISink]:
    return [ListSink(d)]


def all_commands(d: CLIDependencies) -> List[CLICommand]:
    return [ChunkCommand(d), FlattenCommand(d), CountCommand(d), DesireCommand(d), MarkDeleteCommand(d), UniqCommand(d)]


def all_parts(d: CLIDependencies) -> List[CLIPart]:
    # noinspection PyTypeChecker
    return all_sources(d) + all_commands(d) + all_sinks(d)
