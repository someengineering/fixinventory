import asyncio
from functools import reduce
from typing import Optional, List, Iterable, Dict, Tuple

from aiostream import stream
from attr import evolve

from resotocore.cli.cli import CLI
from resotocore.config import ConfigEntity
from resotocore.db.model import QueryModel
from resotocore.ids import ConfigId
from resotocore.inspect import (
    Inspector,
    InspectionCheck,
    Benchmark,
    BenchmarkResult,
    CheckCollection,
    CheckCollectionResult,
    CheckResult,
)
from resotocore.model.model import Model
from resotocore.model.typed_model import from_js, to_js
from resotocore.query.model import Aggregate, AggregateFunction

ConfigCheckPrefix = "resoto.report.check."
ConfigCheckRoot = "inspection_check"


def config_id(name: str) -> ConfigId:
    return ConfigId(ConfigCheckPrefix + name)


def inspection_check(cfg: ConfigEntity) -> InspectionCheck:
    return from_js(cfg.config[ConfigCheckRoot], InspectionCheck)


class InspectorService(Inspector):
    def __init__(self, cli: CLI) -> None:
        self.config_handler = cli.dependencies.config_handler
        self.db_access = cli.dependencies.db_access
        self.cli = cli
        self.query_parser = cli.dependencies.template_expander
        self.model_handler = cli.dependencies.model_handler
        self.predefined_inspections = {i.id: i for i in InspectionCheck.from_files()}
        self.benchmarks = {b.id: b for b in Benchmark.from_files(self.predefined_inspections)}

    async def get_check(self, uid: str) -> Optional[InspectionCheck]:
        entry = await self.config_handler.get_config(config_id(uid))
        return inspection_check(entry) if entry else self.predefined_inspections.get(uid)

    async def list_checks(
        self,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
    ) -> List[InspectionCheck]:
        result = {}

        def add_inspections(inspections: Iterable[InspectionCheck]) -> None:
            for inspection in inspections:
                if (
                    (provider is None or provider == inspection.provider)
                    and (service is None or service == inspection.service)
                    and (category is None or category in inspection.categories)
                    and (kind is None or kind == inspection.kind)
                    and (check_ids is None or inspection.id in check_ids)
                ):
                    result[inspection.id] = inspection

        cfg_ids = [
            i
            async for i in self.config_handler.list_config_ids()
            if i.startswith(ConfigCheckPrefix) and (check_ids is None or i in check_ids)
        ]
        loaded = await asyncio.gather(*[self.config_handler.get_config(cfg_id) for cfg_id in cfg_ids])
        checks = [inspection_check(entry) for entry in loaded if isinstance(entry, ConfigEntity)]
        add_inspections(self.predefined_inspections.values())
        add_inspections(checks)
        return list(result.values())

    async def update_check(self, inspection: InspectionCheck) -> InspectionCheck:
        entity = ConfigEntity(config_id(inspection.id), {ConfigCheckRoot: to_js(inspection)})
        updated = await self.config_handler.put_config(entity)
        return inspection_check(updated)

    async def delete_check(self, uid: str) -> None:
        await self.config_handler.delete_config(config_id(uid))

    async def perform_benchmark(self, benchmark: str, graph: str) -> BenchmarkResult:
        if benchmark not in self.benchmarks:
            raise ValueError(f"Unknown benchmark: {benchmark}")
        return await self.__perform_benchmark(self.benchmarks[benchmark], graph)

    async def perform_checks(
        self,
        graph: str,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> BenchmarkResult:
        checks = await self.list_checks(provider, service, category, kind)
        provider_name = f"{provider}_" if provider else ""
        service_name = f"{service}_" if service else ""
        category_name = f"{category}_" if category else ""
        kind_name = f"{kind}_" if kind else ""
        title = f"{provider_name}{service_name}{category_name}{kind_name}_benchmark"
        benchmark = Benchmark(
            id=title,
            title=title,
            description="On demand benchmark",
            framework="resoto",
            version="1.0",
            checks=[c.id for c in checks],
        )
        return await self.__perform_benchmark(benchmark, graph)

    async def __perform_benchmark(self, benchmark: Benchmark, graph: str) -> BenchmarkResult:
        perform_checks = await self.list_checks(check_ids=benchmark.nested_checks())
        check_by_id = {c.id: c for c in perform_checks}
        result = await self.__perform_checks(graph, perform_checks)

        def check_result(cid: str) -> CheckResult:
            check = check_by_id[cid]
            num_failing = result.get(cid)
            num_failing = -1 if num_failing is None else num_failing
            return CheckResult(check, num_failing == 0, max(0, num_failing))

        def to_result(cc: CheckCollection) -> CheckCollectionResult:
            check_results = [check_result(c) for c in cc.checks or []]
            children = [to_result(c) for c in cc.children or []]
            failing = reduce(lambda a, b: a + b.number_of_resources_failing, check_results, 0) + reduce(
                lambda a, b: a + b.number_of_resources_failing, children, 0
            )
            return CheckCollectionResult(
                cc.title,
                cc.description,
                documentation=cc.documentation,
                checks=check_results,
                children=children,
                passed=failing == 0,
                number_of_resources_failing=failing,
            )

        top = to_result(benchmark)
        return BenchmarkResult(
            benchmark.title,
            benchmark.description,
            benchmark.framework,
            benchmark.version,
            documentation=benchmark.documentation,
            checks=top.checks,
            children=top.children,
            passed=top.passed,
            number_of_resources_failing=top.number_of_resources_failing,
        )

    async def __perform_checks(
        self, graph: str, checks: List[InspectionCheck], parallel_checks: int = 10
    ) -> Dict[str, int]:
        # load model
        model = await self.model_handler.load_model()

        async def perform_single(check: InspectionCheck) -> Tuple[str, int]:
            return check.id, await self.__perform_check(graph, model, check)

        async with stream.map(
            stream.iterate(checks), perform_single, ordered=False, task_limit=parallel_checks
        ).stream() as streamer:
            return {key: value async for key, value in streamer}

    async def __perform_check(self, graph: str, model: Model, inspection: InspectionCheck) -> int:
        async def perform_search(search: str) -> int:
            # parse query
            query = await self.query_parser.parse_query(search, on_section="reported")
            # add aggregation to only query for count
            query = evolve(query, aggregate=Aggregate([], [AggregateFunction("sum", 1, [], "count")]))
            async with await self.db_access.get_graph_db(graph).search_aggregation(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    return result["count"] or 0  # we expect exactly one result. count==null is considered 0
            return -1  # we should never reach this point, if we do, we mark the check as failing

        async def perform_cmd(cmd: str) -> int:
            # adjust command to only count the number of lines
            result = await self.cli.execute_cli_command(f"{cmd} | count", stream.list)
            # TODO: add args to count to get the raw numbers
            return int(result[0][0].rsplit(" ", 1)[-1])

        if resoto_search := inspection.detect.get("resoto"):
            return await perform_search(resoto_search)
        elif resoto_cmd := inspection.detect.get("resoto_cmd"):
            return await perform_cmd(resoto_cmd)
        else:
            raise ValueError(f"Invalid inspection {inspection.id}: no resoto or resoto_cmd defined")
