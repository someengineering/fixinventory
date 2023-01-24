import asyncio
import logging
from typing import Optional, List, Dict, Tuple, Callable

from aiostream import stream
from attr import evolve

from resotocore.cli.cli import CLI
from resotocore.cli.model import CLIContext
from resotocore.config import ConfigEntity, ConfigHandler
from resotocore.db.model import QueryModel
from resotocore.ids import ConfigId
from resotocore.model.model import Model
from resotocore.query.model import Aggregate, AggregateFunction
from resotocore.report import (
    Inspector,
    ReportCheck,
    Benchmark,
    BenchmarkResult,
    CheckCollection,
    CheckCollectionResult,
    CheckResult,
    CheckConfigPrefix,
    BenchmarkConfigPrefix,
    CheckConfigRoot,
    ResotoReportValues,
    BenchmarkConfigRoot,
    ResotoReportBenchmark,
    ResotoReportCheck,
)
from resotocore.report.report_config import ReportCheckCollectionConfig, BenchmarkConfig
from resotocore.types import Json
from resotocore.web.service import Service

log = logging.getLogger(__name__)


def benchmark_id(name: str) -> ConfigId:
    return ConfigId(BenchmarkConfigPrefix + name)


def check_id(name: str) -> ConfigId:
    return ConfigId(CheckConfigPrefix + name)


class InspectorService(Inspector, Service):
    def __init__(self, cli: CLI) -> None:
        self.config_handler: ConfigHandler = cli.dependencies.config_handler
        self.db_access = cli.dependencies.db_access
        self.cli = cli
        self.template_expander = cli.dependencies.template_expander
        self.model_handler = cli.dependencies.model_handler

    async def start(self) -> None:
        # TODO: we need a migration path for checks added in existing configs
        config_ids = {i async for i in self.config_handler.list_config_ids()}
        overwrite = True  # only here to simplify development. True until we reach a stable version.
        for name, js in BenchmarkConfig.from_files().items():
            if overwrite or benchmark_id(name) not in config_ids:
                cid = benchmark_id(name)
                log.info(f"Creating benchmark config {cid}")
                await self.config_handler.put_config(ConfigEntity(cid, {BenchmarkConfigRoot: js}), validate=False)
        for name, js in ReportCheckCollectionConfig.from_files().items():
            if overwrite or check_id(name) not in config_ids:
                cid = check_id(name)
                log.info(f"Creating check collection config {cid}")
                await self.config_handler.put_config(ConfigEntity(cid, {CheckConfigRoot: js}), validate=False)

    async def list_checks(
        self,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
    ) -> List[ReportCheck]:
        def inspection_matches(inspection: ReportCheck) -> bool:
            return (
                (provider is None or provider == inspection.provider)
                and (service is None or service == inspection.service)
                and (category is None or category in inspection.categories)
                and (kind is None or kind == inspection.result_kind)
                and (check_ids is None or inspection.id in check_ids)
            )

        return await self.filter_checks(inspection_matches)

    async def perform_benchmark(self, benchmark_name: str, graph: str) -> BenchmarkResult:
        cfg = await self.config_handler.get_config(benchmark_id(benchmark_name))
        if cfg is None or BenchmarkConfigRoot not in cfg.config:
            raise ValueError(f"Unknown benchmark: {benchmark_name}")
        benchmark = BenchmarkConfig.from_config(cfg)
        return await self.__perform_benchmark(benchmark, graph)

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
            documentation="On demand benchmark",
            framework="resoto",
            version="1.0",
            checks=[c.id for c in checks],
            children=[],
        )
        return await self.__perform_benchmark(benchmark, graph)

    async def filter_checks(self, report_filter: Optional[Callable[[ReportCheck], bool]] = None) -> List[ReportCheck]:
        cfg_ids = [i async for i in self.config_handler.list_config_ids() if i.startswith(CheckConfigPrefix)]
        loaded = await asyncio.gather(*[self.config_handler.get_config(cfg_id) for cfg_id in cfg_ids])
        # fmt: off
        return [
            check
            for entry in loaded if isinstance(entry, ConfigEntity) and CheckConfigRoot in entry.config
            for check in ReportCheckCollectionConfig.from_config(entry) if report_filter is None or report_filter(check)
        ]
        # fmt: on

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
            resources_failing = 0
            checks_failing = 0
            checks_passing = 0
            for cr in check_results:
                resources_failing += cr.number_of_resources_failing
                if cr.passed:
                    checks_passing += 1
                else:
                    checks_failing += 1
            for cd in children:
                resources_failing += cd.resources_failing
                checks_failing += cd.checks_failing
                checks_passing += cd.checks_passing
            return CheckCollectionResult(
                cc.title,
                cc.description,
                documentation=cc.documentation,
                checks=check_results,
                children=children,
                passed=checks_failing == 0,
                resources_failing=resources_failing,
                checks_failing=checks_failing,
                checks_passing=checks_passing,
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
            resources_failing=top.resources_failing,
            checks_failing=top.checks_failing,
            checks_passing=top.checks_passing,
        )

    async def __perform_checks(
        self, graph: str, checks: List[ReportCheck], parallel_checks: int = 10
    ) -> Dict[str, int]:
        # load model
        model = await self.model_handler.load_model()
        # load configuration
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        cfg = cfg_entity.config if cfg_entity else {}

        async def perform_single(check: ReportCheck) -> Tuple[str, int]:
            return check.id, await self.__perform_check(graph, model, check, cfg)

        async with stream.map(
            stream.iterate(checks), perform_single, ordered=False, task_limit=parallel_checks
        ).stream() as streamer:
            return {key: value async for key, value in streamer}

    async def __perform_check(self, graph: str, model: Model, inspection: ReportCheck, config: Json) -> int:
        # final environment: defaults are coming from the check and are eventually overriden in the config
        env = inspection.environment(config)

        async def perform_search(search: str) -> int:
            # parse query
            rendered_query = self.template_expander.render(search, env)
            query = await self.template_expander.parse_query(rendered_query, on_section="reported")
            # add aggregation to only query for count
            query = evolve(query, aggregate=Aggregate([], [AggregateFunction("sum", 1, [], "count")]))
            async with await self.db_access.get_graph_db(graph).search_aggregation(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    return result["count"] or 0  # we expect exactly one result. count==null is considered 0
            return -1  # we should never reach this point, if we do, we mark the check as failing

        async def perform_cmd(cmd: str) -> int:
            # adjust command to only count the number of lines
            result = await self.cli.execute_cli_command(f"{cmd} | count", stream.list, CLIContext(env=env))
            # TODO: add args to count to get the raw numbers
            return int(result[0][0].rsplit(" ", 1)[-1])

        if resoto_search := inspection.detect.get("resoto"):
            return await perform_search(resoto_search)
        elif resoto_cmd := inspection.detect.get("resoto_cmd"):
            return await perform_cmd(resoto_cmd)
        else:
            raise ValueError(f"Invalid inspection {inspection.id}: no resoto or resoto_cmd defined")

    async def validate_benchmark_config(self, json: Json) -> Optional[Json]:
        try:
            benchmark = BenchmarkConfig.from_config(ConfigEntity(ResotoReportBenchmark, json))
            all_checks = {c.id for c in await self.filter_checks()}
            missing = []
            for check in benchmark.nested_checks():
                if check not in all_checks:
                    missing.append(check)
            if missing:
                return {"error": f"Following checks are defined in the benchmark but do not exist: {missing}"}
            else:
                return None
        except Exception as e:
            return {"error": f"Can not digest benchmark: {e}"}

    async def validate_check_collection_config(self, json: Json) -> Optional[Json]:
        try:
            errors = []
            for check in ReportCheckCollectionConfig.from_config(ConfigEntity(ResotoReportCheck, json)):
                env = check.default_values or {}
                if search := check.detect.get("resoto"):
                    rendered_query = self.template_expander.render(search, env)
                    await self.template_expander.parse_query(rendered_query, on_section="reported")
                elif cmd := check.detect.get("resoto_cmd"):
                    await self.cli.evaluate_cli_command(cmd, CLIContext(env=env))
                else:
                    errors.append(f"Check {check.id} neither has a resoto nor resoto_cmd defined")
            if errors:
                return {"error": f"Can not validate check collection: {errors}"}
            else:
                return None

        except Exception as e:
            return {"error": f"Can not digest check collection: {e}"}
