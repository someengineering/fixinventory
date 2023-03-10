import asyncio
import logging
from typing import Optional, List, Dict, Tuple, Callable, AsyncIterator

from aiostream import stream
from attr import evolve, define

from resotocore.analytics import CoreEvent
from resotocore.cli.cli import CLI
from resotocore.cli.model import CLIContext
from resotocore.config import ConfigEntity, ConfigHandler
from resotocore.db.model import QueryModel
from resotocore.error import NotFoundError
from resotocore.ids import ConfigId
from resotocore.model.model import Model
from resotocore.query.model import Aggregate, AggregateFunction, Query, P, AggregateVariable, AggregateVariableName
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

CountByAccount = Dict[str, int]


def benchmark_id(name: str) -> ConfigId:
    return ConfigId(BenchmarkConfigPrefix + name)


def check_id(name: str) -> ConfigId:
    return ConfigId(CheckConfigPrefix + name)


@define
class CheckContext:
    accounts: Optional[List[str]] = None
    parallel_checks: int = 10


class InspectorService(Inspector, Service):
    def __init__(self, cli: CLI) -> None:
        self.config_handler: ConfigHandler = cli.dependencies.config_handler
        self.db_access = cli.dependencies.db_access
        self.cli = cli
        self.template_expander = cli.dependencies.template_expander
        self.model_handler = cli.dependencies.model_handler
        self.event_sender = cli.dependencies.event_sender

    async def start(self) -> None:
        # TODO: we need a migration path for checks added in existing configs
        config_ids = {i async for i in self.config_handler.list_config_ids()}
        overwrite = False  # only here to simplify development. True until we reach a stable version.
        # we renamed this config in 3.2.6 - old installations still might have it
        # this line can be removed in a future version
        await self.config_handler.delete_config(ConfigId("resoto.report.benchmark.aws_cis_1.5"))
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

    async def perform_benchmark(
        self, benchmark_name: str, graph: str, accounts: Optional[List[str]] = None
    ) -> BenchmarkResult:
        cfg = await self.config_handler.get_config(benchmark_id(benchmark_name))
        if cfg is None or BenchmarkConfigRoot not in cfg.config:
            raise ValueError(f"Unknown benchmark: {benchmark_name}")
        benchmark = BenchmarkConfig.from_config(cfg)
        context = CheckContext(accounts=accounts)
        return await self.__perform_benchmark(benchmark, graph, context)

    async def perform_checks(
        self,
        graph: str,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        accounts: Optional[List[str]] = None,
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
        context = CheckContext(accounts=accounts)
        return await self.__perform_benchmark(benchmark, graph, context)

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

    async def list_failing_resources(
        self, graph: str, check_uid: str, account_ids: Optional[List[str]] = None
    ) -> AsyncIterator[Json]:
        context = CheckContext(accounts=account_ids)
        return await self.__list_failing_resources(graph, check_uid, context)

    async def __list_failing_resources(self, graph: str, check_uid: str, context: CheckContext) -> AsyncIterator[Json]:
        checks = await self.list_checks(check_ids=[check_uid])
        if not checks:
            raise NotFoundError(f"Check {check_uid} not found")
        inspection = checks[0]
        # load model
        model = await self.model_handler.load_model()
        # load configuration
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        cfg = cfg_entity.config if cfg_entity else {}
        # final environment: defaults are coming from the check and are eventually overriden in the config
        env = inspection.environment(cfg)
        account_id_prop = "ancestors.account.reported.id"
        # if the result kind is an account, we need to use the id directly instead of walking the graph
        if (result_kind := model.get(inspection.result_kind)) and "account" in result_kind.kind_hierarchy():
            account_id_prop = "reported.id"

        async def perform_search(search: str) -> AsyncIterator[Json]:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported", **env)
            # filter only relevant accounts if provided
            if context.accounts:
                query = Query.by(P.single(account_id_prop).is_in(context.accounts)).combine(query)
            async with await self.db_access.get_graph_db(graph).search_list(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    yield result

        async def perform_cmd(cmd: str) -> AsyncIterator[Json]:
            # filter only relevant accounts if provided
            if context.accounts:
                account_list = ",".join(f'"{a}"' for a in context.accounts)
                cmd = f"search /{account_id_prop} in [{account_list}] | " + cmd
            cli_result = await self.cli.execute_cli_command(cmd, stream.list, CLIContext(env=env))
            for result in cli_result[0]:
                yield result

        if resoto_search := inspection.detect.get("resoto"):
            return perform_search(resoto_search)
        elif resoto_cmd := inspection.detect.get("resoto_cmd"):
            return perform_cmd(resoto_cmd)
        else:
            return stream.empty()  # type: ignore

    async def __perform_benchmark(self, benchmark: Benchmark, graph: str, context: CheckContext) -> BenchmarkResult:
        perform_checks = await self.list_checks(check_ids=benchmark.nested_checks())
        check_by_id = {c.id: c for c in perform_checks}
        result = await self.__perform_checks(graph, perform_checks, context)
        await self.event_sender.core_event(CoreEvent.BenchmarkPerformed, {"benchmark": benchmark.id})

        def to_result(cc: CheckCollection) -> CheckCollectionResult:
            check_results = [CheckResult(check_by_id[cid], result.get(cid, {})) for cid in cc.checks or []]
            children = [to_result(c) for c in cc.children or []]
            return CheckCollectionResult(
                cc.title, cc.description, documentation=cc.documentation, checks=check_results, children=children
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
        )

    async def __perform_checks(
        self, graph: str, checks: List[ReportCheck], context: CheckContext
    ) -> Dict[str, CountByAccount]:
        # load model
        model = await self.model_handler.load_model()
        # load configuration
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        cfg = cfg_entity.config if cfg_entity else {}

        async def perform_single(check: ReportCheck) -> Tuple[str, CountByAccount]:
            return check.id, await self.__perform_check(graph, model, check, cfg, context)

        async with stream.map(
            stream.iterate(checks), perform_single, ordered=False, task_limit=context.parallel_checks
        ).stream() as streamer:
            return {key: value async for key, value in streamer}

    async def __perform_check(
        self, graph: str, model: Model, inspection: ReportCheck, config: Json, context: CheckContext
    ) -> CountByAccount:
        # final environment: defaults are coming from the check and are eventually overriden in the config
        env = inspection.environment(config)
        account_id_prop = "ancestors.account.reported.id"
        # if the result kind is an account, we need to use the id directly instead of walking the graph
        if (result_kind := model.get(inspection.result_kind)) and "account" in result_kind.kind_hierarchy():
            account_id_prop = "reported.id"

        async def perform_search(search: str) -> CountByAccount:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported", **env)
            # filter only relevant accounts if provided
            if context.accounts:
                query = Query.by(P.single(account_id_prop).is_in(context.accounts)).combine(query)
            # add aggregation to only query for count
            ag_var = AggregateVariable(AggregateVariableName(account_id_prop), "account_id")
            ag_fn = AggregateFunction("sum", 1, [], "count")
            query = evolve(query, aggregate=Aggregate([ag_var], [ag_fn]))
            account_result: CountByAccount = {}
            async with await self.db_access.get_graph_db(graph).search_aggregation(QueryModel(query, model)) as ctx:
                async for result in ctx:
                    account_result[result["group"]["account_id"]] = result["count"] or 0
            return account_result

        async def perform_cmd(cmd: str) -> CountByAccount:
            # filter only relevant accounts if provided
            if context.accounts:
                account_list = ",".join(f'"{a}"' for a in context.accounts)
                cmd = f"search /{account_id_prop} in [{account_list}] | " + cmd
            # aggregate by account
            aggregate = f"aggregate /{account_id_prop} as account_id: sum(1) as count"
            cli_result = await self.cli.execute_cli_command(f"{cmd} | {aggregate}", stream.list, CLIContext(env=env))
            account_result: CountByAccount = {}
            for result in cli_result[0]:
                account_result[result["group"]["account_id"]] = result["count"] or 0
            return account_result

        if resoto_search := inspection.detect.get("resoto"):
            return await perform_search(resoto_search)
        elif resoto_cmd := inspection.detect.get("resoto_cmd"):
            return await perform_cmd(resoto_cmd)
        elif inspection.detect.get("manual"):
            # let's assume the manual check is successful
            return {}
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
                try:
                    env = check.default_values or {}
                    if search := check.detect.get("resoto"):
                        await self.template_expander.parse_query(search, on_section="reported", **env)
                    elif cmd := check.detect.get("resoto_cmd"):
                        await self.cli.evaluate_cli_command(cmd, CLIContext(env=env))
                    elif check.detect.get("manual"):
                        pass
                    else:
                        errors.append(f"Check {check.id} neither has a resoto, resoto_cmd or manual defined")
                except Exception as e:
                    errors.append(f"Check {check.id} is invalid: {e}")
            if errors:
                return {"error": f"Can not validate check collection: {errors}"}
            else:
                return None

        except Exception as e:
            return {"error": f"Can not digest check collection: {e}"}
