import asyncio
import logging
from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Callable, AsyncIterator

from aiostream import stream
from attr import define

from resotocore.analytics import CoreEvent
from resotocore.cli.model import CLIContext, CLI
from resotocore.config import ConfigEntity, ConfigHandler
from resotocore.db.model import QueryModel
from resotocore.error import NotFoundError
from resotocore.ids import ConfigId, GraphName, NodeId
from resotocore.model.graph_access import GraphBuilder
from resotocore.model.model import Model
from resotocore.model.resolve_in_graph import NodePath
from resotocore.query.model import Query, P
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
    ReportSeverity,
    ReportSeverityPriority,
)
from resotocore.report.report_config import ReportCheckCollectionConfig, BenchmarkConfig
from resotocore.service import Service
from resotocore.types import Json
from resotocore.util import value_in_path, uuid_str
from resotolib.json_bender import Bender, S, bend

log = logging.getLogger(__name__)

SingleCheckResult = Dict[str, List[Json]]


def benchmark_id(name: str) -> ConfigId:
    return ConfigId(BenchmarkConfigPrefix + name)


def check_id(name: str) -> ConfigId:
    return ConfigId(CheckConfigPrefix + name)


@define
class CheckContext:
    accounts: Optional[List[str]] = None
    severity: Optional[ReportSeverity] = None
    only_failed: bool = False
    parallel_checks: int = 10

    def includes_severity(self, severity: ReportSeverity) -> bool:
        if self.severity is None:
            return True
        else:
            return ReportSeverityPriority[self.severity] <= ReportSeverityPriority[severity]


# This defines the subset of the data provided for every resource
ReportResourceData: Dict[str, Bender] = {
    "node_id": S("id"),
    "id": S("reported", "id"),
    "name": S("reported", "name"),
    "kind": S("reported", "kind"),
    "tags": S("reported", "tags"),
    "ctime": S("reported", "ctime"),
    "atime": S("reported", "atime"),
    "mtime": S("reported", "mtime"),
    "cloud": S("ancestors", "cloud", "reported", "name"),
    "account": S("ancestors", "account", "reported", "name"),
    "region": S("ancestors", "region", "reported", "name"),
    "zone": S("ancestors", "zone", "reported", "name"),
}


class InspectorService(Inspector, Service):
    def __init__(self, cli: CLI) -> None:
        super().__init__()
        self.config_handler: ConfigHandler = cli.dependencies.config_handler
        self.db_access = cli.dependencies.db_access
        self.cli = cli
        self.template_expander = cli.dependencies.template_expander
        self.model_handler = cli.dependencies.model_handler
        self.event_sender = cli.dependencies.event_sender

    async def start(self) -> None:
        if not self.cli.dependencies.config.multi_tenant_setup:
            # TODO: we need a migration path for checks added in existing configs
            config_ids = {i async for i in self.config_handler.list_config_ids()}
            overwrite = False  # Only here to simplify development. True until we reach a stable version.
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

    async def list_benchmarks(self) -> List[Benchmark]:
        return [
            await self.__benchmark(i)
            async for i in self.config_handler.list_config_ids()
            if i.startswith(BenchmarkConfigPrefix)
        ]

    async def benchmark(self, name: str) -> Optional[Benchmark]:
        try:
            return await self.__benchmark(benchmark_id(name))
        except ValueError:
            return None

    async def list_checks(
        self,
        *,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
        context: Optional[CheckContext] = None,
    ) -> List[ReportCheck]:
        def inspection_matches(inspection: ReportCheck) -> bool:
            return (
                (provider is None or provider == inspection.provider)
                and (service is None or service == inspection.service)
                and (category is None or category in inspection.categories)
                and (kind is None or kind == inspection.result_kind)
                and (check_ids is None or inspection.id in check_ids)
                and (context is None or context.includes_severity(inspection.severity))
            )

        return await self.filter_checks(inspection_matches)

    async def perform_benchmarks(
        self,
        graph: GraphName,
        benchmark_names: List[str],
        *,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
        sync_security_section: bool = False,
    ) -> Dict[str, BenchmarkResult]:
        context = CheckContext(accounts=accounts, severity=severity, only_failed=only_failing)
        benchmarks = {name: await self.__benchmark(benchmark_id(name)) for name in benchmark_names}
        # collect all checks
        check_ids = {check for b in benchmarks.values() for check in b.nested_checks()}
        checks = await self.list_checks(check_ids=list(check_ids), context=context)
        check_lookup = {check.id: check for check in checks}
        # create benchmark results
        results = await self.__perform_checks(graph, checks, context)
        result = {
            name: self.__to_result(benchmark, check_lookup, results, context) for name, benchmark in benchmarks.items()
        }
        if sync_security_section:
            model = await self.model_handler.load_model(graph)
            # We invent a report run id here. This id is used to identify all reports created by this run.
            await self.db_access.get_graph_db(graph).update_security_section(
                uuid_str(), self.__benchmarks_to_security_iterator(result), model
            )
        return result

    async def perform_checks(
        self,
        graph: GraphName,
        *,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
        check_ids: Optional[List[str]] = None,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
    ) -> BenchmarkResult:
        context = CheckContext(accounts=accounts, severity=severity, only_failed=only_failing)
        checks = await self.list_checks(
            provider=provider, service=service, category=category, kind=kind, check_ids=check_ids, context=context
        )
        provider_name = f"{provider}_" if provider else ""
        service_name = f"{service}_" if service else ""
        category_name = f"{category}_" if category else ""
        kind_name = f"{kind}_" if kind else ""
        check_id_name = f"{check_ids[0]}_" if check_ids else ""
        title = f"{provider_name}{service_name}{category_name}{kind_name}{check_id_name}benchmark"
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

        if context.accounts is None:
            context.accounts = await self.__list_accounts(benchmark, graph)

        checks_to_perform = await self.list_checks(check_ids=benchmark.nested_checks(), context=context)
        check_by_id = {c.id: c for c in checks_to_perform}
        results = await self.__perform_checks(graph, checks_to_perform, context)
        await self.event_sender.core_event(CoreEvent.BenchmarkPerformed, {"benchmark": benchmark.id})
        return self.__to_result(benchmark, check_by_id, results, context)

    async def __benchmark(self, cfg_id: ConfigId) -> Benchmark:
        cfg = await self.config_handler.get_config(cfg_id)
        if cfg is None or BenchmarkConfigRoot not in cfg.config:
            raise ValueError(f"Unknown benchmark: {cfg_id}")
        return BenchmarkConfig.from_config(cfg)

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
        self, graph: GraphName, check_uid: str, account_ids: Optional[List[str]] = None
    ) -> AsyncIterator[Json]:
        # create context
        context = CheckContext(accounts=account_ids)
        # get check
        checks = await self.list_checks(check_ids=[check_uid], context=context)
        if not checks:
            raise NotFoundError(f"Check {check_uid} not found")
        model = await self.model_handler.load_model(graph)
        inspection = checks[0]
        # load configuration
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        cfg = cfg_entity.config if cfg_entity else {}
        return await self.__list_failing_resources(graph, model, inspection, cfg, context)

    async def __list_failing_resources(
        self, graph: GraphName, model: Model, inspection: ReportCheck, config: Json, context: CheckContext
    ) -> AsyncIterator[Json]:
        # final environment: defaults are coming from the check and are eventually overriden in the config
        env = inspection.environment(config)
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

        async def empty() -> AsyncIterator[Json]:
            if False:  # pylint: disable=using-constant-test
                yield {}  # noqa

        if resoto_search := inspection.detect.get("resoto"):
            return perform_search(resoto_search)
        elif resoto_cmd := inspection.detect.get("resoto_cmd"):
            return perform_cmd(resoto_cmd)
        else:
            return empty()

    def __to_result(
        self,
        benchmark: Benchmark,
        check_by_id: Dict[str, ReportCheck],
        results: Dict[str, SingleCheckResult],
        context: CheckContext,
    ) -> BenchmarkResult:
        def to_result(cc: CheckCollection) -> CheckCollectionResult:
            check_results = []
            for cid in cc.checks or []:
                if (check := check_by_id.get(cid)) is not None:
                    result = results.get(cid, {})
                    count_by_account = {uid: len(failed) for uid, failed in result.items()}
                    check_results.append(CheckResult(check, count_by_account, result))
            children = [to_result(c) for c in cc.children or []]
            return CheckCollectionResult(
                cc.title, cc.description, documentation=cc.documentation, checks=check_results, children=children
            )

        top = to_result(benchmark).filter_result(context.only_failed)
        return BenchmarkResult(
            benchmark.title,
            benchmark.description,
            benchmark.framework,
            benchmark.version,
            documentation=benchmark.documentation,
            checks=top.checks,
            children=top.children,
            accounts=context.accounts,
            only_failed=context.only_failed,
            severity=context.severity,
            id=benchmark.id,
        )

    async def __perform_checks(
        self, graph: GraphName, checks: List[ReportCheck], context: CheckContext
    ) -> Dict[str, SingleCheckResult]:
        # load model
        model = await self.model_handler.load_model(graph)
        # load configuration
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        cfg = cfg_entity.config if cfg_entity else {}

        async def perform_single(check: ReportCheck) -> Tuple[str, SingleCheckResult]:
            return check.id, await self.__perform_check(graph, model, check, cfg, context)

        async with stream.map(
            stream.iterate(checks), perform_single, ordered=False, task_limit=context.parallel_checks
        ).stream() as streamer:
            return {key: value async for key, value in streamer}

    async def __perform_check(
        self, graph: GraphName, model: Model, inspection: ReportCheck, config: Json, context: CheckContext
    ) -> SingleCheckResult:
        resources_by_account = defaultdict(list)
        # if the result kind is an account, we need to use the id directly instead of walking the graph
        is_account = (rk := model.get(inspection.result_kind)) and "account" in rk.kind_hierarchy()
        account_id_path = NodePath.reported_id if is_account else NodePath.ancestor_account_id
        async for resource in await self.__list_failing_resources(graph, model, inspection, config, context):
            account_id = value_in_path(resource, account_id_path)
            if account_id:
                resources_by_account[account_id].append(bend(ReportResourceData, resource))
        return resources_by_account

    async def __list_accounts(self, benchmark: Benchmark, graph: GraphName) -> List[str]:
        model = await self.model_handler.load_model(graph)
        gdb = self.db_access.get_graph_db(graph)
        query = Query.by("account")
        if benchmark.clouds:
            query = query.combine(Query.by(P.single("ancestors.cloud.reported.id").is_in(benchmark.clouds)))
        async with await gdb.search_list(QueryModel(query, model)) as crs:
            ids = [value_in_path(a, NodePath.reported_id) async for a in crs]
            return [aid for aid in ids if aid is not None]

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

    def __benchmarks_to_security_iterator(
        self, results: Dict[str, BenchmarkResult]
    ) -> AsyncIterator[Tuple[NodeId, str, Json]]:
        # Create a mapping from node_id to all check results that contain this node
        node_result: Dict[str, List[Tuple[BenchmarkResult, CheckResult]]] = defaultdict(list)

        def walk_collection(collection: CheckCollectionResult, parent: BenchmarkResult) -> None:
            for check in collection.checks:
                for resources in check.resources_failing_by_account.values():
                    for resource in resources:
                        node_result[resource["node_id"]].append((parent, check))
            for child in collection.children:
                walk_collection(child, parent)

        for result in results.values():
            walk_collection(result, result)

        async def iterate_nodes() -> AsyncIterator[Tuple[NodeId, str, Json]]:
            for node_id, contexts in node_result.items():
                issues = [
                    dict(benchmark=bench.id, check=check.check.id, severity=check.check.severity.name)
                    for bench, check in contexts
                ]
                # ignore the order of the issues
                hashed = GraphBuilder.content_hash({i["check"]: i for i in issues})
                yield NodeId(node_id), hashed, dict(issues=issues)

        return iterate_nodes()
