import asyncio
import logging
from abc import abstractmethod
from collections import defaultdict
from functools import lru_cache
from typing import Optional, List, Dict, Tuple, Callable, AsyncIterator, cast

from aiostream import stream, pipe
from aiostream.core import Stream
from attr import define

from resotocore.analytics import CoreEvent
from resotocore.cli import list_sink
from resotocore.cli.model import CLIContext, CLI
from resotocore.config import ConfigEntity, ConfigHandler
from resotocore.db.model import QueryModel
from resotocore.error import NotFoundError
from resotocore.ids import ConfigId, GraphName, NodeId
from resotocore.model.model import Model
from resotocore.model.resolve_in_graph import NodePath
from resotocore.query.model import Query, P, Term
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
from resotocore.util import value_in_path, uuid_str, value_in_path_get
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

    def severities_including(self, severity: ReportSeverity) -> List[ReportSeverity]:
        return [s for s in ReportSeverity if self.includes_severity(severity)]

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
        self.db_access = cli.dependencies.db_access
        self.cli = cli
        self.template_expander = cli.dependencies.template_expander
        self.model_handler = cli.dependencies.model_handler
        self.event_sender = cli.dependencies.event_sender

    @abstractmethod
    async def _report_values(self) -> Json:
        pass

    @abstractmethod
    async def _check_ids(self) -> List[ConfigId]:
        pass

    @abstractmethod
    async def _checks(self, cfg_id: ConfigId) -> List[ReportCheck]:
        pass

    @abstractmethod
    async def _benchmark(self, cfg_id: ConfigId) -> Benchmark:
        pass

    async def benchmark(self, name: str) -> Optional[Benchmark]:
        try:
            return await self._benchmark(benchmark_id(name))
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
                and (kind is None or kind in inspection.result_kinds)
                and (check_ids is None or inspection.id in check_ids)
                and (context is None or context.includes_severity(inspection.severity))
            )

        return await self.filter_checks(inspection_matches)

    async def load_benchmarks(
        self,
        graph: GraphName,
        benchmark_names: List[str],
        *,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
    ) -> Dict[str, BenchmarkResult]:
        context = CheckContext(accounts=accounts, severity=severity, only_failed=only_failing)
        # create query
        term: Term = P("benchmark").is_in(benchmark_names)
        if severity:
            term = term & P("severity").is_in([s.value for s in context.severities_including(severity)])
        term = P.context("security.issues[]", term)
        if accounts:
            term = term & P("ancestors.account.reported.id").is_in(accounts)
        term = term & P("security.has_issues").eq(True)
        model = QueryModel(Query.by(term), await self.model_handler.load_model(graph))

        # collect all checks
        benchmarks = {name: await self._benchmark(benchmark_id(name)) for name in benchmark_names}
        check_ids = {check for b in benchmarks.values() for check in b.nested_checks()}
        checks = await self.list_checks(check_ids=list(check_ids), context=context)
        check_lookup = {check.id: check for check in checks}

        # perform query, map resources and create lookup map
        check_results: Dict[str, SingleCheckResult] = defaultdict(lambda: defaultdict(list))
        async with await self.db_access.get_graph_db(graph).search_list(model) as cursor:
            async for entry in cursor:
                if account_id := value_in_path(entry, NodePath.ancestor_account_id):
                    mapped = bend(ReportResourceData, entry)
                    for issue in value_in_path_get(entry, NodePath.security_issues, cast(List[Json], [])):
                        if check := issue.get("check"):
                            check_results[check][account_id].append(mapped)
        return {
            name: self.__to_result(benchmark, check_lookup, check_results, context)
            for name, benchmark in benchmarks.items()
        }

    async def perform_benchmarks(
        self,
        graph: GraphName,
        benchmark_names: List[str],
        *,
        accounts: Optional[List[str]] = None,
        severity: Optional[ReportSeverity] = None,
        only_failing: bool = False,
        sync_security_section: bool = False,
        report_run_id: Optional[str] = None,
    ) -> Dict[str, BenchmarkResult]:
        context = CheckContext(accounts=accounts, severity=severity, only_failed=only_failing)
        benchmarks = {name: await self._benchmark(benchmark_id(name)) for name in benchmark_names}
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
            # In case no run_id is provided, we invent a report run id here.
            run_id = report_run_id or uuid_str()
            await self.db_access.get_graph_db(graph).update_security_section(
                run_id, self.__benchmarks_to_security_iterator(result), model, accounts
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

    async def filter_checks(self, report_filter: Optional[Callable[[ReportCheck], bool]] = None) -> List[ReportCheck]:
        cfg_ids = await self._check_ids()
        list_of_lists = await asyncio.gather(*[self._checks(cfg_id) for cfg_id in cfg_ids])
        return [
            check for entries in list_of_lists for check in entries if report_filter is None or report_filter(check)
        ]

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
        cfg = await self._report_values()
        return await self.__list_failing_resources(graph, model, inspection, cfg, context)

    async def __list_failing_resources(
        self, graph: GraphName, model: Model, inspection: ReportCheck, config: Json, context: CheckContext
    ) -> AsyncIterator[Json]:
        # final environment: defaults are coming from the check and are eventually overriden in the config
        env = inspection.environment(config)
        account_id_prop = "ancestors.account.reported.id"

        async def perform_search(search: str) -> AsyncIterator[Json]:
            # parse query
            query = await self.template_expander.parse_query(search, on_section="reported", env=env)
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
            cli_result = await self.cli.execute_cli_command(cmd, list_sink, CLIContext(env=env))
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

    async def __perform_checks(  # type: ignore
        self, graph: GraphName, checks: List[ReportCheck], context: CheckContext
    ) -> Dict[str, SingleCheckResult]:
        # load model
        model = await self.model_handler.load_model(graph)
        # load configuration
        cfg = await self._report_values()

        async def perform_single(check: ReportCheck) -> Tuple[str, SingleCheckResult]:
            return check.id, await self.__perform_check(graph, model, check, cfg, context)

        check_results: Stream[Tuple[str, SingleCheckResult]] = stream.iterate(checks) | pipe.map(
            perform_single, ordered=False, task_limit=context.parallel_checks  # type: ignore
        )
        async with check_results.stream() as streamer:
            return {key: value async for key, value in streamer}

    async def __perform_check(
        self, graph: GraphName, model: Model, inspection: ReportCheck, config: Json, context: CheckContext
    ) -> SingleCheckResult:
        resources_by_account = defaultdict(list)
        async for resource in await self.__list_failing_resources(graph, model, inspection, config, context):
            account_id = value_in_path(resource, NodePath.ancestor_account_id)
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

    async def validate_benchmark_config(self, cfg_id: ConfigId, json: Json) -> Optional[Json]:
        try:
            benchmark = BenchmarkConfig.from_config(ConfigEntity(ResotoReportBenchmark, json))
            bid = cfg_id.rsplit(".", 1)[-1]
            if benchmark.id != bid:
                return {"error": f"Benchmark id should be {bid} (same as the config name). Got {benchmark.id}"}
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
                    detect = ""
                    if detect := check.detect.get("resoto"):
                        await self.template_expander.parse_query(detect, on_section="reported", env=env)
                    elif detect := check.detect.get("resoto_cmd"):
                        await self.cli.evaluate_cli_command(detect, CLIContext(env=env))
                    elif check.detect.get("manual"):
                        continue
                    else:
                        errors.append(f"Check {check.id} neither has a resoto, resoto_cmd or manual defined")
                    if not check.result_kinds:
                        errors.append(f"Check {check.id} does not define any result kind")
                    for rk in check.result_kinds:
                        if rk not in detect:
                            errors.append(f"Check {check.id} does not detect result kind {rk}")
                    if not check.remediation.text:
                        errors.append(f"Check {check.id} does not define any remediation text")
                    if not check.remediation.url:
                        errors.append(f"Check {check.id} does not define any remediation url")
                    for prop in ["id", "title", "risk", "severity"]:
                        if not getattr(check, prop, None):
                            errors.append(f"Check {check.id} does not define prop {prop}")
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
    ) -> AsyncIterator[Tuple[NodeId, Json]]:
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

        async def iterate_nodes() -> AsyncIterator[Tuple[NodeId, Json]]:
            for node_id, contexts in node_result.items():
                issues = [
                    dict(benchmark=bench.id, check=check.check.id, severity=check.check.severity.name)
                    for bench, check in contexts
                ]
                yield NodeId(node_id), dict(issues=issues)

        return iterate_nodes()


@lru_cache(maxsize=1)
def benchmarks_from_file() -> Dict[ConfigId, Benchmark]:
    result = {}
    for name, js in BenchmarkConfig.from_files().items():
        cid = benchmark_id(name)
        benchmark = BenchmarkConfig.from_config(ConfigEntity(cid, {BenchmarkConfigRoot: js}))
        result[cid] = benchmark
    return result


@lru_cache(maxsize=1)
def checks_from_file() -> Dict[ConfigId, List[ReportCheck]]:
    result = {}
    for name, js in ReportCheckCollectionConfig.from_files().items():
        cid = check_id(name)
        result[cid] = ReportCheckCollectionConfig.from_config(ConfigEntity(cid, {CheckConfigRoot: js}))
    return result


class InspectorFileService(InspectorService):
    async def _report_values(self) -> Json:
        return {}  # default values

    async def _check_ids(self) -> List[ConfigId]:
        return list(checks_from_file().keys())

    async def _checks(self, cfg_id: ConfigId) -> List[ReportCheck]:
        return checks_from_file().get(cfg_id, [])

    async def _benchmark(self, cfg_id: ConfigId) -> Benchmark:
        return benchmarks_from_file()[cfg_id]

    async def list_benchmarks(self) -> List[Benchmark]:
        return list(benchmarks_from_file().values())

    @staticmethod
    def on_startup() -> None:
        # make sure benchmarks and checks are loaded
        benchmarks_from_file()
        checks_from_file()


class InspectorConfigService(InspectorService):
    def __init__(self, cli: CLI) -> None:
        super().__init__(cli)
        self.config_handler: ConfigHandler = cli.dependencies.config_handler

    async def start(self) -> None:
        if not self.cli.dependencies.config.multi_tenant_setup:
            # TODO: we need a migration path for checks added in existing configs
            config_ids = {i async for i in self.config_handler.list_config_ids()}
            overwrite = True  # Only here to simplify development. True until we reach a stable version.
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

    async def _report_values(self) -> Json:
        cfg_entity = await self.config_handler.get_config(ResotoReportValues)
        return cfg_entity.config if cfg_entity else {}

    async def _check_ids(self) -> List[ConfigId]:
        return [i async for i in self.config_handler.list_config_ids() if i.startswith(CheckConfigPrefix)]

    async def _checks(self, cfg_id: ConfigId) -> List[ReportCheck]:
        config = await self.config_handler.get_config(cfg_id)
        if config is not None and CheckConfigRoot in config.config:
            return ReportCheckCollectionConfig.from_config(config)
        else:
            return []

    async def _benchmark(self, cfg_id: ConfigId) -> Benchmark:
        cfg = await self.config_handler.get_config(cfg_id)
        if cfg is None or BenchmarkConfigRoot not in cfg.config:
            raise ValueError(f"Unknown benchmark: {cfg_id}")
        return BenchmarkConfig.from_config(cfg)

    async def list_benchmarks(self) -> List[Benchmark]:
        return [
            await self._benchmark(i)
            async for i in self.config_handler.list_config_ids()
            if i.startswith(BenchmarkConfigPrefix)
        ]
