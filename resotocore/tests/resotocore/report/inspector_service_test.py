from typing import Dict

from pytest import fixture

from resotocore.cli.cli import CLIService
from resotocore.config import ConfigEntity
from resotocore.db.model import QueryModel
from resotocore.ids import ConfigId, GraphName
from resotocore.query.model import P, Query
from resotocore.report import BenchmarkConfigRoot, CheckConfigRoot, BenchmarkResult
from resotocore.report.inspector_service import (
    InspectorService,
    check_id,
    benchmark_id,
    InspectorConfigService,
    InspectorFileService,
)
from resotocore.report.report_config import (
    config_model,
    ReportCheckCollectionConfig,
    BenchmarkConfig,
)
from resotocore.types import Json
from resotocore.util import partition_by


@fixture
async def inspector_service_with_test_benchmark(
    cli: CLIService, inspection_check_collection: Json, benchmark: Json
) -> InspectorService:
    service = InspectorConfigService(cli)
    await service.config_handler.put_config(ConfigEntity(check_id("test"), inspection_check_collection))
    await service.config_handler.put_config(ConfigEntity(benchmark_id("test"), benchmark))
    return service


@fixture
async def inspector_file_service(cli: CLIService) -> InspectorService:
    return InspectorFileService(cli)


@fixture
def inspection_check_collection() -> Json:
    return dict(
        report_check=dict(
            provider="test",
            service="test",
            checks=[
                dict(
                    title="search",
                    name="search",
                    result_kind="foo",
                    categories=["test"],
                    severity="critical",
                    risk="",
                    # we use a query with a template here
                    detect={"resoto": "is({{foo_kind}})"},
                    default_values={"foo_kind": "foo"},
                    remediation=dict(text="", url="", action={}),
                ),
                dict(
                    title="cmd",
                    name="cmd",
                    result_kind="foo",
                    categories=["test"],
                    severity="critical",
                    detect={"resoto_cmd": "search is(foo) | jq --no-rewrite ."},
                    risk="",
                    remediation=dict(text="", url="", action={}),
                ),
            ],
        )
    )


@fixture
def benchmark() -> Json:
    return dict(
        report_benchmark=dict(
            title="test_benchmark",
            description="test_benchmark",
            id="test",
            framework="test",
            version="1.0",
            checks=["test_test_search", "test_test_cmd"],
            clouds=["test"],
        )
    )


async def test_config_model() -> None:
    models = config_model()
    assert len(models) == 6


async def test_list_inspect_checks(inspector_service: InspectorService) -> None:
    # list all available checks
    all_checks = {i.id: i for i in await inspector_service.list_checks()}
    assert len(all_checks) >= 30

    # use different filter options. The more filter are used, fewer results are returned
    filter_options = dict(
        provider="aws",
        service="ec2",
        category="security",
        kind="aws_ec2_instance",
        check_ids=["aws_ec2_internet_facing_with_instance_profile"],
    )
    last_len = len(all_checks)
    for options in range(1, len(filter_options)):
        args = dict(list(filter_options.items())[0:options])
        matching_checks = [i for i in await inspector_service.list_checks(**args)]  # type: ignore
        assert len(matching_checks) > 0
        assert len(matching_checks) <= last_len
        last_len = len(matching_checks)
    assert last_len < len(all_checks)


async def test_perform_benchmark(inspector_service_with_test_benchmark: InspectorService) -> None:
    def assert_result(results: Dict[str, BenchmarkResult]) -> None:
        result = results["test"]
        assert result.checks[0].number_of_resources_failing == 10
        assert result.checks[1].number_of_resources_failing == 10
        filtered = result.filter_result(filter_failed=True)
        assert filtered.checks[0].number_of_resources_failing == 10
        assert len(filtered.checks[0].resources_failing_by_account["sub_root"]) == 10
        assert filtered.checks[1].number_of_resources_failing == 10
        assert len(filtered.checks[1].resources_failing_by_account["sub_root"]) == 10
        passing, failing = result.passing_failing_checks_for_account("sub_root")
        assert len(passing) == 0
        assert len(failing) == 2
        passing, failing = result.passing_failing_checks_for_account("does_not_exist")
        assert len(passing) == 2
        assert len(failing) == 0

    inspector = inspector_service_with_test_benchmark
    graph_name = GraphName(inspector.cli.env["graph"])
    performed = await inspector.perform_benchmarks(graph_name, ["test"], sync_security_section=True)
    assert_result(performed)

    # make sure the result is persisted as part of the node
    async def count_vulnerable() -> int:
        db = inspector.db_access.get_graph_db(graph_name)
        model = await inspector.model_handler.load_model(graph_name)
        all_vunerable = Query.by(P("security.has_issues") == True)  # noqa
        async with await db.search_list(QueryModel(all_vunerable, model), with_count=True) as cursor:
            return cursor.count()  # type: ignore

    assert await count_vulnerable() == 10

    # loading the result from the db should give the same information
    loaded = await inspector.load_benchmarks(graph_name, ["test"])
    assert_result(loaded)


async def test_benchmark_node_result(inspector_service_with_test_benchmark: InspectorService) -> None:
    inspector = inspector_service_with_test_benchmark
    results = await inspector.perform_benchmarks(inspector.cli.env["graph"], ["test"])
    result = results["test"]
    node_edge_list = result.to_graph()
    nodes, edges = partition_by(lambda x: x["type"] == "node", node_edge_list)
    assert len(node_edge_list) == 5  # 3 nodes + 2 edges
    assert len(nodes) == 3
    assert len(edges) == 2
    for edge in edges:
        assert edge["from"] == result.node_id


async def test_predefined_checks(inspector_service: InspectorService) -> None:
    checks = ReportCheckCollectionConfig.from_files()
    assert len(checks) > 0
    for name, check in checks.items():
        validation = await inspector_service.validate_check_collection_config({CheckConfigRoot: check})
        assert validation is None, str(validation)


async def test_predefined_benchmarks(inspector_service: InspectorService) -> None:
    benchmarks = BenchmarkConfig.from_files()
    assert len(benchmarks) > 0
    for name, check in benchmarks.items():
        config = {BenchmarkConfigRoot: check}
        cfg_id = ConfigId(name)
        validation = await inspector_service.validate_benchmark_config(cfg_id, config)
        assert validation is None, f"Benchmark: {name}" + str(validation)
        benchmark = BenchmarkConfig.from_config(ConfigEntity(cfg_id, config))
        assert benchmark.clouds == ["aws"]


async def test_list_failing(inspector_service_with_test_benchmark: InspectorService) -> None:
    inspector = inspector_service_with_test_benchmark
    graph = inspector.cli.env["graph"]
    search_res = [r async for r in await inspector.list_failing_resources(graph, "test_test_search")]
    assert len(search_res) == 10
    cmd_res = [r async for r in await inspector.list_failing_resources(graph, "test_test_cmd")]
    assert len(cmd_res) == 10
    search_res_account = [r async for r in await inspector.list_failing_resources(graph, "test_test_search", ["n/a"])]
    assert len(search_res_account) == 0
    cmd_res_account = [r async for r in await inspector.list_failing_resources(graph, "test_test_cmd", ["n/a"])]
    assert len(cmd_res_account) == 0


async def test_file_inspector(inspector_file_service: InspectorService) -> None:
    assert len(await inspector_file_service.list_benchmarks()) >= 1
    assert len(await inspector_file_service.filter_checks()) >= 100
    aws_cis = await inspector_file_service.benchmark("aws_cis_1_5")
    assert aws_cis is not None
