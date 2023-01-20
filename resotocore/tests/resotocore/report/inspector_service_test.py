from pytest import fixture

from resotocore.cli.cli import CLI
from resotocore.config import ConfigEntity
from resotocore.report.inspector_service import InspectorService, check_id, benchmark_id
from resotocore.report.report_config import config_model
from resotocore.types import Json


@fixture
async def inspector_service_with_test_benchmark(
    cli: CLI, inspection_check_collection: Json, benchmark: Json
) -> InspectorService:
    service = InspectorService(cli)
    await service.config_handler.put_config(ConfigEntity(check_id("test"), inspection_check_collection))
    await service.config_handler.put_config(ConfigEntity(benchmark_id("test"), benchmark))
    return service


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
            id="test_benchmark",
            framework="test",
            version="1.0",
            checks=["test_test_search", "test_test_cmd"],
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
    inspector = inspector_service_with_test_benchmark
    result = await inspector.perform_benchmark("test", inspector.cli.cli_env["graph"])
    assert result.passed is False
    assert result.number_of_resources_failing == 22
    assert result.checks[0].number_of_resources_failing == 11
    assert result.checks[0].passed is False
    assert result.checks[1].number_of_resources_failing == 11
    assert result.checks[1].passed is False
