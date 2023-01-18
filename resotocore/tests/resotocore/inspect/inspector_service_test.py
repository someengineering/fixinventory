from typing import List

from attr import evolve
from pytest import fixture

from resotocore.cli.cli import CLI
from resotocore.config import ConfigEntity
from resotocore.inspect import InspectionCheck, InspectionSeverity, Remediation, Benchmark
from resotocore.inspect.inspector_service import InspectorService, config_id, CheckConfigRoot
from resotocore.model.typed_model import to_js

# noinspection PyUnresolvedReferences
from tests.resotocore.db.graphdb_test import (
    filled_graph_db,
    graph_db,
    test_db,
    foo_kinds,
    foo_model,
    local_client,
    system_db,
)

# noinspection PyUnresolvedReferences
from tests.resotocore.web.certificate_handler_test import cert_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.config.config_handler_service_test import config_handler

# noinspection PyUnresolvedReferences
from tests.resotocore.worker_task_queue_test import worker, task_queue, performed_by, incoming_tasks

# noinspection PyUnresolvedReferences
from tests.resotocore.analytics import event_sender

# noinspection PyUnresolvedReferences
from tests.resotocore.query.template_expander_test import expander

# noinspection PyUnresolvedReferences
from tests.resotocore.message_bus_test import message_bus

# noinspection PyUnresolvedReferences
from tests.resotocore.cli.cli_test import cli, cli_deps


@fixture
def inspector_service(cli: CLI) -> InspectorService:
    return InspectorService(cli)


@fixture
def inspection_checks() -> List[InspectionCheck]:
    return [
        InspectionCheck(
            id="test_search",
            provider="test",
            service="test",
            title="test",
            kind="foo",
            categories=["test"],
            severity=InspectionSeverity.critical,
            detect={"resoto": "is(foo)"},
            remediation=Remediation({}, "", ""),
        ),
        InspectionCheck(
            id="test_cmd",
            provider="test",
            service="test",
            title="test",
            kind="foo",
            categories=["test"],
            severity=InspectionSeverity.critical,
            detect={"resoto_cmd": "search is(foo) | jq --no-rewrite ."},
            remediation=Remediation({}, "", ""),
        ),
    ]


@fixture
def benchmark(inspection_checks: List[InspectionCheck]) -> Benchmark:
    return Benchmark(
        title="test_benchmark",
        description="test_benchmark",
        id="test_benchmark",
        framework="test",
        version="1.0",
        checks=[c.id for c in inspection_checks],
    )


async def test_list_inspect_checks(inspector_service: InspectorService) -> None:
    # list all available checks
    all_checks = {i.id: i for i in await inspector_service.list_checks()}
    assert len(all_checks) >= 30
    # modify an existing check

    aws_ec2_encrypted_js = to_js(evolve(all_checks["aws_ec2_snapshot_encrypted"], title="test"))
    entity = ConfigEntity(config_id("aws_ec2_snapshot_encrypted"), {CheckConfigRoot: aws_ec2_encrypted_js})
    await inspector_service.config_handler.put_config(entity)
    all_checks_again = {i.id: i for i in await inspector_service.list_checks()}
    # the list of available checks did not change
    assert all_checks_again.keys() == all_checks.keys()
    # the modified check is modified
    assert all_checks_again["aws_ec2_snapshot_encrypted"].title == "test"

    # list by provider
    aws = {i.id: i for i in await inspector_service.list_checks(provider="aws")}
    aws_ec2 = {i.id: i for i in await inspector_service.list_checks(provider="aws", service="ec2")}
    aws_ec2_cost = {
        i.id: i for i in await inspector_service.list_checks(provider="aws", service="ec2", category="cost")
    }
    assert len(aws) >= 10
    for a in aws.values():
        assert a.provider == "aws"
    assert len(aws) > len(aws_ec2)
    for a in aws_ec2.values():
        assert a.provider == "aws"
        assert a.service == "ec2"
    assert len(aws_ec2) > len(aws_ec2_cost)
    for a in aws_ec2_cost.values():
        assert a.provider == "aws"
        assert a.service == "ec2"
        assert "cost" in a.categories


async def test_perform_benchmark(
    inspector_service: InspectorService, inspection_checks: List[InspectionCheck], benchmark: Benchmark
) -> None:
    inspector_service.predefined_inspections = {i.id: i for i in inspection_checks}
    inspector_service.benchmarks = {benchmark.id: benchmark}
    result = await inspector_service.perform_benchmark(benchmark.id, inspector_service.cli.cli_env["graph"])
    assert result.passed is False
    assert result.number_of_resources_failing == 22
    assert result.checks[0].number_of_resources_failing == 11
    assert result.checks[0].passed is False
    assert result.checks[1].number_of_resources_failing == 11
    assert result.checks[1].passed is False
