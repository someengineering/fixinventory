from attr import evolve

from resotocore.inspect import InspectionCheck
from resotocore.inspect.inspector_service import InspectorService
from tests.resotocore.db.entitydb import InMemoryDb
from pytest import fixture


@fixture
def inspector_service() -> InspectorService:
    return InspectorService(InMemoryDb(InspectionCheck, lambda k: k.id))


async def test_get_inspect_check(inspector_service: InspectorService) -> None:
    aws_ec2_snapshot_encrypted = await inspector_service.get("aws_ec2_snapshot_encrypted")
    assert aws_ec2_snapshot_encrypted is not None
    not_existent = await inspector_service.get("does not exist")
    assert not_existent is None


async def test_list_inspect_checks(inspector_service: InspectorService) -> None:
    # list all available checks
    all_checks = {i.id: i for i in await inspector_service.list()}
    assert len(all_checks) >= 30
    # modify an existing check
    await inspector_service.update(evolve(all_checks["aws_ec2_snapshot_encrypted"], title="test"))
    all_checks_again = {i.id: i for i in await inspector_service.list()}
    # the list of available checks did not change
    assert all_checks_again.keys() == all_checks.keys()
    # the modified check is modified
    assert all_checks_again["aws_ec2_snapshot_encrypted"].title == "test"

    # list by provider
    aws = {i.id: i for i in await inspector_service.list(provider="aws")}
    aws_ec2 = {i.id: i for i in await inspector_service.list(provider="aws", service="ec2")}
    aws_ec2_cost = {i.id: i for i in await inspector_service.list(provider="aws", service="ec2", category="cost")}
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
