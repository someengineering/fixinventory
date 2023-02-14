from concurrent.futures import ThreadPoolExecutor
from typing import Sequence, Tuple, List, Optional

from resoto_plugin_aws.resource.base import ExecutorQueue, AwsRegion, GraphBuilder
from resoto_plugin_aws.resource.ec2 import AwsEc2InstanceType
from test import account_collector, builder, aws_client, aws_config, no_feedback  # noqa: F401


def check_executor_queue(work: Sequence[int], fail_on_first_exception: bool) -> Tuple[List[int], Optional[Exception]]:
    work_done = []

    def do_work(num: int) -> None:
        if num == 5:
            raise Exception(f"Abort {num}")
        work_done.append(num)

    with ThreadPoolExecutor(max_workers=1) as executor:
        queue = ExecutorQueue(executor, "test", fail_on_first_exception=fail_on_first_exception)
        for idx in work:
            queue.submit_work(do_work, idx)

        try:
            queue.wait_for_submitted_work()
            return work_done, None
        except Exception as ex:
            return work_done, ex


def test_success_queue() -> None:
    work_done, ex = check_executor_queue(range(5), True)
    assert work_done == [0, 1, 2, 3, 4]
    assert ex is None
    work_done, ex = check_executor_queue(range(5), False)
    assert work_done == [0, 1, 2, 3, 4]
    assert ex is None


def test_fail_on_first() -> None:
    work_done, ex = check_executor_queue(range(10), True)
    assert work_done == [0, 1, 2, 3, 4]
    assert ex is not None
    assert ex.args[0] == "Abort 5"


def test_fail_late() -> None:
    work_done, ex = check_executor_queue(range(10), False)
    assert work_done == [0, 1, 2, 3, 4, 6, 7, 8, 9]
    assert ex is not None
    assert ex.args[0] == "Abort 5"


def test_instance_type_handling(builder: GraphBuilder) -> None:
    region1 = AwsRegion(id="us-east-1")
    region2 = AwsRegion(id="us-east-2")
    it = AwsEc2InstanceType(id="t3.micro")
    builder.global_instance_types[it.safe_name] = it
    it1: AwsEc2InstanceType = builder.instance_type(region1, it.safe_name)  # type: ignore
    assert it1.region() == region1
    it2: AwsEc2InstanceType = builder.instance_type(region2, it.safe_name)  # type: ignore
    assert it2.region() == region2
    assert it1 is not it2
    assert it1.chksum != it2.chksum
