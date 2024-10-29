from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Sequence, Tuple, List, Optional, Callable, Any

from more_itertools import flatten

from fix_plugin_aws.resource.base import AwsRegion, GraphBuilder
from fix_plugin_aws.resource.ec2 import AwsEc2InstanceType
from fixlib.threading import ExecutorQueue, GatherFutures
from test import account_collector, builder, aws_client, aws_config, no_feedback  # noqa: F401


def check_executor_work(
    work: List[Tuple[str, int]],
    workers: int,
    tasks_per_key: int,
    fail_on_first_exception: bool,
    check_in_progress: Optional[Callable[[set[int]], None]] = None,
) -> Tuple[List[int], Optional[Exception]]:
    work_done = []
    in_progress = set()

    def do_work(num: int) -> None:
        in_progress.add(num)
        if check_in_progress:
            check_in_progress(in_progress)
        in_progress.remove(num)
        if num % 100 == 5:
            raise Exception(f"Abort {num}")
        work_done.append(num)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        queue = ExecutorQueue(
            executor, "test", lambda _: tasks_per_key, fail_on_first_exception_in_group=fail_on_first_exception
        )
        for key, idx in work:
            queue.submit_work(key, do_work, idx)

        try:
            queue.wait_for_submitted_work()
            return work_done, None
        except Exception as ex:
            return work_done, ex


def check_executor_queue(work: Sequence[int], fail_on_first_exception: bool) -> Tuple[List[int], Optional[Exception]]:
    return check_executor_work([("same_key", i) for i in work], 1, 1, fail_on_first_exception)


def test_parallel_work() -> None:
    def assert_one_per_key(in_progress: set[int]) -> None:
        assert len([a for a in in_progress if a < 100]) <= 2
        assert len([a for a in in_progress if a > 100]) <= 2

    # create work with 2 keys: w1(<100) and w2(>100)
    work = flatten([[("w1", i), ("w2", i + 100)] for i in range(10)])
    # test with 4 worker threads and max 2 tasks per key
    work_done, ex = check_executor_work(list(work), 4, 2, False, assert_one_per_key)
    assert ex is not None
    assert set(work_done) == {0, 1, 2, 3, 100, 101, 102, 103, 104, 4, 106, 6, 107, 7, 108, 8, 9, 109}


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


def test_future_gatherer() -> None:
    def do_work(num: int) -> int:
        # sleep(0.1)
        return num

    groups = []

    def check_done(f: Future[Any]) -> None:
        groups.append(f)

    with ThreadPoolExecutor(max_workers=1) as executor:
        work = defaultdict(list)
        for i in range(100):
            work[i % 10].append(executor.submit(do_work, i))

        for group in work.values():
            GatherFutures.all(group).add_done_callback(check_done)
    assert len(groups) == 10
