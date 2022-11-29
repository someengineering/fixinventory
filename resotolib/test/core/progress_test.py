from typing import Callable, Any, List

from pytest import fixture, raises

from resotolib.core.progress import ProgressDone, Progress, ProgressInfo, ProgressTree


@fixture
def progress() -> ProgressTree:
    fp = Progress.from_progresses
    result = fp(
        "aws",
        [
            ProgressDone("region1", 1, 2, path=["account1"]),
            ProgressDone("region2", 2, 2, path=["account1"]),
            ProgressDone("region1", 1, 2, path=["account2"]),
            ProgressDone("region3", 2, 2, path=["account2"]),
            ProgressDone("region2", 1, 2, path=["account3"]),
            ProgressDone("region3", 2, 2, path=["account3"]),
            ProgressDone("extra", 0, 100, path=["some", "deeply", "nested"]),
        ],
    )
    return result


def test_tree() -> None:
    a = ProgressDone("a", 0, 1, path=["cloud", "account", "region"])
    b = ProgressDone("b", 0, 1, path=["cloud", "account", "region"])
    p = Progress.from_progresses("123", [a, b])
    assert len(p.sub_tree.children("root.cloud.account.region")) == 2


def test_info_json() -> None:
    a = ProgressDone("a", 0, 1, path=["cloud", "account", "region"])
    b = ProgressDone("b", 16, 23, path=["cloud", "account", "region"])
    c = ProgressDone("c", 12, 12, path=["cloud", "account", "region"])
    p = Progress.from_progresses("123", [a, b, c])
    assert p.info_json() == {"123": {"cloud": {"account": {"region": {"a": "in progress", "b": "69%", "c": "done"}}}}}


def test_sub_progress(progress: ProgressTree) -> None:
    sub = progress.sub_progress("root.some.deeply")
    assert sub.overall_progress() == ProgressInfo(0, 100)
    assert sub.percentage == 0


def test_progress(progress: Progress) -> None:
    assert progress.overall_progress() == ProgressInfo(225, 400)
    assert progress.percentage == 56


def test_marshalling(progress: Progress) -> None:
    assert Progress.from_json(progress.to_json()).to_json() == progress.to_json()


def test_invalid() -> None:
    with raises(ValueError):
        ProgressDone("region1", 1, 0)


def test_path(progress: ProgressTree) -> None:
    assert progress.has_path("account1.region1")
    res = progress.by_path("account1.region1")
    assert res is not None
    assert res.percentage == 50

    sub = progress.sub_progress("account1")
    assert sub is not None
    assert sub.percentage == 75


def test_equality(progress: ProgressTree) -> None:
    pgc = progress.copy()
    assert pgc == progress
    pgc.add_progress(ProgressDone("region1", 2, 2, path=["account1"]))
    assert pgc != progress


def test_order() -> None:
    def order(key: Callable[[Progress], Any]) -> List[str]:
        pt = ProgressTree("test")
        pt.add_progress(ProgressDone("a", 10, 10))
        pt.add_progress(ProgressDone("b", 8, 10))
        pt.add_progress(ProgressDone("c", 3, 10))
        pt.add_progress(ProgressDone("d", 1, 10))
        js = pt.to_json(key=key)
        return [x["name"] for x in js["parts"]]

    assert order(lambda x: x.name) == ["a", "b", "c", "d"]
    assert order(lambda x: x.overall_progress().percentage) == ["d", "c", "b", "a"]
