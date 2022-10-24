from pytest import fixture, raises

from resotolib.core.progress import ProgressDone, ProgressList, Progress, ProgressInfo


@fixture
def progress() -> Progress:
    return ProgressList(
        "aws",
        [
            ProgressList("account 1", [ProgressDone("region1", 1, 2), ProgressDone("region2", 2, 2)]),
            ProgressList("account 2", [ProgressDone("region1", 0, 2), ProgressDone("region3", 0, 2)]),
            ProgressList("account 3", [ProgressDone("region2", 0, 100), ProgressDone("region3", 0, 200)]),
        ],
    )


def test_progress(progress: Progress) -> None:
    assert progress.overall_progress() == ProgressInfo(300, 1200)
    assert progress.percentage == 25


def test_marshalling(progress: Progress) -> None:
    assert Progress.from_json(progress.to_json()) == progress


def test_invalid() -> None:
    with raises(ValueError):
        ProgressDone("region1", 1, 0)
