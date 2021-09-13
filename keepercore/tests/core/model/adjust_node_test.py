from datetime import datetime

from typing import Optional

from core.model.adjust_node import DirectAdjuster, NoAdjust
from core.types import Json
from core.util import utc_str, value_in_path


def test_adjust_expired() -> None:
    adjuster = DirectAdjuster()
    created_at = datetime(2021, 1, 1)
    expires_at = datetime(2022, 2, 1)

    def expect_expires(reported: Json, expires: Optional[str]) -> None:
        result = adjuster.adjust({"reported": reported})
        assert value_in_path(result, ["metadata", "expires"]) == expires

    # test iso datetime
    expect_expires({"tags": {"expires": utc_str(expires_at)}}, "2022-02-01T00:00:00Z")
    expect_expires({"tags": {"cloudkeeper:expires": utc_str(expires_at)}}, "2022-02-01T00:00:00Z")
    expect_expires({"tags": {"expiration": utc_str(expires_at)}}, "2022-02-01T00:00:00Z")
    expect_expires({"tags": {"cloudkeeper:expiration": utc_str(expires_at)}}, "2022-02-01T00:00:00Z")

    # test duration
    reported: Json = {"ctime": utc_str(created_at)}
    expect_expires(reported | {"tags": {"expires": "never"}}, None)  # never can not be parsed
    expect_expires({"tags": {"expires": "2w3d4h5m"}}, None)  # no ctime given
    expect_expires(reported | {"tags": {"expires": "23h"}}, "2021-01-01T23:00:00Z")
    expect_expires(reported | {"tags": {"expires": "2w3d4h5m"}}, "2021-01-18T04:05:00Z")
    expect_expires(reported | {"tags": {"cloudkeeper:expires": "2w3d4h5m"}}, "2021-01-18T04:05:00Z")
    expect_expires(reported | {"tags": {"cloudkeeper:expiration": "2w3d4h5m"}}, "2021-01-18T04:05:00Z")
    expect_expires(reported | {"tags": {"expiration": "2w3d4h5m"}}, "2021-01-18T04:05:00Z")

    # multiple values given: use order: ck:expiration -> ck:expires -> expiration -> expires
    expect_expires(
        reported
        | {
            "tags": {
                "expires": "4h",
                "expiration": "2021-01-01T11:20:00Z",
                "cloudkeeper:expires": "2h",
                "cloudkeeper:expiration": "2w3d4h5m",
            }
        },
        "2021-01-18T04:05:00Z",
    )

    # no tags given
    expect_expires({}, None)


def test_no_adjust() -> None:
    adjuster = NoAdjust()
    created_at = datetime(2021, 1, 1)
    expires_at = datetime(2022, 2, 1)
    reported: Json = {"ctime": utc_str(created_at)}

    def expect_expires(reported: Json, expires: Optional[str]) -> None:
        result = adjuster.adjust({"reported": reported})
        assert value_in_path(result, ["metadata", "expires"]) == expires

    expect_expires({"tags": {"expires": utc_str(expires_at)}}, None)
    expect_expires(reported | {"tags": {"cloudkeeper:expires": "2w3d4h5m"}}, None)
