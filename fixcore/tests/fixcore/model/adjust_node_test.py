import re
from datetime import datetime

from typing import Optional, Union, Pattern, Any

from fixcore.model.adjust_node import DirectAdjuster, NoAdjust
from fixcore.types import Json
from fixcore.util import utc_str, value_in_path


def test_adjust_expired() -> None:
    adjuster = DirectAdjuster()
    created_at = datetime(2021, 1, 1)
    expires_at = datetime(2022, 2, 15, 13)

    def expect_expires(reported: Json, expires: Optional[Union[str, Pattern[Any]]]) -> None:
        result = adjuster.adjust({"reported": reported})
        if expires is None:
            assert value_in_path(result, ["metadata", "expires"]) is None
        elif isinstance(expires, str):
            assert value_in_path(result, ["metadata", "expires"]) == expires
        elif isinstance(expires, Pattern):
            value = value_in_path(result, ["metadata", "expires"])
            assert value is not None
            assert expires.fullmatch(value)

    # test iso datetime
    expect_expires({"tags": {"fix:expires": utc_str(expires_at)}}, "2022-02-15T13:00:00Z")
    expect_expires({"tags": {"fix:expires": expires_at.isoformat()}}, re.compile("2022-02-1.*"))
    expect_expires({"tags": {"fix:expires": "15.02.2022"}}, re.compile("2022-02-1.*"))
    expect_expires({"tags": {"fix:expires": "02/15/2022"}}, re.compile("2022-02-1.*"))
    expect_expires({"tags": {"fix:expires": "+2d"}}, None)  # ony accept absolute time
    expect_expires({"tags": {"fix:expires": "never"}}, None)  # never can not be parsed

    # test duration
    reported: Json = {"ctime": utc_str(created_at)}
    expect_expires({**reported, "tags": {"expiration": "never"}}, None)  # never can not be parsed
    expect_expires({**reported, "tags": {"fix:expiration": "never"}}, None)  # never can not be parsed
    expect_expires({"tags": {"fix:expiration": "12h"}}, None)  # no ctime given
    expect_expires({"tags": {"expiration": "2mo3d4h5min"}}, None)  # no ctime given
    expect_expires({**reported, "tags": {"fix:expiration": "2mo3d4h5min"}}, "2021-03-07T04:05:00Z")
    expect_expires({**reported, "tags": {"expiration": "2mo3d4h5min"}}, "2021-03-07T04:05:00Z")

    # multiple values given: use order: ck:expiration -> ck:expires -> expiration -> expires
    expect_expires(
        {
            **reported,
            "tags": {
                "expiration": "2d",
                "fix:expires": "2021-01-01T11:20:00Z",
                "fix:expiration": "2w3d4h5m",
            },
        },
        "2021-01-01T11:20:00Z",
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
    expect_expires({"tags": {"fix:expires": "2w3d4h5m"}, **reported}, None)
