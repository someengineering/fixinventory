from typing import List

import pytest
from fixcore.report import ReportCheck
from fixcore.report.report_config import ReportCheckCollectionConfig
from fixcore.types import Json
from fixlib.json import to_json


def test_report_config(inspection_checks: List[ReportCheck]) -> None:
    valid_js: List[Json] = to_json(inspection_checks)  # type: ignore
    for a in valid_js:
        a["name"] = a.pop("id")
    icj = {"provider": "a", "service": "b", "checks": valid_js}
    ReportCheckCollectionConfig.from_json(icj)
    with pytest.raises(Exception):
        ReportCheckCollectionConfig.from_json({"provider": "a", "service": "b", "checks": [{}]})
