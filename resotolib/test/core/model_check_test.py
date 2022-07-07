import os
from abc import ABC
from attrs import define
from typing import ClassVar

import pytest
from pytest import raises

from resotolib.baseresources import BaseResource
from resotolib.core.model_check import check_overlap


@define(slots=False)
class BreakingResource(BaseResource, ABC):
    kind: ClassVar[str] = "breaking"
    volume_size: str = ""


@pytest.mark.skipif(os.environ.get("MODEL_CHECK") is None, reason="Model check is disabled")
def test_check() -> None:
    # this will throw an exception, since breaking resource has a breaking property
    with raises(Exception):
        check_overlap()
    # hacky way to "delete" the fields - the exporter will not see the field any longer.
    BreakingResource.__attrs_attrs__ = {}
    check_overlap()
