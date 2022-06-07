import json
import os

import pytest
from _pytest.fixtures import SubRequest
from resotolib.types import Json


@pytest.fixture
def json_file(request: SubRequest) -> Json:
    for mark in request.node.iter_markers("json_file"):
        path = os.path.abspath(os.path.dirname(__file__) + "/files/" + mark.args[0])
        with open(path) as f:
            content = f.read()
            ks = json.loads(content)
            return ks  # type: ignore
    raise Exception("No json_file mark found")
