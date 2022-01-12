import logging
from resotolib.logging import log


def test_logging():
    assert type(log) is logging.Logger
