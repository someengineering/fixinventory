import logging
from resotolib.logger import log, JsonFormatter


def test_logging():
    assert type(log) is logging.Logger


def test_json_logging() -> None:
    format = JsonFormatter({"level": "levelname", "message": "message"})
    record = logging.getLogger().makeRecord("test", logging.INFO, "test", 1, "test message", (), None)
    assert format.format(record) == '{"level": "INFO", "message": "test message"}'
