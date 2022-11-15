import json
from attrs import define, field
from typing import ClassVar, Optional, Dict, Mapping
import sys
import os
import logging
from logging import (
    basicConfig,
    getLogger,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
    StreamHandler,
    Formatter,
)


from resotolib.args import ArgumentParser
from resotolib.types import Json

DEBUG2 = DEBUG - 1
DEBUG3 = DEBUG - 2
DEBUG4 = DEBUG - 3
DEBUG5 = DEBUG - 4
TRACE = DEBUG - 5

getLogger().setLevel(ERROR)
getLogger("resoto").setLevel(INFO)


def add_args(arg_parser: ArgumentParser) -> None:
    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )
    group.add_argument(
        "--trace",
        help="Trage logging",
        dest="trace",
        action="store_true",
        default=False,
    )
    group.add_argument(
        "--quiet",
        help="Only log errors",
        dest="quiet",
        action="store_true",
        default=False,
    )


def add_config(config) -> None:
    config.add_config(LoggingConfig)


@define
class LoggingConfig:
    kind: ClassVar[str] = "logging"
    verbose: Optional[bool] = field(default=False, metadata={"description": "Verbose logging"})
    quiet: Optional[bool] = field(default=False, metadata={"description": "Only log errors"})


class JsonFormatter(Formatter):
    """
    Simple json log formatter.
    Inspired by: https://stackoverflow.com/questions/50144628/python-logging-into-file-as-a-dictionary-or-json
    """

    def __init__(
        self,
        fmt_dict: Mapping[str, str],
        time_format: str = "%Y-%m-%dT%H:%M:%S",
        static_values: Optional[Dict[str, str]] = None,
    ):
        super().__init__()
        self.fmt_dict = fmt_dict
        self.time_format = time_format
        self.static_values = static_values or {}
        self.__use_time = "asctime" in self.fmt_dict.values()

    def usesTime(self) -> bool:  # noqa: N802
        return self.__use_time

    def formatMessage(self, record) -> dict:  # noqa: N802
        return {fmt_key: record.__dict__[fmt_val] for fmt_key, fmt_val in self.fmt_dict.items()}

    def formatJsonMessage(self, record) -> Json:  # noqa: N802
        record.message = record.getMessage()

        if self.__use_time:
            record.asctime = self.formatTime(record, self.time_format)

        message_dict = self.formatMessage(record)
        message_dict.update(self.static_values)

        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)

        if record.exc_text:
            message_dict["exception"] = record.exc_text

        if record.stack_info:
            message_dict["stack_info"] = self.formatStack(record.stack_info)
        return message_dict

    def format(self, record) -> str:
        message_dict = self.formatJsonMessage(record)
        return json.dumps(message_dict, default=str)


def setup_logger(
    proc: str,
    *,
    force: bool = True,
    verbose: bool = False,
    quiet: bool = False,
    level: Optional[str] = None,
    json_format: bool = True,
) -> None:
    # override log output via env var
    plain_text = os.environ.get("RESOTO_LOG_TEXT", "false").lower() == "true"
    if json_format and not plain_text:
        handler = StreamHandler()
        formatter = JsonFormatter(
            {
                "timestamp": "asctime",
                "level": "levelname",
                "message": "message",
                "pid": "process",
                "thread": "threadName",
            },
            static_values={"process": proc},
        )
        handler.setFormatter(formatter)
        basicConfig(handlers=[handler], force=force, level=level)
    else:
        log_format = f"%(asctime)s|{proc}|%(levelname)5s|%(process)d|%(threadName)10s  %(message)s"
        # allow to define the log format via env var
        log_format = os.environ.get("RESOTO_LOG_FORMAT", log_format)
        basicConfig(format=log_format, datefmt="%y-%m-%d %H:%M:%S", force=force)
    argv = sys.argv[1:]
    if level:
        getLogger("resoto").setLevel(level)
    elif "--trace" in argv or os.environ.get("RESOTO_TRACE", "false").lower() == "true":
        getLogger("resoto").setLevel(TRACE)
    elif verbose or "-v" in argv or "--verbose" in argv or os.environ.get("RESOTO_VERBOSE", "false").lower() == "true":
        getLogger("resoto").setLevel(DEBUG)
    elif quiet or "--quiet" in argv or os.environ.get("RESOTO_QUIET", "false").lower() == "true":
        getLogger().setLevel(WARNING)
        getLogger("resoto").setLevel(CRITICAL)


# via https://stackoverflow.com/a/35804945/92184
def add_logging_level(level_name: str, level_num: int, method_name: Optional[str] = None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> add_logging_level("TRACE", logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace("that worked")
    >>> logging.trace("so did this")
    >>> logging.TRACE
    5

    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError("{} already defined in logging module".format(level_name))
    if hasattr(logging, method_name):
        raise AttributeError("{} already defined in logging module".format(method_name))
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError("{} already defined in logger class".format(method_name))

    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, **kwargs)

    def log_to_root(message, *args, **kwargs):
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)


add_logging_level("DEBUG2", DEBUG2)
add_logging_level("DEBUG3", DEBUG3)
add_logging_level("DEBUG4", DEBUG4)
add_logging_level("DEBUG5", DEBUG5)
add_logging_level("TRACE", TRACE)

setup_logger("resoto", force=False)
log = getLogger("resoto")
