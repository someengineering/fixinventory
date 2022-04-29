import json
from dataclasses import dataclass, field
from typing import ClassVar, Optional, Dict
import sys
import os
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
        "--quiet",
        help="Only log errors",
        dest="quiet",
        action="store_true",
        default=False,
    )


def add_config(config) -> None:
    config.add_config(LoggingConfig)


@dataclass
class LoggingConfig:
    kind: ClassVar[str] = "logging"
    verbose: Optional[bool] = field(
        default=False, metadata={"description": "Verbose logging"}
    )
    quiet: Optional[bool] = field(
        default=False, metadata={"description": "Only log errors"}
    )


class JsonFormatter(Formatter):
    """
    Simple json log formatter.
    Inspired by: https://stackoverflow.com/questions/50144628/python-logging-into-file-as-a-dictionary-or-json
    """

    def __init__(
        self,
        fmt_dict: dict,
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
        return {
            fmt_key: record.__dict__[fmt_val]
            for fmt_key, fmt_val in self.fmt_dict.items()
        }

    def format(self, record) -> str:
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
    if (
        verbose
        or "-v" in argv
        or "--verbose" in argv
        or os.environ.get("RESOTO_VERBOSE", "false").lower() == "true"
    ):
        getLogger("resoto").setLevel(DEBUG)
    elif (
        quiet
        or "--quiet" in argv
        or os.environ.get("RESOTO_QUIET", "false").lower() == "true"
    ):
        getLogger().setLevel(WARNING)
        getLogger("resoto").setLevel(CRITICAL)


setup_logger("resoto", force=False)
log = getLogger("resoto")
