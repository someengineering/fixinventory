from attrs import define
from enum import Enum

from resotolib.types import Json


class Severity(Enum):
    debug = "debug"
    info = "info"
    warn = "warn"
    error = "error"
    critical = "critical"


@define
class Event:
    # who created this message
    origin: str
    # seconds since epoch
    epoch: int
    # severity of this message
    severity: Severity
    # defines the type of the payload (e.g. log)
    kind: str
    # the payload of specific kind
    payload: Json
