from enum import Enum
from collections import namedtuple


class EdgeType(Enum):
    default = "default"
    delete = "delete"
    start = "start"
    stop = "stop"


EdgeKey = namedtuple("EdgeKey", ["src", "dst", "edge_type"])
