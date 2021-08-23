"""
Cloudkeeper CLI
~~~~~~~~~~~~~~~
A commandline interpreter to interact with cloudkeeper.
:copyright: (c) 2021 Some Engineering Inc.
:license: Apache 2.0, see LICENSE for more details.
"""

__title__ = "cloudkeeper-cli"
__author__ = "Some Engineering Inc."
__license__ = "Apache 2.0"
__copyright__ = "Copyright 2021 Some Engineering Inc."
__version__ = "0.0.1a"

from typing import NamedTuple, Literal


class VersionInfo(NamedTuple):
    major: int
    minor: int
    micro: int
    releaselevel: Literal["alpha", "beta", "candidate", "final"]
    serial: int


version_info: VersionInfo = VersionInfo(
    major=2, minor=0, micro=0, releaselevel="alpha", serial=0
)
