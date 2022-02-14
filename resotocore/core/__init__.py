from importlib.metadata import version as meta_version

# pylint: disable=pointless-string-statement
"""
Resoto core graph platform
~~~~~~~~~~~~~~~~~~~~~~~~~~
Keeps all the things in Resoto.
:copyright: © 2022 Some Engineering Inc.
:license: Apache 2.0, see LICENSE for more details.
"""

__title__ = "resotocore"
__description__ = "resoto core."
__author__ = "Some Engineering Inc."
__license__ = "Apache 2.0"
__copyright__ = "Copyright © 2022 Some Engineering Inc."
__version__ = meta_version(__name__)


def version() -> str:
    return __version__
