import jq
import cloudkeeper.logging
from typing import Iterable
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.baseplugin import BaseCliPlugin
from cloudkeeper.args import ArgumentParser
from cloudkeeper.utils import fmt_json, resource2dict


log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class CliJqPlugin(BaseCliPlugin):
    def cmd_jq(self, items: Iterable, args: str) -> Iterable:
        """Usage: | jq <jq filter> |

        Run jq JSON processor against the input
        """
        compiled_jq = jq.compile(args)
        for item in items:
            if isinstance(item, BaseResource):
                item = fmt_json(resource2dict(item, True, self.graph))
            elif not isinstance(item, str):
                continue
            yield from compiled_jq.input(text=item).all()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        """Adds Plugin specific arguments to the global arg parser"""
        pass
