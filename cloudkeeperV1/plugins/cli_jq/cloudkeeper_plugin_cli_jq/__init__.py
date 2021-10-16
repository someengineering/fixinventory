import jq
from typing import Iterable
from cklib.baseresources import BaseResource
from cklib.baseplugin import BaseCliPlugin
from cklib.args import ArgumentParser
from cklib.utils import fmt_json, resource2dict


class CliJqPlugin(BaseCliPlugin):
    def cmd_jq(self, items: Iterable, args: str) -> Iterable:
        """Usage: | jq <jq filter> |

        Run jq JSON processor against the input which must
        either be Cloudkeeper resources or a JSON string.
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
