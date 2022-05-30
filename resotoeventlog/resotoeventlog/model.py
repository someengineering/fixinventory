from argparse import Namespace
from ssl import SSLContext, create_default_context, Purpose
from typing import Optional

from resotolib.core import ResotocoreURI
from resotolib.core.ca import TLSData


class LogConfig:
    def __init__(self, args: Namespace):
        self.args = args
        self.core_uri = ResotocoreURI(args.resotocore_uri)

    @property
    def host(self) -> str:
        return self.args.host  # type: ignore

    @property
    def port(self) -> int:
        return self.args.port  # type: ignore

    def use_tls(self) -> bool:
        return self.core_uri.is_secure and not self.args.no_tls

    def use_core_cert(self) -> bool:
        return self.args.cert is None

    @property
    def ssl_context(self) -> Optional[SSLContext]:
        if self.use_tls():
            if self.args.cert is not None:
                # noinspection PyTypeChecker
                ctx = create_default_context(Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(self.args.cert, self.args.cert_key, self.args.cert_key_pass)
                return ctx
            else:
                tls = TLSData(common_name="resotoeventlog", resotocore_uri=self.core_uri.http_uri)
                # noinspection PyTypeChecker
                ctx = create_default_context(Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(tls.cert_path, tls.key_path)
                # TODO: renew ssl context
                return ctx
        else:
            return None


class RestartService(SystemExit):
    code = 1

    def __init__(self, reason: str) -> None:
        super().__init__(f"RestartService due to: {reason}")
        self.reason = reason
