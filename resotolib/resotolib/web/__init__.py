import threading
import cherrypy
from resotolib.args import ArgumentParser
from resotolib.logging import log


class WebServer(threading.Thread):
    def __init__(self, webapp) -> None:
        super().__init__()
        self.name = "webserver"
        self.webapp = webapp

    @property
    def serving(self):
        return cherrypy.engine.state == cherrypy.engine.states.STARTED

    def run(self) -> None:
        # CherryPy always prefixes its log messages with a timestamp.
        # The next line monkey patches that time method to return a
        # fixed string. So instead of having duplicate timestamps in
        # each web server related log message they are now prefixed
        # with the string 'CherryPy'.
        cherrypy._cplogging.LogManager.time = lambda self: "CherryPy"
        cherrypy.engine.unsubscribe("graceful", cherrypy.log.reopen_files)

        # We always mount at / as well as any user configured --web-path
        cherrypy.tree.mount(
            self.webapp,
            "",
            self.webapp.config,
        )
        if self.webapp.mountpoint not in ("/", ""):
            cherrypy.tree.mount(
                self.webapp,
                self.webapp.mountpoint,
                self.webapp.config,
            )
        cherrypy.config.update(
            {
                "global": {
                    "engine.autoreload.on": False,
                    "server.socket_host": ArgumentParser.args.web_host,
                    "server.socket_port": ArgumentParser.args.web_port,
                    "log.screen": False,
                    "log.access_file": "",
                    "log.error_file": "",
                    "tools.log_headers.on": False,
                    "tools.encode.on": True,
                    "tools.encode.encoding": "utf-8",
                    "request.show_tracebacks": False,
                    "request.show_mismatched_params": False,
                }
            }
        )
        cherrypy.engine.start()
        cherrypy.engine.block()

    def shutdown(self):
        log.debug("Received request to shutdown http server threads")
        cherrypy.engine.exit()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--web-port",
            help="Web Port (default 9955)",
            default=9955,
            dest="web_port",
            type=int,
        )
        arg_parser.add_argument(
            "--web-host",
            help="IP to bind to (default: ::)",
            default="::",
            dest="web_host",
            type=str,
        )
