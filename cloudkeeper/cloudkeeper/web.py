from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, dispatch_event
from cloudkeeper.utils import get_stats
from typing import Dict
import os
import jwt
import cherrypy
import threading
import cloudkeeper.logging

log = cloudkeeper.logging.getLogger(__name__)


class CloudkeeperWebApp:
    def __init__(self, gc) -> None:
        self.gc = gc

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def health(self):
        cherrypy.response.headers["Content-Type"] = "text/plain"
        return "ok\r\n"

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def metrics(self):
        cherrypy.response.headers["Content-Type"] = CONTENT_TYPE_LATEST
        return generate_latest()

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph(self):
        cherrypy.response.headers["Content-Type"] = "application/octet-stream"
        return self.gc.pickle

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["POST"])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def callback(self):
        jwt_data = self.get_jwt_data(cherrypy.request)
        if jwt_data.get("event") in ("COLLECT_FINISH", "PROCESS_FINISH"):
            dispatch_event(Event(EventType.START_COLLECT))
            return {"status": "ok"}
        return {"status": "unknown event"}

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    @cherrypy.tools.json_out()
    def stats(self):
        return get_stats(self.gc.graph)

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph_gexf(self):
        cherrypy.response.headers["Content-Type"] = "application/xml; charset=utf-8"
        return str(self.gc.gexf).encode("utf-8")

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph_graphml(self):
        cherrypy.response.headers["Content-Type"] = "application/xml; charset=utf-8"
        return str(self.gc.graphml).encode("utf-8")

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph_json(self):
        cherrypy.response.headers["Content-Type"] = "application/json; charset=utf-8"
        return str(self.gc.json).encode("utf-8")

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph_net(self):
        cherrypy.response.headers["Content-Type"] = "text/plain"
        return self.gc.pajek

    @cherrypy.expose
    @cherrypy.tools.allow(methods=["GET"])
    def graph_txt(self):
        cherrypy.response.headers["Content-Type"] = "text/plain"
        return self.gc.text

    @staticmethod
    def get_jwt_data(cherrypy_request) -> Dict:
        data = getattr(cherrypy_request, "json")
        jwt_data = {}
        if not isinstance(data, dict):
            raise cherrypy.HTTPError("400 Invalid JSON request")
        if "jwt" not in data:
            raise cherrypy.HTTPError("400 JWT token missing")
        try:
            jwt_data = jwt.decode(
                data.get("jwt"), ArgumentParser.args.web_psk, algorithms=["HS256"]
            )
        except jwt.PyJWTError as e:
            log.error(f"Rejecting JWT token in incoming callback request: {str(e)}")
            raise cherrypy.HTTPError(f"401 {e}")
        return jwt_data


class WebServer(threading.Thread):
    def __init__(self, gc) -> None:
        super().__init__()
        self.name = "webserver"
        self.gc = gc
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    @property
    def serving(self):
        return cherrypy.engine.state == cherrypy.engine.states.STARTED

    def run(self) -> None:
        local_path = os.path.abspath(os.path.dirname(__file__))
        cherrypy.engine.unsubscribe("graceful", cherrypy.log.reopen_files)
        cherrypy.tree.mount(
            CloudkeeperWebApp(self.gc),
            "/",
            {
                "/": {
                    "tools.gzip.on": True,
                    "tools.staticdir.index": "index.html",
                    "tools.staticdir.on": True,
                    "tools.staticdir.dir": f"{local_path}/static",
                },
            },
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

    def shutdown(self, event: Event):
        log.debug(
            f"Received request to shutdown http server threads {event.event_type}"
        )
        cherrypy.engine.exit()

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--web-port",
            help="Web Port (default 8000)",
            default=8000,
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
        arg_parser.add_argument(
            "--web-psk",
            help="Pre Shared Key for /callback requests",
            default="cloudkeeper",
            dest="web_psk",
            type=str,
        )
