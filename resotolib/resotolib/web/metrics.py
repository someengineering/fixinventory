from dataclasses import dataclass, field
import os
from typing import ClassVar, Optional
import cherrypy
from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
from resotolib.config import Config


class WebApp:
    def __init__(self) -> None:
        self.mountpoint = Config.webapp.web_path
        local_path = os.path.abspath(os.path.dirname(__file__))
        config = {
            "tools.gzip.on": True,
            "tools.staticdir.index": "index.html",
            "tools.staticdir.on": True,
            "tools.staticdir.dir": f"{local_path}/static",
        }
        self.config = {"/": config}
        if self.mountpoint not in ("/", ""):
            self.config[self.mountpoint] = config

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

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(WebAppConfig)


@dataclass
class WebAppConfig:
    kind: ClassVar[str] = "webapp"
    web_path: Optional[str] = field(
        default="/", metadata={"description": "Web root in browser"}
    )
