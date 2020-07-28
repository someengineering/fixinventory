from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from socketserver import ThreadingMixIn
from prometheus_client.exposition import generate_latest, CONTENT_TYPE_LATEST
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener, dispatch_event
import json
import falcon
import threading
import logging

log = logging.getLogger(__name__)


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    pass


class CloudkeeperRequestHandler(WSGIRequestHandler):
    pass


class WebServer(threading.Thread):
    """A basic webserver returning some metrics and Graph representations for debugging purposes

    This is just Python's build in web server used to return some light debug and metric information.
    Don't abuse it for heavy workloads!
    """
    def __init__(self, gc) -> None:
        super().__init__()
        self.name = 'webserver'
        api = falcon.API()
        api.add_route('/health', HealthCheck())
        api.add_route('/metrics', Metrics())
        api.add_route('/graph', Remote(gc))
        api.add_route('/collect', Collect())
        api.add_route('/graph.gexf', GEXF(gc))
        api.add_route('/graph.graphml', GraphML(gc))
        api.add_route('/graph.json', JSON(gc))
        api.add_route('/graph.net', Pajek(gc))
        api.add_route('/graph.txt', TXT(gc))
        self.httpd = make_server('', ArgumentParser.args.web_port, api, ThreadingWSGIServer, CloudkeeperRequestHandler)
        add_event_listener(EventType.SHUTDOWN, self.shutdown)

    def __del__(self):
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def run(self) -> None:
        self.httpd.serve_forever()

    def shutdown(self, event: Event):
        log.debug(f'Received request to shutdown http server threads {event.event_type}')
        if self.httpd is not None:
            self.httpd.socket.close()
            self.httpd.shutdown()
        self.httpd = None

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--web-port', help='Web Port (default 8000)', default=8000, dest='web_port', type=int)
        arg_parser.add_argument('--web-psk', help='Pre Shared Key for /collect requests', default=None, dest='web_psk', type=str)


class HealthCheck:
    def on_get(self, req, resp) -> None:
        resp.content_type = 'text/plain'
        resp.body = 'ok\r\n'


class Metrics:
    """Returns Prometheus formated metrics"""
    def on_get(self, req, resp) -> None:
        resp.content_type = CONTENT_TYPE_LATEST
        resp.body = generate_latest()


class Remote:
    """Returns a pickled representation of the current Graph"""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'application/octet-stream'
        resp.body = self.gc.pickle


class GraphML:
    """Returns a GraphML representation of the current Graph"""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'application/xml'
        resp.body = self.gc.graphml


class GEXF:
    """Returns a GEXF representation of the current Graph"""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'application/xml'
        resp.body = self.gc.gexf


class JSON:
    """Returns a JSON representation of the current Graph to be used with e.g. D3.js"""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'application/json'
        resp.body = self.gc.json


class TXT:
    """Returns a human readable text dump of the Graph."""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'text/plain'
        resp.body = self.gc.text


class Pajek:
    """Returns a Pajek representation of the current Graph"""
    def __init__(self, gc) -> None:
        self.gc = gc

    def on_get(self, req, resp) -> None:
        resp.content_type = 'text/plain'
        resp.body = self.gc.pajek


def validate_psk(req, resp, resource, params):
    if ArgumentParser.args.web_psk:
        try:
            data = json.load(req.bounded_stream)
        except json.decoder.JSONDecodeError:
            raise falcon.HTTPUnauthorized('Authentication required')
        else:
            if not isinstance(data, dict) or data.get('psk') != ArgumentParser.args.web_psk:
                raise falcon.HTTPUnauthorized('Invalid PSK')
        return True


class Collect:
    """Start a Collect run"""
    @falcon.before(validate_psk)
    def on_post(self, req, resp) -> None:
        dispatch_event(Event(EventType.START_COLLECT))
        resp.content_type = 'application/json'
        j = json.dumps({'status': 'ok'})
        resp.body = f'{j}\r\n'
