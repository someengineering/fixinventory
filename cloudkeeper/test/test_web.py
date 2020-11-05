import socket
import requests
import time
import cloudkeeper.logging as logging
from cloudkeeper.args import ArgumentParser, get_arg_parser
from cloudkeeper.event import add_args as event_add_args, Event, EventType
from cloudkeeper.web import WebServer, CloudkeeperWebApp
from cloudkeeper.graph import GraphContainer

logging.getLogger("cloudkeeper").setLevel(logging.DEBUG)


def test_web():
    arg_parser = get_arg_parser()
    WebServer.add_args(arg_parser)
    event_add_args(arg_parser)
    arg_parser.parse_args()

    gc = GraphContainer(cache_graph=False)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("", 0))
    _, free_port = tcp.getsockname()
    ArgumentParser.args.web_port = free_port
    tcp.close()
    # todo: race between closing socket and reusing free port in WebServer

    web_server = WebServer(CloudkeeperWebApp(gc))
    web_server.daemon = True
    web_server.start()
    start_time = time.time()
    while not web_server.serving:
        if time.time() - start_time > 10:
            raise RuntimeError("timeout waiting for web server start")
        time.sleep(0.1)

    endpoint = f"http://localhost:{free_port}"
    r = requests.get(f"{endpoint}/health")
    assert r.content == b"ok\r\n"
    web_server.shutdown(Event(EventType.SHUTDOWN))
