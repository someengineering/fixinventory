import socket
import requests
import cloudkeeper.logging as logging
from cloudkeeper.args import ArgumentParser, get_arg_parser
from cloudkeeper.event import add_args as event_add_args
from cloudkeeper.web import WebServer
from cloudkeeper.graph import GraphContainer
logging.getLogger('cloudkeeper').setLevel(logging.DEBUG)


def test_web():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    _, free_port = tcp.getsockname()
    tcp.close()
    # fixme: race
    arg_parser = get_arg_parser()
    WebServer.add_args(arg_parser)
    event_add_args(arg_parser)
    arg_parser.parse_args()

    ArgumentParser.args.web_port = free_port

    gc = GraphContainer(cache_graph=False)
    web_server = WebServer(gc)
    web_server.daemon = True
    web_server.start()

    endpoint = f'http://localhost:{free_port}'

    r = requests.get(f'{endpoint}/health')
    assert r.content == b'ok\r\n'
