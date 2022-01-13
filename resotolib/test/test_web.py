import socket
import requests
import time
from resotolib.args import ArgumentParser
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp


def test_web():
    arg_parser = ArgumentParser(
        description="resoto metrics exporter", env_args_prefix="RESOTOMETRICS_"
    )
    WebServer.add_args(arg_parser)
    WebApp.add_args(arg_parser)
    arg_parser.parse_args()

    # Find a free local port to reuse when we bind the web server.
    # This is so that multiple builds/tests can run in parallel
    # on the same CI agent.
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("", 0))
    _, free_port = tcp.getsockname()
    ArgumentParser.args.web_port = free_port
    tcp.close()
    # todo: race between closing socket and reusing free port in WebServer

    web_server = WebServer(WebApp())
    web_server.daemon = True
    web_server.start()
    start_time = time.time()
    while not web_server.serving:
        if time.time() - start_time > 10:
            raise RuntimeError("timeout waiting for web server start")
        time.sleep(0.1)

    # We're statically using localhost in the endpoint url.
    # Other options would have been to set ArgumentParser.args.web_host
    # and then connect to that value. However we'd have to use an IP
    # address and then needed to decide if we use either
    # 127.0.0.1 or ::1. Which might fail on CI boxes without
    # IPv4 or IPv6 respectively. Instead we leave the default which
    # binds to all IPs and assume that localhost will resolve to
    # the appropriate v4 or v6 loopback address. A disadvantage
    # of this is that for a brief moment during the test we're
    # exposing the web server on all local IPs.
    endpoint = f"http://localhost:{ArgumentParser.args.web_port}"
    r = requests.get(f"{endpoint}/health")
    assert r.content == b"ok\r\n"
    web_server.shutdown()
