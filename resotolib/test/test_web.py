import socket
import requests
import time
import os
import tempfile
from resotolib.x509 import (
    gen_rsa_key,
    gen_csr,
    bootstrap_ca,
    sign_csr,
    write_cert_to_file,
    write_key_to_file,
)
from resotolib.web import WebServer
from resotolib.web.metrics import WebApp
import cherrypy


def get_free_port() -> int:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("", 0))
    _, free_port = tcp.getsockname()
    tcp.close()
    return free_port


def test_web():
    # Find a free local port to reuse when we bind the web server.
    # This is so that multiple builds/tests can run in parallel
    # on the same CI agent.
    # todo: race between closing socket and reusing free port in WebServer
    free_port = get_free_port()
    print(f"Starting http webserver on port {free_port}")
    web_server = WebServer(WebApp(), web_port=free_port)
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
    endpoint = f"http://localhost:{free_port}"
    r = requests.get(f"{endpoint}/health")
    assert r.text == "ok\r\n"
    web_server.shutdown()
    while web_server.is_alive():
        print("Waiting for web server to shutdown")
        time.sleep(1)


def disabled_test_secure_web():
    with tempfile.TemporaryDirectory() as tmp:
        ca_key, ca_cert = bootstrap_ca()
        cert_key = gen_rsa_key()
        cert_csr = gen_csr(cert_key, common_name="localhost")
        cert_crt = sign_csr(cert_csr, ca_key, ca_cert)
        ca_cert_path = os.path.join(tmp, "ca.crt")
        cert_key_path = os.path.join(tmp, "cert.key")
        cert_crt_path = os.path.join(tmp, "cert.crt")

        write_cert_to_file(ca_cert, cert_path=ca_cert_path)
        write_key_to_file(cert_key, key_path=cert_key_path)
        write_cert_to_file(cert_crt, cert_path=cert_crt_path)

        free_port = get_free_port()
        print(f"Starting https webserver on port {free_port}")
        web_server = WebServer(WebApp(), web_port=free_port, ssl_cert=cert_crt_path, ssl_key=cert_key_path)
        web_server.daemon = True
        web_server.start()
        start_time = time.time()
        while not web_server.serving:
            if time.time() - start_time > 10:
                raise RuntimeError("timeout waiting for web server start")
            time.sleep(0.1)

        endpoint = f"https://localhost:{free_port}"
        r = requests.get(f"{endpoint}/health", verify=ca_cert_path)
        assert r.text == "ok\r\n"
        web_server.shutdown()
        while web_server.is_alive():
            print("Waiting for web server to shutdown")
            time.sleep(1)
        cherrypy.engine
