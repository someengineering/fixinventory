import os
import warnings
from contextlib import suppress

import certifi

import requests
from ssl import create_default_context, SSLContext
from typing import Tuple, Optional, List, Dict
from resotolib.args import ArgumentParser
from resotolib.core import resotocore
from resotolib.x509 import (
    csr_to_bytes,
    load_cert_from_bytes,
    cert_fingerprint,
    gen_rsa_key,
    gen_csr,
    cert_to_bytes,
    load_cert_from_file,
    write_cert_to_file,
    write_key_to_file,
    key_to_bytes,
    load_key_from_bytes,
    load_key_from_file,
    write_ca_bundle,
)
from resotolib.jwt import decode_jwt_from_headers, encode_jwt_to_headers
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from tempfile import TemporaryDirectory
from threading import Lock, Event
from resotolib.logging import log


def ensure_tls_setup_for_requests(
    resotocore_uri: str, psk: Optional[str], tls_cert: Optional[str]
) -> None:
    """
    The requests library uses its own TLS configuration.
    This function ensures that the certificate is set up correctly.
    :param resotocore_uri: the uri of the resotocore
    :param psk: the optional psk
    :param tls_cert: if defined use the given cert, otherwise it is downloaded from resotocore.
    """

    def append_cert_to_file(cert: Certificate) -> None:
        with open(certifi.where(), "ab") as outfile:
            outfile.write(b"\n")
            outfile.write(b"# Issuer: Resoto\n")
            outfile.write(b"# Label: Resoto Root CA\n")
            outfile.write(cert_to_bytes(cert))

    if resotocore_uri.startswith("https://"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                # Only install the certificate, if not already done
                requests.get(resotocore_uri)
                log.debug("TLS is working - no additional setup required")
            except requests.exceptions.SSLError:
                with suppress(Exception):
                    if tls_cert:
                        log.debug("Adding CA root to trust store from cmd line")
                        append_cert_to_file(load_cert_from_file(tls_cert))
                    else:
                        log.debug("Adding CA root to trust store from resotocore")
                        append_cert_to_file(get_ca_cert(resotocore_uri, psk))


def get_ca_cert(
    resotocore_uri: Optional[str] = None, psk: Optional[str] = None
) -> Certificate:
    if resotocore_uri is None:
        resotocore_uri = resotocore.http_uri
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = requests.get(f"{resotocore_uri}/ca/cert", verify=False)
        ca_cert = load_cert_from_bytes(r.content)
        if psk:
            # noinspection PyTypeChecker
            jwt = decode_jwt_from_headers(r.headers, psk)
            if jwt is None:
                raise ValueError(
                    "Failed to decode JWT - was resotocore started without PSK?"
                )
            if jwt["sha256_fingerprint"] != cert_fingerprint(ca_cert):
                raise ValueError("Invalid Root CA certificate fingerprint")
        return ca_cert


def get_signed_cert(
    common_name: str,
    san_dns_names: Optional[List[str]] = None,
    san_ip_addresses: Optional[List[str]] = None,
    resotocore_uri: str = None,
    psk: str = None,
    ca_cert_path: str = None,
) -> Tuple[RSAPrivateKey, Certificate]:
    if resotocore_uri is None:
        resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)

    cert_key = gen_rsa_key()
    cert_csr = gen_csr(cert_key, common_name, san_dns_names, san_ip_addresses)
    cert_csr_bytes = csr_to_bytes(cert_csr)
    headers = {}
    if psk is not None:
        encode_jwt_to_headers(headers, {}, psk)
    request_kwargs = {}
    if ca_cert_path is not None:
        request_kwargs["verify"] = ca_cert_path
    r = requests.post(
        f"{resotocore_uri}/ca/sign", cert_csr_bytes, headers=headers, **request_kwargs
    )
    if r.status_code != 200:
        raise ValueError(f"Failed to get signed certificate: {r.text}")
    cert_bytes = r.content
    cert_crt = load_cert_from_bytes(cert_bytes)
    return cert_key, cert_crt


class TLSData:
    def __init__(
        self,
        common_name: str = None,
        san_dns_names: Optional[List[str]] = None,
        san_ip_addresses: Optional[List[str]] = None,
        tempdir: str = None,
        resotocore_uri: str = None,
        psk: str = None,
    ) -> None:
        self.common_name = common_name
        self.san_dns_names = san_dns_names
        self.san_ip_addresses = san_ip_addresses
        self.__tempdir = TemporaryDirectory(prefix="resoto-cert-", dir=tempdir)
        if resotocore_uri is None:
            resotocore_uri = resotocore.http_uri
        self.__resotocore_uri = resotocore_uri
        self.__psk = psk
        self.__ca_cert = None
        self.__cert = None
        self.__key = None
        self.__ca_cert_path = f"{self.__tempdir.name}/ca.crt"
        self.__cert_path = f"{self.__tempdir.name}/cert.crt"
        self.__key_path = f"{self.__tempdir.name}/cert.key"
        self.__loaded = Event()
        self.__lock = Lock()

    def __getstate__(self):
        d = self.__dict__.copy()
        del d["_TLSData__lock"]
        del d["_TLSData__loaded"]
        del d["_TLSData__ca_cert"]
        del d["_TLSData__cert"]
        del d["_TLSData__key"]
        d["__is_loaded"] = self.__loaded.is_set()
        if self.__loaded.is_set():
            d["__ca_cert_bytes"] = cert_to_bytes(self.__ca_cert)
            d["__cert_bytes"] = cert_to_bytes(self.__cert)
            d["__key_bytes"] = key_to_bytes(self.__key)
        return d

    def __setstate__(self, d):
        d["_TLSData__lock"] = Lock()
        d["_TLSData__loaded"] = Event()
        d["_TLSData__ca_cert"] = None
        d["_TLSData__cert"] = None
        d["_TLSData__key"] = None
        if d["__is_loaded"]:
            d["_TLSData__loaded"].set()
            d["_TLSData__ca_cert"] = load_cert_from_bytes(d["__ca_cert_bytes"])
            d["_TLSData__cert"] = load_cert_from_bytes(d["__cert_bytes"])
            d["_TLSData__key"] = load_key_from_bytes(d["__key_bytes"])
            del d["__ca_cert_bytes"]
            del d["__cert_bytes"]
            del d["__key_bytes"]
        del d["__is_loaded"]
        self.__dict__.update(d)

    def load_from_core(self) -> None:
        with self.__lock:
            if getattr(ArgumentParser.args, "ca_cert", None) is not None:
                log.debug(f"Loading CA certificate from {ArgumentParser.args.ca_cert}")
                self.__ca_cert = load_cert_from_file(ArgumentParser.args.ca_cert)
            else:
                log.debug("Loading CA cert from core")
                self.__ca_cert = get_ca_cert(
                    resotocore_uri=self.__resotocore_uri, psk=self.__psk
                )
            log.debug(f"Writing CA cert {self.__ca_cert_path}")
            write_ca_bundle(self.__ca_cert, self.__ca_cert_path, include_certifi=True)
            if (
                getattr(ArgumentParser.args, "cert", None) is not None
                and getattr(ArgumentParser.args, "cert_key", None) is not None
            ):
                log.debug(f"Loading certificate from {ArgumentParser.args.cert}")
                self.__cert = load_cert_from_file(ArgumentParser.args.cert)
                cert_key_pass = None
                if getattr(ArgumentParser.args, "cert_key_pass", None) is not None:
                    cert_key_pass = ArgumentParser.args.cert_key_pass
                log.debug(f"Loading key from {ArgumentParser.args.key}")
                self.__key = load_key_from_file(
                    ArgumentParser.args.key, passphrase=cert_key_pass
                )
            else:
                log.debug("Requesting signed cert from core")
                self.__key, self.__cert = get_signed_cert(
                    common_name=self.common_name,
                    san_dns_names=self.san_dns_names,
                    san_ip_addresses=self.san_ip_addresses,
                    resotocore_uri=self.__resotocore_uri,
                    psk=self.__psk,
                    ca_cert_path=self.ca_cert_path,
                )
            log.debug(f"Writing signed cert/key {self.__cert_path}")
            write_cert_to_file(self.__cert, self.__cert_path)
            write_key_to_file(self.__key, self.__key_path)
            self.__loaded.set()

    @property
    def ca_cert(self) -> str:
        if not os.path.isfile(self.__ca_cert_path):
            self.load_from_core()
        return self.__ca_cert

    @property
    def cert(self) -> str:
        if not self.__loaded.is_set():
            self.load_from_core()
        return self.__cert

    @property
    def key(self) -> str:
        if not self.__loaded.is_set():
            self.load_from_core()
        return self.__key

    @property
    def ca_cert_path(self) -> str:
        if not os.path.isfile(self.__ca_cert_path):
            self.load_from_core()
        return self.__ca_cert_path

    @property
    def cert_path(self) -> str:
        if not self.__loaded.is_set():
            self.load_from_core()
        return self.__cert_path

    @property
    def key_path(self) -> str:
        if not self.__loaded.is_set():
            self.load_from_core()
        return self.__key_path

    @property
    def sslopt(self) -> Dict[str, str]:
        return {"ca_certs": self.ca_cert_path}

    @property
    def verify(self) -> str:
        return self.ca_cert_path

    @property
    def ssl_context(self) -> SSLContext:
        context = create_default_context()
        context.load_verify_locations(cafile=self.ca_cert_path)
        return context

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--ca-cert",
            help="Path to custom CA certificate file",
            default=None,
            type=str,
            dest="ca_cert",
        )
        arg_parser.add_argument(
            "--cert",
            help="Path to custom certificate file",
            default=None,
            type=str,
            dest="cert",
        )
        arg_parser.add_argument(
            "--cert-key",
            help="Path to custom certificate key file",
            default=None,
            type=str,
            dest="cert_key",
        )
        arg_parser.add_argument(
            "--cert-key-pass",
            help="Passphrase for certificate key file",
            default=None,
            type=str,
            dest="cert_key_pass",
        )
        arg_parser.add_argument(
            "--no-verify-certs",
            help="Turn off certificate verification",
            default=True,
            type=bool,
            dest="verify_certs",
            action="store_false",
        )
