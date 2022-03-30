import warnings
from contextlib import suppress

import certifi
import logging

import requests
from typing import Tuple, Optional, List
from resotolib.args import ArgumentParser
from resotolib.x509 import (
    csr_to_bytes,
    load_cert_from_bytes,
    cert_fingerprint,
    gen_rsa_key,
    gen_csr,
    cert_to_bytes,
    load_cert_from_file,
)
from resotolib.jwt import decode_jwt_from_headers, encode_jwt_to_headers
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

log = logging.getLogger(__name__)


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


def get_ca_cert(resotocore_uri: str, psk: str) -> Certificate:
    if resotocore_uri is None:
        resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = requests.get(f"{resotocore_uri}/ca/cert", verify=False)
        ca_cert = load_cert_from_bytes(r.content)
        if psk:
            # noinspection PyTypeChecker
            jwt = decode_jwt_from_headers(r.headers, psk)
            if jwt is None or jwt["sha256_fingerprint"] != cert_fingerprint(ca_cert):
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
    cert_bytes = r.content
    cert_crt = load_cert_from_bytes(cert_bytes)
    return cert_key, cert_crt
