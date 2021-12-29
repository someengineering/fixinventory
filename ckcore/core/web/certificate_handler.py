from __future__ import annotations

import logging
import socket
from contextlib import suppress
from typing import Tuple, Set, Optional

from arango.database import StandardDatabase
from cklib.x509 import (
    bootstrap_ca,
    gen_rsa_key,
    gen_csr,
    sign_csr,
    cert_to_bytes,
    key_to_bytes,
    load_key_from_bytes,
    load_cert_from_bytes,
    cert_fingerprint,
    load_csr_from_bytes,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

log = logging.getLogger(__name__)


class CertificateHandler:
    def __init__(self, ca_key: RSAPrivateKey, ca_cert: Certificate) -> None:
        self._ca_key = ca_key
        self._ca_cert = ca_cert
        self._ca_cert_bytes = cert_to_bytes(ca_cert)
        self._ca_cert_fingerprint = cert_fingerprint(ca_cert)
        self._host_key, self._host_cert = self.create_host_certificate(ca_key, ca_cert)

    @property
    def authority_certificate(self) -> Tuple[bytes, str]:
        return self._ca_cert_bytes, self._ca_cert_fingerprint

    @property
    def host_certificate(self) -> Certificate:
        return self._host_cert

    def sign(self, csr_bytes: bytes) -> Tuple[bytes, str]:
        csr = load_csr_from_bytes(csr_bytes)
        certificate = sign_csr(csr, self._ca_key, self._ca_cert)
        return cert_to_bytes(certificate), cert_fingerprint(certificate)

    @staticmethod
    def create_host_certificate(ca_key: RSAPrivateKey, ca_cert: Certificate) -> Tuple[RSAPrivateKey, Certificate]:
        key = gen_rsa_key()
        host_names: Set[str] = set()
        host_ips: Set[str] = set()
        with suppress(Exception):
            # This will only return IPV4 information
            host_name, aliases, ip_addresses = socket.gethostbyname_ex(socket.gethostname())
            host_names.add(host_name)
            host_names.update(aliases)
            host_ips.update(ip_addresses)
        with suppress(Exception):
            # This will return IPV4 and IPV6 information
            for info in socket.getaddrinfo(
                socket.gethostname(), 80, proto=socket.IPPROTO_TCP, flags=socket.AI_CANONNAME
            ):
                host_names.add(info[3])
                host_ips.add(info[4][0])
        host_names.discard("")  # the api will return an empty string, if the hostname can not be resolved
        log.info(f'Create host certificate for hostnames:{", ".join(host_names)} and ips:{", ".join(ip_addresses)}')
        csr = gen_csr(key, san_dns_names=list(host_names), san_ip_addresses=list(host_ips))
        cert = sign_csr(csr, ca_key, ca_cert)
        return key, cert

    @staticmethod
    def lookup(db: StandardDatabase, passphrase: Optional[str] = None) -> CertificateHandler:
        sd = db.collection("system_data")
        maybe_ca = sd.get("ca")
        if maybe_ca and isinstance(maybe_ca.get("key"), str) and isinstance(maybe_ca.get("certificate"), str):
            log.debug("Found existing certificate in data store.")
            key = load_key_from_bytes(maybe_ca["key"].encode("utf-8"))
            certificate = load_cert_from_bytes(maybe_ca["certificate"].encode("utf-8"))
            return CertificateHandler(key, certificate)
        else:
            wo = "with" if passphrase else "without"
            log.info(f"No ca certificate found - create a new one {wo} passphrase.")
            key, certificate = bootstrap_ca()
            key_string = key_to_bytes(key, passphrase).decode("utf-8")
            certificate_string = cert_to_bytes(certificate).decode("utf-8")
            sd.insert({"_key": "ca", "key": key_string, "certificate": certificate_string})
            return CertificateHandler(key, certificate)
