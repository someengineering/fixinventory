from __future__ import annotations

import logging
from typing import Tuple, Optional

from arango.database import StandardDatabase
from resotolib.utils import get_local_ip_addresses, get_local_hostnames
from resotolib.x509 import (
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

from resotocore.core_config import CoreConfig

log = logging.getLogger(__name__)


class CertificateHandler:
    def __init__(self, config: CoreConfig, ca_key: RSAPrivateKey, ca_cert: Certificate) -> None:
        self.config = config
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

    def create_host_certificate(self, ca_key: RSAPrivateKey, ca_cert: Certificate) -> Tuple[RSAPrivateKey, Certificate]:
        key = gen_rsa_key()
        host_names = get_local_hostnames(args=self.config.args)
        host_ips = get_local_ip_addresses(args=self.config.args)
        log.info(f'Create host certificate for hostnames:{", ".join(host_names)} and ips:{", ".join(host_ips)}')
        csr = gen_csr(key, san_dns_names=list(host_names), san_ip_addresses=list(host_ips))
        cert = sign_csr(csr, ca_key, ca_cert)
        return key, cert

    @staticmethod
    def lookup(config: CoreConfig, db: StandardDatabase, passphrase: Optional[str] = None) -> CertificateHandler:
        sd = db.collection("system_data")
        maybe_ca = sd.get("ca")
        if maybe_ca and isinstance(maybe_ca.get("key"), str) and isinstance(maybe_ca.get("certificate"), str):
            log.debug("Found existing certificate in data store.")
            key = load_key_from_bytes(maybe_ca["key"].encode("utf-8"))
            certificate = load_cert_from_bytes(maybe_ca["certificate"].encode("utf-8"))
            return CertificateHandler(config, key, certificate)
        else:
            wo = "with" if passphrase else "without"
            log.info(f"No ca certificate found - create a new one {wo} passphrase.")
            key, certificate = bootstrap_ca()
            key_string = key_to_bytes(key, passphrase).decode("utf-8")
            certificate_string = cert_to_bytes(certificate).decode("utf-8")
            sd.insert({"_key": "ca", "key": key_string, "certificate": certificate_string})
            return CertificateHandler(config, key, certificate)
