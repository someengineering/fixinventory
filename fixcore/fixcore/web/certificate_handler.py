from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from ssl import SSLContext, create_default_context, Purpose
from tempfile import TemporaryDirectory
from typing import Tuple, Optional, List, Union, Dict

from arango.database import StandardDatabase
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, CertificateSigningRequest

from fixcore.core_config import CoreConfig, CertificateConfig
from fixcore.service import Service
from fixcore.types import Json
from fixcore.util import Periodic
from fixlib.core.ca import TLSData
from fixlib.utils import get_local_ip_addresses, get_local_hostnames
from fixlib.x509 import (
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
    write_key_to_file,
    write_cert_to_file,
    load_key_from_file,
    load_cert_from_file,
    write_ca_bundle,
)

log = logging.getLogger(__name__)


class CertificateHandler(Service):
    def __init__(
        self,
        config: CoreConfig,
        ca_cert: Certificate,
        host_key: RSAPrivateKey,
        host_cert: Certificate,
        temp_dir: Path,
        additional_trusted_authorities: Optional[List[Certificate]] = None,
    ) -> None:
        super().__init__()
        self.config = config
        self._ca_cert = ca_cert
        self._trusted_authorities = [self._ca_cert] + (additional_trusted_authorities or [])
        self._ca_cert_bytes = cert_to_bytes(ca_cert)
        self._ca_cert_fingerprint = cert_fingerprint(ca_cert)
        self._ca_bundle = temp_dir / "ca-bundle.crt"
        self._host_key = host_key
        self._host_cert = host_cert
        self.__recreate_ca_file()  # write the CA bundle to the temp dir
        self._ca_cert_recreate = Periodic("recreate ca bundle file", self.__recreate_ca_file, timedelta(hours=1))
        self._host_context = self._create_host_context(config, self._host_cert, self._host_key)
        self._client_context = self.__create_client_context(config, ca_cert, additional_trusted_authorities)

    async def start(self) -> None:
        await self._ca_cert_recreate.start()

    async def stop(self) -> None:
        await self._ca_cert_recreate.stop()

    def __recreate_ca_file(self) -> None:
        write_ca_bundle(self._trusted_authorities, str(self._ca_bundle))

    @property
    def ca_cert(self) -> Certificate:
        return self._ca_cert

    @property
    def ca_bundle(self) -> Path:
        return self._ca_bundle

    @property
    def authority_certificate(self) -> Tuple[bytes, str]:
        return self._ca_cert_bytes, self._ca_cert_fingerprint

    @property
    def host_certificate(self) -> Tuple[RSAPrivateKey, Certificate]:
        return self._host_key, self._host_cert

    def create_key_and_cert(
        self, common_name: str, dns_names: List[str], ip_addresses: List[str], days_valid: int
    ) -> Tuple[RSAPrivateKey, Certificate]:
        raise NotImplementedError("Signing is not implemented!")

    def sign(
        self,
        csr_or_bytes: Union[CertificateSigningRequest, bytes],
        days_valid: int = 365,
        server_auth: bool = True,
        client_auth: bool = True,
        key_usage: Optional[Dict[str, bool]] = None,
    ) -> Tuple[Certificate, str]:
        raise NotImplementedError("Signing is not implemented!")

    @property
    def host_context(self) -> Optional[SSLContext]:
        return self._host_context

    @property
    def client_context(self) -> SSLContext:
        return self._client_context

    @staticmethod
    def _create_host_context(config: CoreConfig, host_cert: Certificate, host_key: RSAPrivateKey) -> SSLContext:
        args = config.args
        # noinspection PyTypeChecker
        ctx = create_default_context(purpose=Purpose.CLIENT_AUTH)
        if config.args.cert:
            log.info("Using TLS certificate from command line.")
            # Use the certificate provided via cmd line flags
            ctx.load_cert_chain(args.cert, args.cert_key, args.cert_key_pass)
        else:
            log.info("Using TLS certificate from data store.")
            # ssl library wants to load cert/key from file: put it into a temp directory for loading
            with TemporaryDirectory() as td:
                cert_file = Path(td, "cert")
                key_file = Path(td, "key")
                write_cert_to_file(host_cert, str(cert_file))
                write_key_to_file(host_key, str(key_file))
                ctx.load_cert_chain(str(cert_file), str(key_file), args.ca_cert_key_pass)
        return ctx

    @staticmethod
    def __create_client_context(
        config: CoreConfig, ca_cert: Certificate, additional_trusted_authorities: Optional[List[Certificate]]
    ) -> SSLContext:
        # noinspection PyTypeChecker
        ctx = create_default_context(purpose=Purpose.SERVER_AUTH)
        if config.args.ca_cert:
            ctx.load_verify_locations(cafile=config.args.ca_cert)
        else:
            ca_bytes = cert_to_bytes(ca_cert).decode("utf-8")
            ctx.load_verify_locations(cadata=ca_bytes)
        # also load all additional trusted authorities into context
        for cert in additional_trusted_authorities or []:
            ca_bytes = cert_to_bytes(cert).decode("utf-8")
            ctx.load_verify_locations(cadata=ca_bytes)
        return ctx


class CertificateHandlerNoCA(CertificateHandler):
    """
    This certificate handler is using a CA that is outside the control of fix core.
    As a consequence it is not possible to create new certificates or to sign CSRs.
    This functionality is only available in CertificateHandlerWithCA.

    All certificates can be provided via command line.
    If one part is missing, all of them get ignored.

    If not provided via command line, the CA certificate is retrieved from the CA.
    """

    @staticmethod
    def lookup(config: CoreConfig, temp_dir: Path) -> CertificateHandlerNoCA:
        args = config.args

        # if we get a ca certificate from the command line, use it
        if args.ca_cert and args.cert and args.cert_key:
            ca_cert = load_cert_from_file(args.ca_cert)
            host_key = load_key_from_file(args.cert_key, args.cert_key_pass)
            host_cert = load_cert_from_file(args.cert)
            log.info(f"Using CA certificate from command line. fingerprint:{cert_fingerprint(ca_cert)}")
            return CertificateHandlerNoCA(config, ca_cert, host_key, host_cert, temp_dir)

        # otherwise, retrieve the CA certificate from the CA
        assert config.args.ca_url is not None, "CA URL must be set! Use --ca-url <url> to set it."
        cfg = config.api.host_certificate
        tls_data = TLSData(
            common_name=cfg.common_name,
            san_dns_names=get_local_hostnames(
                include_loopback=cfg.include_loopback,
                san_ip_addresses=cfg.san_ip_addresses,
                san_dns_names=cfg.san_dns_names,
            ),
            san_ip_addresses=get_local_ip_addresses(
                include_loopback=cfg.include_loopback, san_ip_addresses=cfg.san_ip_addresses
            ),
            fixcore_uri=config.args.ca_url,
            tempdir=str(temp_dir),
            psk=config.args.psk,
        )
        tls_data.load()
        authorities = [load_cert_from_file(args.ca_cert)] if args.ca_cert else []
        return CertificateHandlerNoCA(config, tls_data.ca_cert, tls_data.key, tls_data.cert, temp_dir, authorities)


class CertificateHandlerWithCA(CertificateHandler):
    """
    This certificate handler is implementing the CA.
    It can create new certificates and sign CSRs.
    """

    def __init__(
        self,
        config: CoreConfig,
        ca_key: RSAPrivateKey,
        ca_cert: Certificate,
        host_key: RSAPrivateKey,
        host_cert: Certificate,
        temp_dir: Path,
        additional_trusted_authorities: Optional[List[Certificate]] = None,
    ) -> None:
        super().__init__(config, ca_cert, host_key, host_cert, temp_dir, additional_trusted_authorities)
        self._ca_key = ca_key

    def create_key_and_cert(
        self, common_name: str, dns_names: List[str], ip_addresses: List[str], days_valid: int
    ) -> Tuple[RSAPrivateKey, Certificate]:
        key = gen_rsa_key()
        csr = gen_csr(
            key,
            include_loopback=False,
            common_name=common_name,
            san_dns_names=dns_names,
            san_ip_addresses=ip_addresses,
            discover_local_dns_names=False,
            discover_local_ip_addresses=False,
        )
        cert = sign_csr(csr, self._ca_key, self._ca_cert, days_valid)
        return key, cert

    def sign(
        self,
        csr_or_bytes: Union[CertificateSigningRequest, bytes],
        days_valid: int = 365,
        server_auth: bool = True,
        client_auth: bool = True,
        key_usage: Optional[Dict[str, bool]] = None,
    ) -> Tuple[Certificate, str]:
        csr = load_csr_from_bytes(csr_or_bytes) if isinstance(csr_or_bytes, bytes) else csr_or_bytes
        certificate = sign_csr(csr, self._ca_key, self._ca_cert, days_valid, server_auth, client_auth, key_usage)
        return certificate, cert_fingerprint(certificate)

    @staticmethod
    def _create_host_certificate(
        cfg: CertificateConfig, ca_key: RSAPrivateKey, ca_cert: Certificate
    ) -> Tuple[RSAPrivateKey, Certificate]:
        key = gen_rsa_key()
        host_names = get_local_hostnames(
            include_loopback=cfg.include_loopback,
            san_ip_addresses=cfg.san_ip_addresses,
            san_dns_names=cfg.san_dns_names,
        )
        host_ips = get_local_ip_addresses(include_loopback=cfg.include_loopback, san_ip_addresses=cfg.san_ip_addresses)
        log.info(f'Create host certificate for hostnames:{", ".join(host_names)} and ips:{", ".join(host_ips)}')
        csr = gen_csr(
            key,
            common_name=cfg.common_name,
            san_dns_names=list(host_names),
            san_ip_addresses=list(host_ips),
            include_loopback=cfg.include_loopback,
        )
        cert = sign_csr(csr, ca_key, ca_cert)
        return key, cert

    @staticmethod
    def lookup(config: CoreConfig, db: StandardDatabase, temp_dir: Path) -> CertificateHandlerWithCA:
        args = config.args
        # if we get a ca certificate from the command line, use it
        if args.ca_cert and args.ca_cert_key:
            ca_key = load_key_from_file(args.ca_cert_key, args.ca_cert_key_pass)
            ca_cert = load_cert_from_file(args.ca_cert)
            if args.cert and args.cert_key:
                host_key = load_key_from_file(args.ca_cert_key, args.ca_cert_key_pass)
                host_cert = load_cert_from_file(args.ca_cert)
            else:
                host_key, host_cert = CertificateHandlerWithCA._create_host_certificate(
                    config.api.host_certificate, ca_key, ca_cert
                )
            log.info(f"Using CA certificate from command line. fingerprint:{cert_fingerprint(ca_cert)}")
            return CertificateHandlerWithCA(config, ca_key, ca_cert, host_key, host_cert, temp_dir)

        # otherwise, load from database or create it
        sd = db.collection("system_data")
        maybe_ca: Optional[Json] = sd.get("ca")  # type: ignore
        authorities = [load_cert_from_file(args.ca_cert)] if args.ca_cert else []
        if maybe_ca and isinstance(maybe_ca.get("key"), str) and isinstance(maybe_ca.get("certificate"), str):
            log.debug("Found existing certificate in data store.")
            key = load_key_from_bytes(maybe_ca["key"].encode("utf-8"))
            certificate = load_cert_from_bytes(maybe_ca["certificate"].encode("utf-8"))
            log.info(f"Using CA certificate from database. fingerprint:{cert_fingerprint(certificate)}")
            host_key, host_cert = CertificateHandlerWithCA._create_host_certificate(
                config.api.host_certificate, key, certificate
            )
            return CertificateHandlerWithCA(config, key, certificate, host_key, host_cert, temp_dir, authorities)
        else:
            wo = "with" if args.ca_cert_key_pass else "without"
            key, certificate = bootstrap_ca()
            log.info(
                f"No ca certificate found - create new one {wo} passphrase. fingerprint:{cert_fingerprint(certificate)}"
            )
            key_string = key_to_bytes(key, args.ca_cert_key_pass).decode("utf-8")
            certificate_string = cert_to_bytes(certificate).decode("utf-8")
            sd.insert({"_key": "ca", "key": key_string, "certificate": certificate_string})
            host_key, host_cert = CertificateHandlerWithCA._create_host_certificate(
                config.api.host_certificate, key, certificate
            )
            return CertificateHandlerWithCA(config, key, certificate, host_key, host_cert, temp_dir, authorities)
