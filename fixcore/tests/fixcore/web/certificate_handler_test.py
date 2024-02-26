from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, cast

from arango.database import StandardDatabase
from attr import evolve

from fixcore.core_config import CoreConfig
from fixcore.system_start import empty_config, parse_args
from fixcore.types import Json
from fixcore.web.certificate_handler import CertificateHandler, CertificateHandlerWithCA, CertificateHandlerNoCA
from fixlib.x509 import (
    load_cert_from_bytes,
    cert_fingerprint,
    csr_to_bytes,
    gen_csr,
    gen_rsa_key,
    bootstrap_ca,
    write_cert_to_file,
    write_key_to_file,
)


def test_ca_certificate(cert_handler: CertificateHandler) -> None:
    cert_bytes, fingerprint = cert_handler.authority_certificate
    cert = load_cert_from_bytes(cert_bytes)
    assert cert_fingerprint(cert) == fingerprint


def test_sign(cert_handler: CertificateHandler) -> None:
    cert, fingerprint = cert_handler.sign(csr_to_bytes(gen_csr(gen_rsa_key())))
    assert cert_fingerprint(cert) == fingerprint


def test_bootstrap(test_db: StandardDatabase) -> None:
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        sd = test_db.collection("system_data")
        config = empty_config()
        # Delete any existing entry, so a new certificate needs to be created
        sd.delete("ca", ignore_missing=True)
        handler = CertificateHandlerWithCA.lookup(config, test_db, tmp)
        ca = cast(Optional[Json], sd.get("ca"))
        assert ca is not None
        # ensure the certificate in the database is the same as exposed by the handler
        ca_bytes, fingerprint = handler.authority_certificate
        assert ca_bytes == ca["certificate"].encode("utf-8")
        # a new handler will use the existing certificate
        handler2 = CertificateHandlerWithCA.lookup(config, test_db, tmp)
        assert handler.authority_certificate == handler2.authority_certificate
        # but the host certificate will be different
        assert handler.host_certificate != handler2.host_certificate


def test_load_from_args(default_config: CoreConfig) -> None:
    with TemporaryDirectory() as tmpdir:
        ca_path = tmpdir + "/ca.crt"
        key_path = tmpdir + "/ca.eky"
        pk, cert = bootstrap_ca()
        write_cert_to_file(cert, ca_path)
        write_key_to_file(pk, key_path)
        args = parse_args(["--cert", ca_path, "--cert-key", key_path])
        config = evolve(default_config, args=args)
        context = CertificateHandler._create_host_context(config, cert, pk)
        assert context is not None


def test_additional_authorities(test_db: StandardDatabase) -> None:
    config = empty_config()
    ca_key, ca_cert = bootstrap_ca(common_name="the ca")
    another_key, another_ca = bootstrap_ca(common_name="another ca")
    key, cert = CertificateHandlerWithCA._create_host_certificate(config.api.host_certificate, ca_key, ca_cert)

    def assert_certs(handler: CertificateHandler, name: str) -> None:
        ca_crts = {crt["issuer"]: crt for crt in handler.client_context.get_ca_certs()}
        assert ((("organizationName", "Some Engineering Inc."),), (("commonName", name),)) in ca_crts

    with TemporaryDirectory() as temp:
        ca_path = temp + "/ca.crt"
        key_path = temp + "/ca.key"
        another_ca_path = temp + "/another_ca.crt"
        another_key_path = temp + "/another_ca.key"
        write_cert_to_file(ca_cert, ca_path)
        write_key_to_file(ca_key, key_path)
        write_cert_to_file(another_ca, another_ca_path)
        write_key_to_file(another_key, another_key_path)

        # another ca is added explicitly
        ca = CertificateHandlerWithCA(config, ca_key, ca_cert, key, cert, Path(temp), [another_ca])
        assert_certs(ca, "another ca")
        no_ca = CertificateHandlerNoCA(config, ca_cert, key, cert, Path(temp), [another_ca])
        assert_certs(no_ca, "another ca")

        # another ca is defined on the command line (no key)
        config = evolve(config, args=parse_args(["--ca-cert", another_ca_path]))
        assert_certs(CertificateHandlerWithCA.lookup(config, test_db, Path(temp)), "another ca")

        # in case cert and key are defined, it is used as the ca
        config = evolve(config, args=parse_args(["--ca-cert", ca_path, "--ca-cert-key", key_path]))
        assert_certs(CertificateHandlerWithCA.lookup(config, test_db, Path(temp)), "the ca")

        # get ca certificate and host certificate/license from args
        args = ["--ca-cert", ca_path, "--cert", another_ca_path, "--cert-key", another_key_path]
        config = evolve(config, args=parse_args(args))
        assert_certs(CertificateHandlerNoCA.lookup(config, Path(temp)), "the ca")
