from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, cast

from arango.database import StandardDatabase
from attr import evolve

from resotocore.core_config import CoreConfig
from resotocore.system_start import empty_config, parse_args
from resotocore.types import Json
from resotocore.web.certificate_handler import CertificateHandler
from resotolib.x509 import (
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
        handler = CertificateHandler.lookup(config, test_db, tmp)
        ca = cast(Optional[Json], sd.get("ca"))
        assert ca is not None
        # ensure the certificate in the database is the same as exposed by the handler
        ca_bytes, fingerprint = handler.authority_certificate
        assert ca_bytes == ca["certificate"].encode("utf-8")
        # a new handler will use the existing certificate
        handler2 = CertificateHandler.lookup(config, test_db, tmp)
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
