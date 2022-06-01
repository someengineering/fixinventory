import os
import tempfile
from resotolib.x509 import (
    gen_rsa_key,
    gen_csr,
    bootstrap_ca,
    sign_csr,
    write_csr_to_file,
    write_cert_to_file,
    write_key_to_file,
    load_csr_from_file,
    load_cert_from_file,
    load_key_from_file,
    key_to_bytes,
    cert_fingerprint,
)


def test_x509():
    with tempfile.TemporaryDirectory() as tmp:
        ca_key, ca_cert = bootstrap_ca()
        cert_key = gen_rsa_key()
        gen_csr(cert_key)  # dummy call to generate CSR without SANs
        cert_csr = gen_csr(
            cert_key,
            san_dns_names=["example.com"],
            san_ip_addresses=["10.0.1.1", "10.0.0.0/24"],
        )
        cert_crt = sign_csr(cert_csr, ca_key, ca_cert)
        ca_key_path = os.path.join(tmp, "ca.key")
        ca_cert_path = os.path.join(tmp, "ca.crt")

        cert_key_path = os.path.join(tmp, "cert.key")
        cert_key_passphrase = "foobar"
        cert_csr_path = os.path.join(tmp, "cert.csr")
        cert_crt_path = os.path.join(tmp, "cert.crt")

        write_key_to_file(ca_key, key_path=ca_key_path)
        write_cert_to_file(ca_cert, cert_path=ca_cert_path)

        write_key_to_file(cert_key, key_path=cert_key_path, passphrase=cert_key_passphrase)
        write_csr_to_file(cert_csr, csr_path=cert_csr_path)
        write_cert_to_file(cert_crt, cert_path=cert_crt_path)

        loaded_ca_key = load_key_from_file(ca_key_path)
        loaded_ca_cert = load_cert_from_file(ca_cert_path)
        loaded_cert_key = load_key_from_file(cert_key_path, passphrase=cert_key_passphrase)
        loaded_cert_csr = load_csr_from_file(cert_csr_path)
        loaded_cert_crt = load_cert_from_file(cert_crt_path)

        assert loaded_ca_cert == ca_cert
        assert loaded_cert_csr == cert_csr
        assert loaded_cert_crt == cert_crt
        assert cert_fingerprint(loaded_ca_cert) == cert_fingerprint(ca_cert)
        assert cert_fingerprint(loaded_cert_crt) == cert_fingerprint(cert_crt)
        assert key_to_bytes(ca_key) == key_to_bytes(loaded_ca_key)
        assert key_to_bytes(cert_key) == key_to_bytes(loaded_cert_key)
