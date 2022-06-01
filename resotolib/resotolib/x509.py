import os
import certifi
from ipaddress import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)
from resotolib.utils import get_local_hostnames, get_local_ip_addresses
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    generate_private_key,
)
from cryptography.x509.base import Certificate, CertificateSigningRequest
from typing import List, Optional, Tuple, Union


def gen_rsa_key(key_size: int = 2048) -> RSAPrivateKey:
    return generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())


def bootstrap_ca(
    days_valid: int = 3650,
    common_name: str = "Resoto Root CA",
    organization_name: str = "Some Engineering Inc.",
    path_length: int = 2,
) -> Tuple[RSAPrivateKey, Certificate]:
    ca_key = gen_rsa_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                key_cert_sign=True,  # CA Cert is only allowed to sign other certs
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,  # and cert revocation lists
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,  # KeyUsage extension is critical to support
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    return ca_key, ca_cert


def gen_csr(
    csr_key: RSAPrivateKey,
    *,
    common_name: str = "some.engineering",
    san_dns_names: Optional[List[str]] = None,
    san_ip_addresses: Optional[List[str]] = None,
    include_loopback: bool = True,
    connect_to_ips: Optional[List[str]] = None,
    discover_local_dns_names: bool = True,
    discover_local_ip_addresses: bool = True,
) -> CertificateSigningRequest:
    if san_dns_names is None:
        san_dns_names = []
    elif isinstance(san_dns_names, str):
        san_dns_names = [san_dns_names]
    if san_ip_addresses is None:
        san_ip_addresses = []
    elif isinstance(san_ip_addresses, str):
        san_ip_addresses = [san_ip_addresses]

    if discover_local_dns_names:
        san_dns_names = get_local_hostnames(
            include_loopback=include_loopback,
            san_ip_addresses=san_ip_addresses,
            san_dns_names=san_dns_names,
            connect_to_ips=connect_to_ips,
        )

    if discover_local_ip_addresses:
        san_ip_addresses = get_local_ip_addresses(
            include_loopback=include_loopback,
            san_ip_addresses=san_ip_addresses,
            connect_to_ips=connect_to_ips,
        )

    csr_build = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if len(san_dns_names) + len(san_ip_addresses) > 0:
        csr_build = csr_build.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in san_dns_names] + [x509.IPAddress(make_ip(i)) for i in san_ip_addresses]
            ),
            critical=False,  # Optional extensions are not critical if unsupported
        )
    return csr_build.sign(csr_key, hashes.SHA256(), default_backend())


def sign_csr(
    csr: CertificateSigningRequest,
    ca_key: RSAPrivateKey,
    ca_cert: Certificate,
    days_valid: int = 365,
    server_auth: bool = True,
    client_auth: bool = True,
) -> Certificate:
    crt_build = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=days_valid))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,  # Server/client certs are allowed for
                key_encipherment=True,  # signatures and encrypting traffic.
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if server_auth or client_auth:
        key_usage = []
        if server_auth:
            key_usage.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
        if client_auth:
            key_usage.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
        crt_build = crt_build.add_extension(x509.ExtendedKeyUsage(key_usage), critical=False)
    for extension in csr.extensions:
        if not isinstance(extension.value, x509.SubjectAlternativeName):
            continue
        crt_build = crt_build.add_extension(extension.value, critical=extension.critical)
    return crt_build.sign(ca_key, hashes.SHA256(), default_backend())


def write_csr_to_file(csr: CertificateSigningRequest, csr_path: str, rename: bool = True) -> None:
    tmp_csr_path = f"{csr_path}.tmp" if rename else csr_path
    with open(tmp_csr_path, "wb") as f:
        f.write(csr_to_bytes(csr))
    if rename:
        os.rename(tmp_csr_path, csr_path)


def write_cert_to_file(cert: Certificate, cert_path: str, rename: bool = True) -> None:
    tmp_cert_path = f"{cert_path}.tmp" if rename else cert_path
    with open(tmp_cert_path, "wb") as f:
        f.write(cert_to_bytes(cert))
    if rename:
        os.rename(tmp_cert_path, cert_path)


def write_ca_bundle(cert: Certificate, cert_path: str, include_certifi: bool = True, rename: bool = True) -> None:
    tmp_cert_path = f"{cert_path}.tmp" if rename else cert_path
    with open(tmp_cert_path, "wb") as f:
        if include_certifi:
            f.write(certifi.contents().encode())
        f.write("\n".encode())
        f.write(f"# Issuer: {cert.issuer.rfc4514_string()}\n".encode())
        f.write(f"# Subject: {cert.subject.rfc4514_string()}\n".encode())
        label = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        f.write(f"# Label: {label}\n".encode())
        f.write(f"# Serial: {cert.serial_number}\n".encode())
        md5 = cert_fingerprint(cert, "MD5")
        sha1 = cert_fingerprint(cert, "SHA1")
        sha256 = cert_fingerprint(cert, "SHA256")
        f.write(f"# MD5 Fingerprint: {md5}\n".encode())
        f.write(f"# SHA1 Fingerprint: {sha1}\n".encode())
        f.write(f"# SHA256 Fingerprint: {sha256}\n".encode())
        f.write(cert_to_bytes(cert))
    if rename:
        os.rename(tmp_cert_path, cert_path)


def write_key_to_file(
    key: RSAPrivateKey,
    key_path: str,
    passphrase: Optional[str] = None,
    rename: bool = True,
) -> None:
    tmp_key_path = f"{key_path}.tmp" if rename else key_path
    with open(os.open(tmp_key_path, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as f:
        f.write(key_to_bytes(key, passphrase))
    if rename:
        os.rename(tmp_key_path, key_path)


def key_to_bytes(
    key: RSAPrivateKey,
    passphrase: Optional[str] = None,
):
    kwargs = {"encryption_algorithm": serialization.NoEncryption()}
    if passphrase is not None:
        kwargs["encryption_algorithm"] = serialization.BestAvailableEncryption(passphrase.encode())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        **kwargs,
    )


def csr_to_bytes(csr: CertificateSigningRequest) -> bytes:
    return cert_to_bytes(csr)


def cert_to_bytes(cert: Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_csr_from_file(csr_path: str) -> CertificateSigningRequest:
    with open(csr_path, "rb") as f:
        csr = f.read()
    return load_csr_from_bytes(csr)


def load_cert_from_file(cert_path: str) -> Certificate:
    with open(cert_path, "rb") as f:
        cert = f.read()
    return load_cert_from_bytes(cert)


def load_key_from_file(key_path: str, passphrase: Optional[str] = None) -> RSAPrivateKey:
    with open(key_path, "rb") as f:
        key = f.read()
    return load_key_from_bytes(key, passphrase)


def load_csr_from_bytes(csr: bytes) -> CertificateSigningRequest:
    return x509.load_pem_x509_csr(csr, default_backend())


def load_cert_from_bytes(cert: bytes) -> Certificate:
    return x509.load_pem_x509_certificate(cert, default_backend())


def load_key_from_bytes(key: bytes, passphrase: Optional[str] = None) -> RSAPrivateKey:
    backend = default_backend()
    if passphrase is not None:
        passphrase = passphrase.encode()
    return backend.load_pem_private_key(key, passphrase)


def make_ip(ip: str) -> Union[IPv4Address, IPv6Address, IPv4Network, IPv6Network]:
    if "/" in ip:
        return ip_network(ip)
    else:
        return ip_address(ip)


def cert_fingerprint(cert: Certificate, hash_algorithm: str = "SHA256") -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(getattr(hashes, hash_algorithm.upper())()))
