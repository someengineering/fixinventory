import os
import jwt
import base64
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from jwt.utils import base64url_encode

from fixlib.args import ArgumentParser
from fixlib.x509 import x5t_s256, x5t
from typing import Any, Optional, Tuple, Dict, Mapping, Union, cast
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.base import Certificate

from fixlib.types import Json


def key_from_psk(psk: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Derive a 256 bit key from a passphrase/pre-shared-key.
    A salt can be optionally provided. If not one will be generated.
    Returns both the key and the salt.
    """
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", psk.encode(), salt, 100000)
    return key, salt


def encode_jwt(
    payload: Dict[str, Any],
    key: Union[str, RSAPrivateKey],
    headers: Optional[Dict[str, str]] = None,
    expire_in: int = 300,
    cert: Optional[Certificate] = None,
) -> str:
    """Encodes a payload into a JWT either using a pre-shared-key or an RSA private key."""
    payload = dict(payload)
    if headers is None:
        headers = {}
    headers.update({"typ": "JWT"})
    if expire_in > 0 and "exp" not in payload:
        payload.update({"exp": int(time.time()) + expire_in})

    if isinstance(key, RSAPrivateKey):
        return encode_jwt_pki(payload, key, headers, cert)
    else:
        return encode_jwt_psk(payload, key, headers)


def encode_jwt_pki(
    payload: Dict[str, Any],
    private_key: RSAPrivateKey,
    headers: Dict[str, str],
    cert: Optional[Certificate] = None,
) -> str:
    """Encodes a payload into a JWT either using an RSA private key."""
    headers.update({"alg": "RS256"})
    if cert is not None:
        headers.update({"x5t#S256": x5t_s256(cert)})
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def encode_jwt_psk(
    payload: Dict[str, Any],
    psk: str,
    headers: Dict[str, str],
) -> str:
    """Encodes a payload into a JWT and signs using a key derived from a pre-shared-key.
    Stores the key's salt in the JWT headers.
    """
    key, salt = key_from_psk(psk)
    salt_encoded = base64.standard_b64encode(salt).decode("utf-8")
    headers.update({"alg": "HS256", "salt": salt_encoded})
    return jwt.encode(payload, key, algorithm="HS256", headers=headers)


def decode_jwt(
    encoded_jwt: str, psk_or_cert: Union[str, Certificate, RSAPublicKey], options: Optional[Dict[str, Any]] = None
) -> Json:
    """Decode a JWT using a key derived from a pre-shared-key and a salt stored
    in the JWT headers or an RSA public key.
    """
    alg = jwt.get_unverified_header(encoded_jwt).get("alg")
    if alg == "RS256":
        assert isinstance(psk_or_cert, (Certificate, RSAPublicKey))
        return decode_jwt_pki(encoded_jwt, psk_or_cert, options)
    elif alg == "HS256":
        assert isinstance(psk_or_cert, str)
        return decode_jwt_psk(encoded_jwt, psk_or_cert, options)
    else:
        raise ValueError(f"Unsupported JWT algorithm: {alg}")


def decode_jwt_psk(encoded_jwt: str, psk: str, options: Optional[Dict[str, Any]] = None) -> Json:
    """Decode a JWT using a key derived from a pre-shared-key and a salt stored
    in the JWT headers.
    """
    salt_encoded = jwt.get_unverified_header(encoded_jwt).get("salt")
    salt = base64.standard_b64decode(salt_encoded) if salt_encoded else None
    key, _ = key_from_psk(psk, salt)
    return jwt.decode(encoded_jwt, key, algorithms=["HS256"], options=options)  # type: ignore


def decode_jwt_pki(
    encoded_jwt: str, public_key: Union[Certificate, RSAPublicKey], options: Optional[Dict[str, Any]] = None
) -> Json:
    """Decode a JWT using an RSA public key."""
    if isinstance(public_key, Certificate):
        public_key = cast(RSAPublicKey, public_key.public_key())
        assert isinstance(public_key, RSAPublicKey)
    return jwt.decode(encoded_jwt, public_key, algorithms=["RS256"], options=options)  # type: ignore


def encode_jwt_to_headers(
    http_headers: Dict[str, str],
    payload: Dict[str, Any],
    key: Union[str, RSAPrivateKey],
    scheme: str = "Bearer",
    headers: Optional[Dict[str, str]] = None,
    expire_in: int = 300,
    cert: Optional[Certificate] = None,
) -> Dict[str, str]:
    """Takes a payload and psk turns them into a JWT and adds that to a http headers
    dictionary. Also returns that dict.
    """
    http_headers.update({"Authorization": f"{scheme} {encode_jwt(payload, key, headers, expire_in, cert)}"})
    return http_headers


def decode_jwt_from_headers(
    http_headers: Mapping[str, str],
    psk_or_cert: Union[str, Certificate, RSAPublicKey],
    scheme: str = "Bearer",
    options: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    """Retrieves the Authorization header from a http headers dictionary and
    passes it to `decode_jwt_from_header_value()` to return the decoded payload.
    """
    authorization_header = {str(k).capitalize(): v for k, v in http_headers.items()}.get("Authorization")
    if authorization_header is None:
        return None
    return decode_jwt_from_header_value(authorization_header, psk_or_cert, scheme, options)


def decode_jwt_from_header_value(
    authorization_header: str,
    psk_or_cert: Union[str, Certificate, RSAPublicKey],
    scheme: str = "Bearer",
    options: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    """Decodes a JWT payload from a http Authorization header value."""
    if (
        len(authorization_header) <= len(scheme) + 1
        or str(authorization_header[0 : len(scheme)]).lower() != scheme.lower()
        or authorization_header[len(scheme) : len(scheme) + 1] != " "
    ):
        return None
    encoded_jwt = authorization_header[len(scheme) + 1 :]
    return decode_jwt(encoded_jwt, psk_or_cert, options)


def create_jwk_dict(cert: Certificate) -> Json:
    pub_key = cert.public_key()
    if not isinstance(pub_key, RSAPublicKey):
        raise ValueError(f"Unsupported public key type: {type(pub_key)}")
    pem_data = cert.public_bytes(serialization.Encoding.PEM)
    pem_contents = pem_data.split(b"\n")[1:-2]  # Remove header and footer lines
    x5t_256 = x5t_s256(cert)
    pub_num = pub_key.public_numbers()
    return {
        "kty": "RSA",
        "alg": cert.signature_algorithm_oid._name,
        "n": base64url_encode(pub_num.n.to_bytes((pub_num.n.bit_length() + 7) // 8, "big")).decode("utf-8"),
        "e": base64url_encode(pub_num.e.to_bytes((pub_num.e.bit_length() + 7) // 8, "big")).decode("utf-8"),
        "use": "sig",
        "kid": x5t_256,
        "x5t": x5t(cert),
        "x5t#S256": x5t_256,
        "x5c": [b"".join(pem_contents).decode("utf-8")],
    }


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--psk",
        help="Pre-shared key",
        type=lambda x: x if len(x) > 0 else None,
        default=None,
        dest="psk",
    )
