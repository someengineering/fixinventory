import os
import jwt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Any, Optional


def key_from_psk(psk: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a 256 bit key from a passphrase/pre-shared-key.
    A salt can be optionally provided. If not one will be generated.
    Returns both the key and the salt.
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(psk.encode())
    return key, salt


def encode_jwt(
    payload: dict[str, str], psk: str, headers: Optional[dict[str, str]] = None
) -> str:
    """Encodes a payload into a JWT and signs using a key derived from a pre-shared-key.
    Stores the key's salt in the JWT headers.
    """
    if headers is None:
        headers = {}
    key, salt = key_from_psk(psk)
    salt_encoded = base64.standard_b64encode(salt).decode("utf-8")
    headers.update({"salt": salt_encoded})
    return jwt.encode(payload, key, algorithm="HS256", headers=headers)


def decode_jwt(
    encoded_jwt: str, psk: str, options: Optional[dict[str, Any]] = None
) -> dict:
    """Decode a JWT using a key derived from a pre-shared-key and a salt stored
    in the JWT headers.
    """
    salt_encoded = jwt.get_unverified_header(encoded_jwt).get("salt")
    salt = base64.standard_b64decode(salt_encoded)
    key, _ = key_from_psk(psk, salt)
    return jwt.decode(encoded_jwt, key, algorithms=["HS256"], options=options)


def encode_jwt_to_headers(
    http_headers: dict[str, str],
    payload: dict[str, str],
    psk: str,
    scheme: str = "Bearer",
    headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Takes a payload and psk turns them into a JWT and adds that to a http headers
    dictionary.
    """
    http_headers.update(
        {"Authorization": f"{scheme} {encode_jwt(payload, psk, headers)}"}
    )
    return http_headers


def decode_jwt_from_headers(
    http_headers: dict[str, str],
    psk: str,
    scheme: str = "Bearer",
    options: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, str]]:
    """Retrieves the Authorization header from a http headers dictionary and
    passes it to `decode_jwt_from_header_value()` to return the decoded payload.
    """
    authorization_header = {
        str(k).capitalize(): v for k, v in http_headers.items()
    }.get("Authorization")
    if authorization_header is None:
        return None
    return decode_jwt_from_header_value(authorization_header, psk, scheme, options)


def decode_jwt_from_header_value(
    authorization_header: str,
    psk: str,
    scheme: str = "Bearer",
    options: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, str]]:
    """Decodes a JWT payload from a http Authorization header value."""
    if (
        len(authorization_header) <= len(scheme) + 1
        or str(authorization_header[0 : len(scheme)]).lower() != scheme.lower()
        or authorization_header[len(scheme) : len(scheme) + 1] != " "
    ):
        return None
    encoded_jwt = authorization_header[len(scheme) + 1 :]
    return decode_jwt(encoded_jwt, psk, options)
