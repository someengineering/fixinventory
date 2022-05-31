import os
import jwt
import base64
import hashlib
import time
from resotolib.args import ArgumentParser
from typing import Any, Optional, Tuple, Dict


def key_from_psk(psk: str, salt: bytes = None) -> Tuple[bytes, bytes]:
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
    psk: str,
    headers: Optional[Dict[str, str]] = None,
    expire_in: int = 300,
) -> str:
    """Encodes a payload into a JWT and signs using a key derived from a pre-shared-key.
    Stores the key's salt in the JWT headers.
    """
    payload = dict(payload)
    if headers is None:
        headers = {}
    if expire_in > 0 and "exp" not in payload:
        payload.update({"exp": int(time.time()) + expire_in})
    key, salt = key_from_psk(psk)
    salt_encoded = base64.standard_b64encode(salt).decode("utf-8")
    headers.update({"salt": salt_encoded})
    return jwt.encode(payload, key, algorithm="HS256", headers=headers)


def decode_jwt(encoded_jwt: str, psk: str, options: Optional[Dict[str, Any]] = None) -> dict:
    """Decode a JWT using a key derived from a pre-shared-key and a salt stored
    in the JWT headers.
    """
    salt_encoded = jwt.get_unverified_header(encoded_jwt).get("salt")
    salt = base64.standard_b64decode(salt_encoded)
    key, _ = key_from_psk(psk, salt)
    return jwt.decode(encoded_jwt, key, algorithms=["HS256"], options=options)


def encode_jwt_to_headers(
    http_headers: Dict[str, str],
    payload: Dict[str, Any],
    psk: str,
    scheme: str = "Bearer",
    headers: Optional[Dict[str, str]] = None,
    expire_in: int = 300,
) -> Dict[str, str]:
    """Takes a payload and psk turns them into a JWT and adds that to a http headers
    dictionary. Also returns that dict.
    """
    http_headers.update({"Authorization": f"{scheme} {encode_jwt(payload, psk, headers, expire_in)}"})
    return http_headers


def decode_jwt_from_headers(
    http_headers: Dict[str, str],
    psk: str,
    scheme: str = "Bearer",
    options: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    """Retrieves the Authorization header from a http headers dictionary and
    passes it to `decode_jwt_from_header_value()` to return the decoded payload.
    """
    authorization_header = {str(k).capitalize(): v for k, v in http_headers.items()}.get("Authorization")
    if authorization_header is None:
        return None
    return decode_jwt_from_header_value(authorization_header, psk, scheme, options)


def decode_jwt_from_header_value(
    authorization_header: str,
    psk: str,
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
    return decode_jwt(encoded_jwt, psk, options)


def add_args(arg_parser: ArgumentParser) -> None:
    arg_parser.add_argument(
        "--psk",
        help="Pre-shared key",
        type=lambda x: x if len(x) > 0 else None,
        default=None,
        dest="psk",
    )
