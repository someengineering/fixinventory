import os
import jwt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional


def key_from_psk(psk: str, salt: bytes = None) -> tuple[bytes, bytes]:
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


def encode_jwt(payload: dict[str, str], psk: str) -> str:
    key, salt = key_from_psk(psk)
    salt_encoded = base64.standard_b64encode(salt).decode("utf-8")
    return jwt.encode(payload, key, algorithm="HS256", headers={"salt": salt_encoded})


def decode_jwt(encoded_jwt: str, psk: str) -> dict:
    salt_encoded = jwt.get_unverified_header(encoded_jwt).get("salt")
    salt = base64.standard_b64decode(salt_encoded)
    key, _ = key_from_psk(psk, salt)
    return jwt.decode(encoded_jwt, key, algorithms=["HS256"])


def encode_jwt_to_headers(
    http_headers: dict[str, str],
    payload: dict[str, str],
    psk: str,
    scheme: str = "Bearer",
) -> dict[str, str]:
    http_headers.update({"Authorization": f"{scheme} {encode_jwt(payload, psk)}"})
    return http_headers


def decode_jwt_from_headers(
    http_headers: dict[str, str], psk: str, scheme: str = "Bearer"
) -> Optional[dict[str, str]]:
    authorization_header = {
        str(k).capitalize(): v for k, v in http_headers.items()
    }.get("Authorization")
    if authorization_header is None:
        return None
    return decode_jwt_from_header_value(authorization_header, psk, scheme)


def decode_jwt_from_header_value(
    authorization_header: str, psk: str, scheme: str = "Bearer"
) -> Optional[dict[str, str]]:
    if (
        len(authorization_header) <= len(scheme) + 1
        or str(authorization_header[0 : len(scheme)]).lower() != scheme.lower()
        or authorization_header[len(scheme) : len(scheme) + 1] != " "
    ):
        return None
    encoded_jwt = authorization_header[len(scheme) + 1 :]
    return decode_jwt(encoded_jwt, psk)
