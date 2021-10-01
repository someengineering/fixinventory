import os
import jwt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
