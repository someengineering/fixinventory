import pytest
from cklib.jwt import (
    decode_jwt_from_header_value,
    decode_jwt_from_headers,
    encode_jwt,
    decode_jwt,
    encode_jwt_to_headers,
)
from jwt import InvalidSignatureError


def test_jwt():
    psk = "somesecret"
    payload = {"Hello": "World"}
    j1 = encode_jwt(payload, psk)
    j2 = encode_jwt(payload, psk)
    h1 = encode_jwt_to_headers({}, payload, psk)
    assert j1 != j2
    assert decode_jwt(j1, psk) == payload
    assert decode_jwt(j2, psk) == payload
    with pytest.raises(InvalidSignatureError) as e:
        decode_jwt(j1, "wrongpsk")
    assert str(e.value) == "Signature verification failed"
    assert decode_jwt_from_headers(h1, psk) == payload
    assert decode_jwt_from_headers({}, psk) is None
    assert decode_jwt_from_header_value("", psk) is None
