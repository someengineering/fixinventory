import pytest
from cklib.jwt import encode_jwt, decode_jwt
from jwt import InvalidSignatureError


def test_jwt():
    psk = "somesecret"
    payload = {"Hello": "World"}
    j1 = encode_jwt(payload, psk)
    j2 = encode_jwt(payload, psk)
    assert j1 != j2
    assert decode_jwt(j1, psk) == payload
    assert decode_jwt(j2, psk) == payload
    with pytest.raises(InvalidSignatureError) as e:
        decode_jwt(j1, "wrongpsk")
    assert str(e.value) == "Signature verification failed"
