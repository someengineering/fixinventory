import pytest
from cklib.jwt import make_jwt, verify_jwt
from jwt import InvalidSignatureError


def test_jwt():
    psk = "somesecret"
    payload = {"Hello": "World"}
    j1 = make_jwt(payload, psk)
    j2 = make_jwt(payload, psk)
    assert j1 != j2
    assert verify_jwt(j1, psk) == payload
    assert verify_jwt(j2, psk) == payload
    with pytest.raises(InvalidSignatureError) as excinfo:
        verify_jwt(j1, "wrongpsk")
    assert "Signature verification failed" in str(excinfo.value)
