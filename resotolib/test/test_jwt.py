import pytest
import datetime
from resotolib.jwt import (
    decode_jwt_from_header_value,
    decode_jwt_from_headers,
    encode_jwt,
    decode_jwt,
    encode_jwt_to_headers,
)
from jwt import (
    InvalidSignatureError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    MissingRequiredClaimError,
)


def test_jwt():
    psk = "somesecret"
    payload = {"Hello": "World"}
    j1 = encode_jwt(payload, psk, expire_in=-1)
    j2 = encode_jwt(payload, psk, expire_in=-1)
    past_date = datetime.datetime.now() - datetime.timedelta(30)
    future_date = datetime.datetime.now() + datetime.timedelta(30)

    expired_payload = {"Hello": "World", "exp": past_date}
    future_payload = {"Hello": "World", "exp": future_date}
    nbf_payload = {"Hello": "World", "nbf": future_date}
    expired_jwt = encode_jwt(expired_payload, psk)
    valid_jwt = encode_jwt(future_payload, psk)
    not_yet_valid_jwt = encode_jwt(nbf_payload, psk)

    h1 = encode_jwt_to_headers({}, payload, psk, expire_in=-1)

    assert j1 != j2
    assert decode_jwt(j1, psk) == payload
    assert decode_jwt(j2, psk) == payload
    assert decode_jwt_from_headers(h1, psk) == payload
    assert decode_jwt_from_headers({}, psk) is None
    assert decode_jwt_from_header_value("", psk) is None
    with pytest.raises(InvalidSignatureError) as e:
        decode_jwt(j1, "wrongpsk")
    assert str(e.value) == "Signature verification failed"
    assert decode_jwt(expired_jwt, psk, options={"verify_exp": False}).get("Hello") == "World"
    with pytest.raises(ExpiredSignatureError) as e:
        decode_jwt(expired_jwt, psk)
    assert str(e.value) == "Signature has expired"
    assert decode_jwt(valid_jwt, psk).get("Hello") == "World"
    with pytest.raises(ImmatureSignatureError) as e:
        decode_jwt(not_yet_valid_jwt, psk)
    assert str(e.value).startswith("The token is not yet valid")
    with pytest.raises(MissingRequiredClaimError) as e:
        decode_jwt(j1, psk, options={"require": ["exp"]})
    assert str(e.value) == 'Token is missing the "exp" claim'
