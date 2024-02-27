import pytest
import datetime
from fixlib.jwt import (
    decode_jwt_from_header_value,
    decode_jwt_from_headers,
    encode_jwt,
    decode_jwt,
    encode_jwt_to_headers,
    create_jwk_dict,
)
from jwt import (
    InvalidSignatureError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    MissingRequiredClaimError,
    get_unverified_header,
)
from fixlib.x509 import (
    bootstrap_ca,
    gen_rsa_key,
    gen_csr,
    sign_csr,
    cert_is_signed_by_ca,
    x5t_s256,
)


def test_jwt_psk():
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


def test_jwt_pki():
    ca_key, ca_cert = bootstrap_ca()
    cert_key = gen_rsa_key()
    cert_crt = sign_csr(gen_csr(cert_key), ca_key, ca_cert)
    payload = {"Hello": "World"}
    jwt = encode_jwt(payload, cert_key, expire_in=-1)
    assert cert_is_signed_by_ca(cert_crt, ca_cert)
    assert decode_jwt(jwt, cert_crt) == payload

    jwt = encode_jwt(payload, cert_key, cert=cert_crt)
    assert decode_jwt(jwt, cert_crt).get("Hello") == "World"
    assert get_unverified_header(jwt).get("x5t#S256") == x5t_s256(cert_crt)


def test_jwk() -> None:
    ca_key, ca_cert = bootstrap_ca()
    cert_key = gen_rsa_key()
    cert_crt = sign_csr(gen_csr(cert_key), ca_key, ca_cert)
    cert_cwk = create_jwk_dict(cert_crt)
    # has 9 entries
    assert len(cert_cwk) == 9
    # creating the jwk from the same cert, creates the same key data
    assert cert_cwk == create_jwk_dict(cert_crt)
    # check on specific values
    assert cert_cwk["alg"] == "sha256WithRSAEncryption"
    assert cert_cwk["kty"] == "RSA"
    assert cert_cwk["use"] == "sig"
    assert cert_cwk["x5t#S256"] == x5t_s256(cert_crt)
    assert cert_cwk["kid"] == cert_cwk["x5t#S256"]
