"""Scheme rules of Basic, Bearer and Digest, enforced by strict parsing and by the builder."""

from __future__ import annotations

import pytest

from authchallenge import (
    AuthError,
    build_auth_info,
    build_authorization,
    build_challenge,
    parse_auth_info,
    parse_authorization,
    parse_challenges,
)

NONCE = 'nonce="n", qop="auth"'
CREDS = 'username="u", realm="r", nonce="n", uri="/", response="x", cnonce="c", nc=00000001'


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("Basic", "Basic needs the 'realm' parameter"),
        ('Basic realm="r", charset="latin1"', "only allows 'UTF-8'"),
        ("Bearer", "at least one auth-param"),
        ('Bearer scope="a\\\\b"', "scope holds a character"),
        ('Bearer scope="a  b"', "scope holds a character"),
        ('Bearer error="a\\"b"', "error holds a character"),
        ('Bearer error_description="café"', "error_description holds a character"),
        ('Bearer error_uri="http://x/ y"', "error_uri holds a character"),
        ("Digest abc==", "not a token68"),
        (f'Digest realm="r", {NONCE}, stale="true"', "stale parameter must not be quoted"),
        (f'Digest realm="r", {NONCE}, algorithm="MD5"', "algorithm parameter must not be quoted"),
        ('Digest realm="r", nonce=n, qop="auth"', "nonce parameter must be a quoted-string"),
        ('Digest realm="r", nonce="n", qop=auth', "qop parameter must be a quoted-string"),
        ('Digest realm="r", qop="auth"', "Digest needs the 'nonce' parameter"),
        ('Digest realm="r", nonce="n"', "Digest needs the 'qop' parameter"),
        (f'Digest realm="r", {NONCE}, stale=maybe', "stale parameter is 'true' or 'false'"),
        (f'Digest realm="r", {NONCE}, userhash=1', "userhash parameter is 'true' or 'false'"),
        (f'Digest realm="r", {NONCE}, charset=latin1', "only allows 'UTF-8'"),
    ],
)
def test_challenge_rules(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        parse_challenges(value, strict=True)


@pytest.mark.parametrize(
    "value",
    [
        'Basic realm="r", charset=utf-8',
        'Bearer realm="r", scope="openid profile", error=invalid_token',
        f'Digest realm="r", {NONCE}, stale=TRUE, userhash=false, algorithm=SHA-256',
        'Basic realm="r", Bearer realm="r", Digest realm="r", ' + NONCE,
    ],
)
def test_valid_challenges(value: str) -> None:
    assert parse_challenges(value, strict=True)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('Basic realm="r"', "Basic credentials are a token68"),
        ("Basic QWxhZGRpbg==", "lack the ':'"),
        ("Basic QWxhZGRpbjpvcGVu=", "not valid base64"),
        ("Basic QQ-_", "not valid base64"),
        ("Basic dXNlcgpuYW1lOnB3", "control characters"),
        ('Bearer token="x"', "Bearer credentials are a b64token"),
        (CREDS.replace('username="u"', "username=u"), "username parameter must be a quoted"),
        (CREDS + ', qop="auth"', "qop parameter must not be quoted"),
        (CREDS.replace("00000001", "1"), "exactly 8 hexadecimal digits"),
        (CREDS + ", username*=UTF-8''u", "exactly one of username and username\\*"),
        (CREDS.replace('username="u"', "x=1"), "exactly one of username and username\\*"),
        (CREDS.replace('username="u"', "username*=\"UTF-8''u\""), "is an ext-value"),
        (CREDS.replace('username="u"', "username*=latin1''u"), "is not a valid ext-value"),
        (CREDS.replace(', cnonce="c"', ""), "Digest needs the 'cnonce' parameter"),
        (CREDS.replace(', uri="/"', ""), "Digest needs the 'uri' parameter"),
    ],
)
def test_credentials_rules(value: str, reason: str) -> None:
    text = value if value.split(" ")[0] in ("Basic", "Bearer") else "Digest " + value
    with pytest.raises(AuthError, match=reason):
        parse_authorization(text, strict=True)


def test_valid_digest_credentials() -> None:
    creds = parse_authorization("Digest " + CREDS + ", qop=auth", strict=True)
    assert creds.params["nc"] == "00000001"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("nextnonce=abc", "nextnonce parameter must be a quoted-string"),
        ('qop="auth", rspauth="r", cnonce="c", nc=00000001', "qop parameter must not be quoted"),
        ('qop=auth, cnonce="c", nc=00000001', "needs the 'rspauth' parameter"),
        ('qop=auth, rspauth="r", cnonce="c", nc=0001', "exactly 8 hexadecimal"),
    ],
)
def test_digest_auth_info_rules(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        parse_auth_info(value, strict=True, scheme="Digest")


def test_auth_info_rules_apply_only_with_a_scheme() -> None:
    assert parse_auth_info("nextnonce=abc", strict=True) == {"nextnonce": "abc"}
    assert parse_auth_info("x=1", strict=True, scheme="Basic") == {"x": "1"}


@pytest.mark.parametrize(
    ("call", "reason"),
    [
        (lambda: build_challenge("Basic"), "realm"),
        (lambda: build_challenge("bearer"), "at least one"),
        (lambda: build_challenge("Bearer", {"error_description": 'say "hi"'}), "error_desc"),
        (lambda: build_challenge("Digest", {"realm": "r"}), "nonce"),
        (lambda: build_challenge("Digest", token68="abc"), "token68"),
        (lambda: build_authorization("Basic", {"user": "a"}), "token68"),
        (lambda: build_authorization("Basic", token68="QWxhZGRpbg=="), "':'"),
        (lambda: build_authorization("Bearer", {"t": "x"}), "b64token"),
        (lambda: build_authorization("DIGEST", {"username": "u"}), "realm"),
        (lambda: build_auth_info({"qop": "auth"}, scheme="Digest"), "rspauth"),
    ],
)
def test_the_builder_enforces_the_same_rules(call: object, reason: str) -> None:
    assert callable(call)
    with pytest.raises(AuthError, match=reason):
        call()


def test_a_bearer_token_is_built_as_token68() -> None:
    assert build_authorization("Bearer", token68="mF_9.B5f-4.1JqM") == "Bearer mF_9.B5f-4.1JqM"
