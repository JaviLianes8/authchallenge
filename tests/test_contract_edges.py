"""Edges the author mutation round showed no contract held on its own."""

from __future__ import annotations

import base64

import pytest

import authchallenge as ac

DIGEST_INFO = {"qop": "auth", "rspauth": "r", "cnonce": "c"}


@pytest.mark.parametrize("nc", ["0000001", "000000001", "0000000g", "", "0000 001"])
def test_digest_nc_is_exactly_eight_hex_digits(nc: str) -> None:
    with pytest.raises(ac.AuthError):
        ac.build_auth_info({**DIGEST_INFO, "nc": nc}, scheme="Digest")
    with pytest.raises(ac.AuthError):
        ac.parse_auth_info(
            f'qop=auth, rspauth="r", cnonce="c", nc={nc}', strict=True, scheme="Digest"
        )


def test_digest_nc_accepts_any_case_of_hex() -> None:
    header = ac.build_auth_info({**DIGEST_INFO, "nc": "0000aBcD"}, scheme="Digest")
    assert ac.parse_auth_info(header, strict=True, scheme="Digest")["nc"] == "0000aBcD"


@pytest.mark.parametrize("char", ["\x00", "\x1f", "\x7f"])
def test_basic_refuses_every_ascii_control(char: str) -> None:
    with pytest.raises(ac.AuthError, match="control characters"):
        ac.encode_basic("u", f"a{char}b")
    token = base64.b64encode(f"u:a{char}b".encode()).decode()
    with pytest.raises(ac.AuthError, match="control characters"):
        ac.decode_basic("Basic " + token)


def test_basic_allows_the_characters_next_to_the_controls() -> None:
    assert ac.decode_basic(ac.encode_basic("u", " ~\x80\xa0")) == ("u", " ~\x80\xa0")


@pytest.mark.parametrize("charset", ["ascii", "us-ascii", "cp1252", "latin-9", "utf-16"])
def test_basic_charsets_are_utf_8_and_latin_1_only(charset: str) -> None:
    with pytest.raises(ac.AuthError, match="unsupported Basic charset"):
        ac.encode_basic("u", "p", charset=charset)
    with pytest.raises(ac.AuthError, match="unsupported Basic charset"):
        ac.decode_basic("Basic dTpw", charset=charset)


def test_a_backslash_outside_a_quoted_string_escapes_nothing() -> None:
    (challenge,) = ac.parse_challenges(r"X a=b\, c=d")
    assert challenge.params == {"c": "d"}
    assert ac.parse_auth_info(r"a=1, b\, c=2") == {"a": "1", "c": "2"}
    with pytest.raises(ac.AuthError, match="unexpected text after the value of 'a'"):
        ac.parse_challenges(r"X a=b\, c=d", strict=True)


@pytest.mark.parametrize(
    "token",
    ["QWxhZGRpbjpvcGVu=", "dTpw=", "dTpw==", "dTpw===", "dTpw====", "dTo====", "dTo==", "dTpwcQ="],
)
def test_basic_refuses_surplus_or_short_padding_on_every_python(token: str) -> None:
    # Some CPython 3.10 and 3.11 releases decode surplus padding with validate=True.
    with pytest.raises(ac.AuthError, match="not valid base64"):
        ac.decode_basic("Basic " + token)


@pytest.mark.parametrize("token", ["dTpw", "dTo=", "dTpwcQ==", "dTpwcXI="])
def test_basic_accepts_canonical_padding(token: str) -> None:
    assert ac.decode_basic("Basic " + token) == tuple(
        base64.b64decode(token).decode().split(":", 1)
    )
