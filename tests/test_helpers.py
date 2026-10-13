"""Basic encoding, ext-values, Bearer challenges and challenge selection."""

from __future__ import annotations

import pytest

from authchallenge import (
    AuthError,
    Challenge,
    Credentials,
    build_bearer_challenge,
    decode_basic,
    decode_ext_value,
    encode_basic,
    encode_ext_value,
    parse_challenges,
    select_challenge,
)


def test_basic_round_trip_keeps_colons_in_the_password() -> None:
    header = encode_basic("user", "pa:ss word")
    assert decode_basic(header) == ("user", "pa:ss word")


def test_basic_charset_is_selectable() -> None:
    utf8, latin1 = encode_basic("u", "£"), encode_basic("u", "£", charset="latin-1")
    assert utf8 != latin1
    assert decode_basic(latin1, charset="latin-1") == ("u", "£")
    with pytest.raises(AuthError, match="not valid utf-8"):
        decode_basic(latin1)


@pytest.mark.parametrize(
    ("user", "password", "reason"),
    [
        ("a:b", "p", "cannot contain ':'"),
        ("a\nb", "p", "control characters"),
        ("a", "p\x7f", "control characters"),
        ("a", "€", "cannot be encoded"),
    ],
)
def test_basic_encoding_refuses_what_rfc_7617_forbids(
    user: str, password: str, reason: str
) -> None:
    charset = "latin-1" if reason == "cannot be encoded" else "utf-8"
    with pytest.raises(AuthError, match=reason):
        encode_basic(user, password, charset=charset)


def test_basic_decoding_accepts_parsed_credentials_and_any_case() -> None:
    assert decode_basic(Credentials("BASIC", "dTpw")) == ("u", "p")
    assert decode_basic("  basic   dTpw  ") == ("u", "p")
    assert decode_basic("Basic\tdTpw") == ("u", "p")


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("Bearer dTpw", "not Basic"),
        (Credentials("Basic"), "invalid token68"),
        ("Basic", "invalid token68"),
        ("Basic dTpw!", "invalid token68"),
    ],
)
def test_basic_decoding_refuses_other_input(value: str | Credentials, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        decode_basic(value)


def test_ext_value_round_trip() -> None:
    encoded = encode_ext_value("Jäsøn Doe")
    assert encoded == "UTF-8''J%C3%A4s%C3%B8n%20Doe"
    assert decode_ext_value(encoded) == "Jäsøn Doe"


def test_ext_value_keeps_attr_chars_and_encodes_the_rest() -> None:
    assert encode_ext_value("a-b.c*'%") == "UTF-8''a-b.c%2A%27%25"


def test_ext_value_reads_a_language_and_iso_8859_1() -> None:
    # RFC 8187 section 3.2.3, the pound sign example (https://www.rfc-editor.org/rfc/rfc8187).
    assert decode_ext_value("utf-8'en'%C2%A3%20rates") == "£ rates"
    assert decode_ext_value("iso-8859-1''%A3") == "£"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("UTF-8'u", "invalid ext-value"),
        ("UTF-8''a b", "invalid ext-value"),
        ("UTF-8''%G1", "invalid ext-value"),
        ("UTF-16''a", "unsupported ext-value charset"),
        ("UTF-8''%FF", "not valid utf-8"),
    ],
)
def test_ext_value_refuses_malformed_input(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        decode_ext_value(value)


def test_bearer_challenge_orders_and_quotes_attributes() -> None:
    header = build_bearer_challenge(
        realm="api", scope=["read", "write"], error="insufficient_scope", error_uri="https://e/x"
    )
    assert header == (
        'Bearer realm="api", scope="read write", error="insufficient_scope", '
        'error_uri="https://e/x"'
    )
    assert parse_challenges(header, strict=True)[0].params["scope"] == "read write"


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"scope": []}, {"scope": ["a b"]}, {"scope": [""]}, {"error_description": "a\\b"}],
)
def test_bearer_challenge_refuses_invalid_attributes(kwargs: dict[str, object]) -> None:
    with pytest.raises(AuthError):
        build_bearer_challenge(**kwargs)  # type: ignore[arg-type]


def test_select_challenge_follows_the_callers_preference() -> None:
    offered = parse_challenges('Basic realm="a", DIGEST realm="b", nonce="n", qop="auth"')
    chosen = select_challenge(offered, "digest", "basic")
    assert chosen is not None and chosen.scheme == "DIGEST"
    assert select_challenge(offered, "Negotiate") is None
    assert select_challenge(iter(offered), "Negotiate", "BASIC") == offered[0]


def test_select_challenge_takes_the_first_of_equal_schemes() -> None:
    offered = [Challenge("Basic", None, {"realm": "1"}), Challenge("basic", None, {"realm": "2"})]
    assert select_challenge(offered, "Basic") is offered[0]
